//! Short-code SPAKE2 bootstrap. Authenticated PAKE records deliver a fresh TLS
//! trust anchor and receiver secret; application data still uses rustls TLS.
use super::{
    Direction, KeySchedule, Opener, Sealer,
    direct::{Error, Invitation},
};
use crate::protocol::frame::Framed;
use curve25519_dalek::edwards::CompressedEdwardsY;
use sha2::{Digest, Sha256};
use spake2::{Ed25519Group, Identity, Password, Spake2};
use std::{sync::OnceLock, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    time::timeout,
};
use zeroize::Zeroizing;

const DOMAIN: &[u8] = b"cayman/spake2-tls/1";
const HELLO: &[u8] = b"CYPAKE01";
const HANDSHAKE_LIMIT: usize = 512;
const DEADLINE: Duration = Duration::from_secs(30);
fn words() -> &'static [&'static str] {
    static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    WORDS.get_or_init(|| include_str!("words.txt").split_whitespace().collect())
}

/// Six public routing digits and four independent random words (32 secret bits).
/// Never derive a relay room from the complete code or its password words.
pub struct ShortCode {
    room: String,
    password: Zeroizing<String>,
}
impl ShortCode {
    pub fn generate() -> Result<Self, Error> {
        let mut random = Zeroizing::new([0; 8]);
        let room = loop {
            getrandom::fill(random.as_mut()).map_err(|e| format!("random source: {e}"))?;
            let n = u32::from_le_bytes(random[..4].try_into()?) & 0x000f_ffff;
            if n < 900_000 {
                break (100_000 + n).to_string();
            }
        };
        let password = Zeroizing::new(
            random[4..]
                .iter()
                .map(|b| words()[*b as usize])
                .collect::<Vec<_>>()
                .join("-"),
        );
        Ok(Self { room, password })
    }
    pub fn parse(text: &str) -> Result<Self, Error> {
        if text.len() > 128 {
            return Err("pairing code is too long".into());
        }
        let normalized = Zeroizing::new(text.trim().to_ascii_lowercase());
        let parts: Vec<_> = normalized.split('-').collect();
        if parts.len() != 5
            || parts[0].len() != 6
            || parts[0].starts_with('0')
            || !parts[0].bytes().all(|b| b.is_ascii_digit())
            || parts[1..].iter().any(|p| !words().contains(p))
        {
            return Err("expected pairing code: 6 digits followed by four words; upgrade both peers for short-code pairing".into());
        }
        Ok(Self {
            room: parts[0].to_owned(),
            password: Zeroizing::new(parts[1..].join("-")),
        })
    }
    pub fn encode(&self) -> Zeroizing<String> {
        Zeroizing::new(format!("{}-{}", self.room, self.password.as_str()))
    }
    pub fn relay_room(&self) -> String {
        format!("cayman-spake2-v1-{}", self.room)
    }
}

#[derive(Clone, Copy)]
enum Role {
    Sender,
    Receiver,
}

fn validate_message(bytes: &[u8], role: Role) -> Result<&[u8], Error> {
    if bytes.len() != HELLO.len() + 33 || !bytes.starts_with(HELLO) {
        return Err("unsupported pairing handshake; upgrade both peers".into());
    }
    let message = &bytes[HELLO.len()..];
    let peer = match role {
        Role::Sender => b'B',
        Role::Receiver => b'A',
    };
    if message[0] != peer {
        return Err("incorrect SPAKE2 peer role".into());
    }
    let encoded: [u8; 32] = message[1..].try_into()?;
    let point = CompressedEdwardsY(encoded)
        .decompress()
        .ok_or("invalid SPAKE2 point")?;
    if !point.is_torsion_free() || point.is_small_order() || point.compress().to_bytes() != encoded
    {
        return Err("invalid SPAKE2 subgroup or encoding".into());
    }
    Ok(message)
}

async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    code: &ShortCode,
    role: Role,
) -> Result<(Sealer, Opener), Error> {
    let id_a = Identity::new(format!("cayman/spake2-tls/1/sender/{}", code.room).as_bytes());
    let id_b = Identity::new(format!("cayman/spake2-tls/1/receiver/{}", code.room).as_bytes());
    let password = Password::new(code.password.as_bytes());
    let (state, message) = match role {
        Role::Sender => Spake2::<Ed25519Group>::start_a(&password, &id_a, &id_b),
        Role::Receiver => Spake2::<Ed25519Group>::start_b(&password, &id_a, &id_b),
    };
    let hello = [HELLO, message.as_slice()].concat();
    let mut frames = Framed::new(stream, HANDSHAKE_LIMIT, DEADLINE)?;
    let peer = match role {
        Role::Sender => {
            frames.send(&hello).await?;
            frames.receive().await?
        }
        Role::Receiver => {
            let peer = frames.receive().await?;
            validate_message(&peer, role)?;
            frames.send(&hello).await?;
            peer
        }
    };
    let key = Zeroizing::new(state.finish(validate_message(&peer, role)?)?);
    let (a, b) = match role {
        Role::Sender => (&hello, &peer),
        Role::Receiver => (&peer, &hello),
    };
    let mut hash = Sha256::new();
    for field in [DOMAIN, code.room.as_bytes(), a.as_slice(), b.as_slice()] {
        hash.update((field.len() as u32).to_be_bytes());
        hash.update(field);
    }
    let mut schedule = KeySchedule::from_pake_output(key, hash.finalize().into());
    let outgoing = match role {
        Role::Sender => Direction::SenderToReceiver,
        Role::Receiver => Direction::ReceiverToSender,
    };
    let incoming = match role {
        Role::Sender => Direction::ReceiverToSender,
        Role::Receiver => Direction::SenderToReceiver,
    };
    match role {
        Role::Sender => {
            frames.send(&schedule.confirmation(outgoing)).await?;
            schedule.verify_confirmation(incoming, &frames.receive().await?)?;
        }
        Role::Receiver => {
            schedule.verify_confirmation(incoming, &frames.receive().await?)?;
            frames.send(&schedule.confirmation(outgoing)).await?;
        }
    }
    Ok(schedule.into_records(outgoing)?)
}

pub async fn send<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    code: &ShortCode,
    invitation: &Invitation,
) -> Result<S, Error> {
    timeout(DEADLINE, async {
        let (mut seal, mut open) = exchange(&mut stream, code, Role::Sender).await?;
        let mut frames = Framed::new(&mut stream, HANDSHAKE_LIMIT, DEADLINE)?;
        let encoded = invitation.encode();
        frames.send(&seal.seal(encoded.as_bytes())?).await?;
        if open.open(&frames.receive().await?)? != b"cayman/spake2-tls/1/bootstrap-received" {
            return Err("pairing bootstrap acknowledgement failed".into());
        }
        Ok(stream)
    })
    .await
    .map_err(|_| "short-code pairing timed out")?
}
pub async fn receive<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    code: &ShortCode,
) -> Result<(S, Invitation), Error> {
    timeout(DEADLINE, async {
        let (mut seal, mut open) = exchange(&mut stream, code, Role::Receiver).await?;
        let mut frames = Framed::new(&mut stream, HANDSHAKE_LIMIT, DEADLINE)?;
        let plaintext = Zeroizing::new(open.open(&frames.receive().await?)?);
        let invitation = Invitation::parse(std::str::from_utf8(&plaintext)?)?;
        frames
            .send(&seal.seal(b"cayman/spake2-tls/1/bootstrap-received")?)
            .await?;
        Ok((stream, invitation))
    })
    .await
    .map_err(|_| "short-code pairing timed out")?
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn codes_roundtrip_and_room_does_not_disclose_password() {
        assert_eq!(words().len(), 256);
        assert_eq!(
            words()
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            256
        );
        for _ in 0..100 {
            let code = ShortCode::generate().unwrap();
            let encoded = code.encode();
            let parsed = ShortCode::parse(&encoded.to_uppercase()).unwrap();
            assert_eq!(*parsed.encode(), *encoded);
            assert!(encoded.len() < 50);
        }
        let a = ShortCode::parse("123456-maple-river-otter-cloud").unwrap();
        let b = ShortCode::parse("123456-amber-river-otter-cloud").unwrap();
        assert_eq!(a.relay_room(), b.relay_room());
        for invalid in [
            "123456",
            "123456-maple-river",
            "123456-maple-river-otter-password",
            "012345-maple-river-otter-cloud",
            "123456-maple-river-otter-cloud-extra",
        ] {
            assert!(ShortCode::parse(invalid).is_err());
        }
    }
    #[tokio::test]
    async fn confirms_password_and_binds_room_before_bootstrap() {
        let (_, invitation) = super::super::direct::server().unwrap();
        for peer in [
            "123456-maple-river-otter-cloud",
            "123456-amber-river-otter-cloud",
            "123457-maple-river-otter-cloud",
        ] {
            let a = ShortCode::parse("123456-maple-river-otter-cloud").unwrap();
            let b = ShortCode::parse(peer).unwrap();
            let (left, right) = tokio::io::duplex(256);
            let (sent, received) = tokio::join!(send(left, &a, &invitation), receive(right, &b));
            if peer == "123456-maple-river-otter-cloud" {
                sent.unwrap();
                let (_, got) = received.unwrap();
                assert_eq!(*got.encode(), *invitation.encode());
            } else {
                assert!(sent.is_err());
                assert!(received.is_err());
            }
        }
    }
    #[tokio::test]
    async fn altered_confirmation_or_bootstrap_fails_closed() {
        for tamper_bootstrap in [false, true] {
            let (_, invitation) = super::super::direct::server().unwrap();
            let code = ShortCode::parse("123456-maple-river-otter-cloud").unwrap();
            let (a, proxy_a) = tokio::io::duplex(1024);
            let (b, proxy_b) = tokio::io::duplex(1024);
            let proxy = async move {
                let mut left = Framed::new(proxy_a, HANDSHAKE_LIMIT, DEADLINE).unwrap();
                let mut right = Framed::new(proxy_b, HANDSHAKE_LIMIT, DEADLINE).unwrap();
                let hello_a = left.receive().await.unwrap();
                right.send(&hello_a).await.unwrap();
                let hello_b = right.receive().await.unwrap();
                left.send(&hello_b).await.unwrap();
                let mut confirmation = left.receive().await.unwrap();
                if !tamper_bootstrap {
                    confirmation[0] ^= 1;
                }
                right.send(&confirmation).await.unwrap();
                if tamper_bootstrap {
                    let confirmation = right.receive().await.unwrap();
                    left.send(&confirmation).await.unwrap();
                    let mut record = left.receive().await.unwrap();
                    record[12] ^= 1;
                    right.send(&record).await.unwrap();
                }
                // Drop both streams; no retry or unauthenticated fallback.
            };
            let (sent, received, ()) = timeout(Duration::from_secs(5), async {
                tokio::join!(send(a, &code, &invitation), receive(b, &code), proxy)
            })
            .await
            .unwrap();
            assert!(sent.is_err());
            assert!(received.is_err());
        }
    }

    #[test]
    fn invalid_roles_and_group_elements_are_rejected() {
        for point in [[0; 32], [255; 32], {
            let mut p = [0; 32];
            p[0] = 1;
            p
        }] {
            let mut hello = [HELLO, b"B"].concat();
            hello.extend(point);
            assert!(validate_message(&hello, Role::Sender).is_err());
        }
        assert!(validate_message(b"CYPAKE01", Role::Sender).is_err());
    }
}
