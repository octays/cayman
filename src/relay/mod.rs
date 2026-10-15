//! croc v11.5.3 legacy relay admission; application traffic stays end-to-end TLS.
mod pake;
use crate::crypto::direct::Error;
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use std::{num::NonZeroU32, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};
use zeroize::Zeroizing;

pub const DEFAULT_RELAY: &str = "croc.schollz.com:9009";
const LIMIT: usize = 64 * 1024;
const READY: &[u8] = b"cayman-relay-spake2-tls/1";

pub async fn connect(address: &str, password: &str, room: &str) -> Result<TcpStream, Error> {
    timeout(Duration::from_secs(30), async {
        let mut tcp = TcpStream::connect(address).await?;
        tcp.set_nodelay(true)?;
        admit(&mut tcp, password, room).await?;
        Ok(tcp)
    })
    .await
    .map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "relay connection/admission timed out",
        )
    })?
}

// Exact reads are important: room confirmation and the peer's first frame can
// arrive together. Never consume bytes belonging to the next protocol phase.
async fn send<S: AsyncWrite + Unpin>(stream: &mut S, bytes: &[u8]) -> Result<(), Error> {
    if bytes.len() > LIMIT {
        return Err("relay frame too large".into());
    }
    stream.write_all(b"croc").await?;
    stream
        .write_all(&(bytes.len() as u32).to_le_bytes())
        .await?;
    stream.write_all(bytes).await?;
    stream.flush().await?;
    Ok(())
}
async fn read<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>, Error> {
    let mut header = [0; 8];
    stream.read_exact(&mut header).await?;
    if &header[..4] != b"croc" {
        return Err("invalid croc relay frame magic".into());
    }
    let size = u32::from_le_bytes(header[4..].try_into()?) as usize;
    if size > LIMIT {
        return Err("relay frame exceeds admission limit".into());
    }
    let mut bytes = vec![0; size];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}
fn cipher(key: &[u8], salt: &[u8]) -> Aes256Gcm {
    let mut derived = Zeroizing::new([0; 32]);
    ring::pbkdf2::derive(
        ring::pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(100).unwrap(),
        salt,
        key,
        derived.as_mut(),
    );
    Aes256Gcm::new_from_slice(derived.as_ref()).unwrap()
}
fn seal(cipher: &Aes256Gcm, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    let mut nonce = [0; 12];
    getrandom::fill(&mut nonce).map_err(|e| format!("random source: {e}"))?;
    let mut result = nonce.to_vec();
    result.extend(
        cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .map_err(|_| "relay encryption failed")?,
    );
    Ok(result)
}
fn open(cipher: &Aes256Gcm, bytes: &[u8]) -> Result<Vec<u8>, Error> {
    if bytes.len() < 28 {
        return Err("truncated relay ciphertext".into());
    }
    cipher
        .decrypt(Nonce::from_slice(&bytes[..12]), &bytes[12..])
        .map_err(|_| "relay response authentication failed".into())
}
async fn admit<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    password: &str,
    room: &str,
) -> Result<(), Error> {
    if password.len() > 4096 || room.is_empty() || room.len() > 128 {
        return Err("invalid relay admission parameters".into());
    }
    let (pake, hello) = pake::Client::start()?;
    send(stream, &hello).await?;
    let key = pake.finish(&read(stream).await?)?;
    let mut salt = [0; 8];
    getrandom::fill(&mut salt).map_err(|e| format!("random source: {e}"))?;
    let cipher = cipher(key.as_ref(), &salt);
    send(stream, &salt).await?;
    send(stream, &seal(&cipher, password.as_bytes())?).await?;
    let banner = open(&cipher, &read(stream).await?)?;
    if banner == b"bad password" {
        return Err("relay password rejected".into());
    }
    if !banner.windows(3).any(|w| w == b"|||") {
        return Err("invalid relay admission banner".into());
    }
    send(stream, &seal(&cipher, room.as_bytes())?).await?;
    match open(&cipher, &read(stream).await?)?.as_slice() {
        b"ok" => Ok(()),
        b"room full" => Err("relay room is already occupied".into()),
        b"rate limited" => Err("relay admission rate limited".into()),
        _ => Err("relay room admission rejected".into()),
    }
}

/// Keepalive frames are accepted only before the peer protocol marker. After
/// the marker the byte stream belongs exclusively to TLS, without frame parsing.
pub async fn pair<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S) -> Result<S, Error> {
    timeout(Duration::from_secs(600), async {
        send(&mut stream, READY).await?;
        loop {
            let message = read(&mut stream).await?;
            if message == READY {
                return Ok(stream);
            }
            if message != [1] {
                return Err("unexpected peer protocol on relay".into());
            }
        }
    })
    .await
    .map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "timed out waiting for relay peer",
        )
    })?
}

#[cfg(all(test, unix))]
pub(crate) async fn test_admit<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    room: &str,
) -> Result<(), Error> {
    admit(stream, "pass123", room).await
}
#[cfg(test)]
pub(crate) async fn test_server<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    admission: &[u8],
) -> String {
    let (reply, key) = pake::server_reply(&read(stream).await.unwrap());
    send(stream, &reply).await.unwrap();
    let salt = read(stream).await.unwrap();
    assert_eq!(salt.len(), 8);
    let cipher = cipher(key.as_ref(), &salt);
    let password = open(&cipher, &read(stream).await.unwrap()).unwrap();
    if password != b"pass123" {
        send(stream, &seal(&cipher, b"bad password").unwrap())
            .await
            .unwrap();
        return String::new();
    }
    send(stream, &seal(&cipher, b"ok|||127.0.0.1:1234").unwrap())
        .await
        .unwrap();
    let room = String::from_utf8(open(&cipher, &read(stream).await.unwrap()).unwrap()).unwrap();
    send(stream, &seal(&cipher, admission).unwrap())
        .await
        .unwrap();
    room
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;
    #[test]
    fn go_pbkdf2_and_gcm_fixture() {
        let f: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/fixtures/relay-v11.5.3.json")).unwrap();
        let bytes = |s: &str| pake::fixture_hex(f[s].as_str().unwrap());
        let c = cipher(&bytes("key"), &bytes("salt"));
        assert_eq!(
            open(&c, &bytes("encrypted_banner")).unwrap(),
            b"ok|||127.0.0.1:12345"
        );
        let mut tampered = bytes("encrypted_banner");
        tampered[15] ^= 1;
        assert!(open(&c, &tampered).is_err());
        assert!(open(&c, &[0; 27]).is_err());
    }
    #[tokio::test]
    async fn admission_and_rejections() {
        for (password, response, ok) in [
            ("pass123", b"ok".as_slice(), true),
            ("bad", b"ok".as_slice(), false),
            ("pass123", b"room full".as_slice(), false),
            ("pass123", b"rate limited".as_slice(), false),
        ] {
            let (mut client, mut server) = duplex(64);
            let (result, room) = tokio::join!(
                admit(&mut client, password, "public-room"),
                test_server(&mut server, response)
            );
            assert_eq!(result.is_ok(), ok);
            if password == "pass123" {
                assert_eq!(room, "public-room");
            }
        }
    }
    #[tokio::test]
    async fn fragmented_keepalive_and_coalesced_tls_bytes() {
        let (client, mut server) = duplex(16);
        let server = async move {
            assert_eq!(read(&mut server).await.unwrap(), READY);
            let mut bytes = Vec::new();
            for body in [&[1][..], READY] {
                bytes.extend(b"croc");
                bytes.extend((body.len() as u32).to_le_bytes());
                bytes.extend(body);
            }
            bytes.extend(b"first TLS bytes");
            for byte in bytes {
                server.write_all(&[byte]).await.unwrap();
            }
        };
        let client = async {
            let mut stream = pair(client).await.unwrap();
            let mut bytes = [0; 15];
            stream.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"first TLS bytes");
        };
        tokio::join!(client, server);
    }
    #[tokio::test]
    async fn bad_frames_and_peer_markers_fail_closed() {
        for bytes in [
            b"oops\0\0\0\0".to_vec(),
            [b"croc".as_slice(), &u32::MAX.to_le_bytes()].concat(),
            b"croc\x03\0\0\0ab".to_vec(),
        ] {
            let (mut client, mut server) = duplex(64);
            server.write_all(&bytes).await.unwrap();
            drop(server);
            assert!(read(&mut client).await.is_err());
        }
        let (client, mut server) = duplex(64);
        send(&mut server, b"wrong protocol").await.unwrap();
        assert!(pair(client).await.is_err());
    }
}
