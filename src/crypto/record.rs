use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

const MAX_PLAINTEXT: usize = crate::protocol::frame::MAX_RECORD - 8 - 16;
const MAX_RECORDS: u64 = 1 << 24;
const MAX_BYTES: u64 = 64 * 1024 * 1024 * 1024;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    SenderToReceiver,
    ReceiverToSender,
}

impl Direction {
    fn label(self) -> &'static str {
        match self {
            Self::SenderToReceiver => "sender-to-receiver",
            Self::ReceiverToSender => "receiver-to-sender",
        }
    }
    fn role(self) -> &'static str {
        match self {
            Self::SenderToReceiver => "sender",
            Self::ReceiverToSender => "receiver",
        }
    }
    fn byte(self) -> u8 {
        match self {
            Self::SenderToReceiver => 0,
            Self::ReceiverToSender => 1,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("authentication failed")]
    Authentication,
    #[error("record is malformed, out of sequence, or too large")]
    InvalidRecord,
    #[error("key usage limit reached; establish a new session")]
    Exhausted,
    #[error("record direction is closed")]
    Closed,
}

/// Session schedule for the SPAKE2 adapter, NOT a password KDF.
/// The caller must supply fresh PAKE output and a canonical transcript hash,
/// exchange/verify both confirmations before releasing application data.
/// This type intentionally has no serialization or Debug implementation.
pub struct KeySchedule {
    secret: Zeroizing<Vec<u8>>,
    transcript: [u8; 32],
    verified_peer: Option<Direction>,
    failed: bool,
}

impl KeySchedule {
    pub fn from_pake_output(secret: Zeroizing<Vec<u8>>, transcript: [u8; 32]) -> Self {
        Self {
            secret,
            transcript,
            verified_peer: None,
            failed: false,
        }
    }

    fn derive<const N: usize>(&self, purpose: &str) -> Zeroizing<[u8; N]> {
        let hkdf = Hkdf::<Sha256>::new(Some(&self.transcript), &self.secret);
        let mut output = Zeroizing::new([0; N]);
        hkdf.expand(format!("cayman/1/{purpose}").as_bytes(), output.as_mut())
            .expect("fixed output sizes are within HKDF limits");
        output
    }

    pub fn confirmation(&self, direction: Direction) -> [u8; 32] {
        self.confirmation_mac(direction)
            .finalize()
            .into_bytes()
            .into()
    }

    fn confirmation_mac(&self, direction: Direction) -> Hmac<Sha256> {
        let key = self.derive::<32>(&format!("confirm/{}", direction.role()));
        let mut mac =
            <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(key.as_ref()).expect("HMAC key");
        mac.update(direction.role().as_bytes());
        mac.update(&self.transcript);
        mac
    }

    pub fn verify_confirmation(
        &mut self,
        direction: Direction,
        received: &[u8],
    ) -> Result<(), CryptoError> {
        if self.failed {
            return Err(CryptoError::Closed);
        }
        self.failed = true;
        self.confirmation_mac(direction)
            .verify_slice(received)
            .map_err(|_| CryptoError::Authentication)?;
        self.verified_peer = Some(direction);
        self.failed = false;
        Ok(())
    }

    /// Consume the schedule so traffic states cannot be duplicated accidentally.
    /// Call only after successful mutual confirmation.
    pub fn into_records(self, outgoing: Direction) -> Result<(Sealer, Opener), CryptoError> {
        let incoming = match outgoing {
            Direction::SenderToReceiver => Direction::ReceiverToSender,
            Direction::ReceiverToSender => Direction::SenderToReceiver,
        };
        if self.failed || self.verified_peer != Some(incoming) {
            return Err(CryptoError::Authentication);
        }
        Ok((Sealer(self.state(outgoing)), Opener(self.state(incoming))))
    }

    fn state(&self, direction: Direction) -> State {
        let key = self.derive::<32>(&format!("key/{}", direction.label()));
        let prefix = self.derive::<4>(&format!("nonce/{}", direction.label()));
        State {
            cipher: Aes256Gcm::new_from_slice(key.as_ref()).expect("AES-256 key"),
            prefix: *prefix,
            transcript: self.transcript,
            direction,
            sequence: 0,
            bytes: 0,
            closed: false,
        }
    }
}

struct State {
    cipher: Aes256Gcm,
    prefix: [u8; 4],
    transcript: [u8; 32],
    direction: Direction,
    sequence: u64,
    bytes: u64,
    closed: bool,
}

impl State {
    fn begin(&mut self, plaintext_len: usize) -> Result<(), CryptoError> {
        if self.closed {
            return Err(CryptoError::Closed);
        }
        // Errors permanently close this direction, including local size errors.
        self.closed = true;
        if plaintext_len > MAX_PLAINTEXT {
            return Err(CryptoError::InvalidRecord);
        }
        if self.sequence >= MAX_RECORDS || self.bytes + plaintext_len as u64 > MAX_BYTES {
            return Err(CryptoError::Exhausted);
        }
        Ok(())
    }

    fn nonce(&self) -> [u8; 12] {
        let mut nonce = [0; 12];
        nonce[..4].copy_from_slice(&self.prefix);
        nonce[4..].copy_from_slice(&self.sequence.to_be_bytes());
        nonce
    }

    fn aad(&self, length: usize) -> Vec<u8> {
        let mut aad = b"cayman/1".to_vec();
        aad.extend_from_slice(&self.transcript);
        aad.push(self.direction.byte());
        aad.extend_from_slice(&(length as u32).to_be_bytes());
        aad.extend_from_slice(&self.sequence.to_be_bytes());
        aad
    }

    fn advance(&mut self, length: usize) {
        self.sequence += 1;
        self.bytes += length as u64;
        self.closed = false;
    }
}

/// Produces frame bodies: sequence (8 bytes) followed by AES-GCM ciphertext/tag.
/// Never retry a socket write using this state: close the entire connection.
pub struct Sealer(State);
pub struct Opener(State);

impl Sealer {
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let state = &mut self.0;
        state.begin(plaintext.len())?;
        let ciphertext = state
            .cipher
            .encrypt(
                Nonce::from_slice(&state.nonce()),
                Payload {
                    msg: plaintext,
                    aad: &state.aad(8 + plaintext.len() + 16),
                },
            )
            .map_err(|_| CryptoError::Authentication)?;
        let mut record = Vec::with_capacity(8 + ciphertext.len());
        record.extend_from_slice(&state.sequence.to_be_bytes());
        record.extend_from_slice(&ciphertext);
        state.advance(plaintext.len());
        Ok(record)
    }
}

impl Opener {
    pub fn open(&mut self, record: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let state = &mut self.0;
        if record.len() < 24 {
            if state.closed {
                return Err(CryptoError::Closed);
            }
            state.closed = true;
            return Err(CryptoError::InvalidRecord);
        }
        state.begin(record.len() - 24)?;
        if record[..8] != state.sequence.to_be_bytes() {
            return Err(CryptoError::InvalidRecord);
        }
        let plaintext = state
            .cipher
            .decrypt(
                Nonce::from_slice(&state.nonce()),
                Payload {
                    msg: &record[8..],
                    aad: &state.aad(record.len()),
                },
            )
            .map_err(|_| CryptoError::Authentication)?;
        state.advance(plaintext.len());
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn schedule(secret: u8, transcript: u8) -> KeySchedule {
        KeySchedule::from_pake_output(Zeroizing::new(vec![secret; 32]), [transcript; 32])
    }
    fn confirmed(secret: u8, transcript: u8, outgoing: Direction) -> (Sealer, Opener) {
        let mut keys = schedule(secret, transcript);
        let peer = match outgoing {
            Direction::SenderToReceiver => Direction::ReceiverToSender,
            Direction::ReceiverToSender => Direction::SenderToReceiver,
        };
        let proof = keys.confirmation(peer);
        keys.verify_confirmation(peer, &proof).unwrap();
        keys.into_records(outgoing).unwrap()
    }
    fn pair() -> (Sealer, Opener) {
        let (seal, _) = confirmed(1, 2, Direction::SenderToReceiver);
        let (_, open) = confirmed(1, 2, Direction::ReceiverToSender);
        (seal, open)
    }

    #[test]
    fn confirmation_is_required_and_failure_is_terminal() {
        assert!(
            schedule(1, 2)
                .into_records(Direction::SenderToReceiver)
                .is_err()
        );
        let mut keys = schedule(1, 2);
        let valid = keys.confirmation(Direction::ReceiverToSender);
        assert!(
            keys.verify_confirmation(Direction::ReceiverToSender, &[0; 32])
                .is_err()
        );
        assert!(matches!(
            keys.verify_confirmation(Direction::ReceiverToSender, &valid),
            Err(CryptoError::Closed)
        ));
        assert!(keys.into_records(Direction::SenderToReceiver).is_err());
    }

    #[test]
    fn oversized_plaintext_closes_direction() {
        let (mut seal, _) = pair();
        assert!(matches!(
            seal.seal(&vec![0; MAX_PLAINTEXT + 1]),
            Err(CryptoError::InvalidRecord)
        ));
        assert!(matches!(seal.seal(b"valid"), Err(CryptoError::Closed)));
    }

    #[test]
    fn confirmation_binds_secret_transcript_and_role() {
        let mut a = schedule(1, 2);
        let proof = a.confirmation(Direction::SenderToReceiver);
        a.verify_confirmation(Direction::SenderToReceiver, &proof)
            .unwrap();
        for mut b in [schedule(2, 2), schedule(1, 3)] {
            assert!(
                b.verify_confirmation(Direction::SenderToReceiver, &proof)
                    .is_err()
            );
        }
        assert!(
            a.verify_confirmation(Direction::ReceiverToSender, &proof)
                .is_err()
        );
        assert!(
            a.verify_confirmation(Direction::SenderToReceiver, &proof[..31])
                .is_err()
        );
    }

    #[test]
    fn records_roundtrip_and_nonce_changes() {
        let (mut seal, mut open) = pair();
        let a = seal.seal(b"file metadata").unwrap();
        let b = seal.seal(b"file metadata").unwrap();
        assert_ne!(a, b);
        assert_eq!(open.open(&a).unwrap(), b"file metadata");
        assert_eq!(open.open(&b).unwrap(), b"file metadata");
        assert!(matches!(open.open(&a), Err(CryptoError::InvalidRecord)));
        assert!(matches!(open.open(&b), Err(CryptoError::Closed)));
    }

    #[test]
    fn tamper_and_truncation_fail_closed() {
        let (mut seal, _) = pair();
        let original = seal.seal(b"secret data").unwrap();
        for index in 0..original.len() {
            let (_, mut open) = pair();
            let mut changed = original.clone();
            changed[index] ^= 1;
            assert!(open.open(&changed).is_err());
            assert!(matches!(open.open(&original), Err(CryptoError::Closed)));
        }
        for length in 0..original.len() {
            let (_, mut open) = pair();
            assert!(open.open(&original[..length]).is_err());
        }
    }

    #[test]
    fn wrong_direction_and_session_fail() {
        let (mut seal, _) = pair();
        let record = seal.seal(b"data").unwrap();
        for (secret, transcript, role) in [
            (1, 2, Direction::SenderToReceiver),
            (2, 2, Direction::ReceiverToSender),
            (1, 3, Direction::ReceiverToSender),
        ] {
            let (_, mut open) = confirmed(secret, transcript, role);
            assert!(matches!(
                open.open(&record),
                Err(CryptoError::Authentication)
            ));
        }
    }

    #[test]
    fn sequence_gaps_and_limits_rejected() {
        let (mut seal, mut open) = pair();
        seal.seal(b"first").unwrap();
        assert!(open.open(&seal.seal(b"second").unwrap()).is_err());
        let (mut seal, _) = pair();
        seal.0.sequence = MAX_RECORDS;
        assert!(matches!(seal.seal(b"x"), Err(CryptoError::Exhausted)));
        let (mut seal, _) = pair();
        seal.0.bytes = MAX_BYTES;
        assert!(matches!(seal.seal(b"x"), Err(CryptoError::Exhausted)));
    }
}
