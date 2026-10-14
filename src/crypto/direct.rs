//! End-to-end TLS bootstrap for both transports: certificate pin + 256-bit secret.
//! The legacy invitation prefix and ALPN are preserved for wire compatibility.
//! This is NOT PAKE and never accepts a human-chosen low-entropy password.
use rustls::{
    ClientConfig, DigitallySignedStruct, ServerConfig, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use zeroize::Zeroizing;

pub type Error = Box<dyn std::error::Error + Send + Sync>;

pub struct Invitation {
    pub(crate) pin: [u8; 32],
    pub(crate) secret: Zeroizing<[u8; 32]>,
}

impl Invitation {
    pub fn encode(&self) -> Zeroizing<String> {
        let mut text = Zeroizing::new(String::from("cayman-direct-v1:"));
        for b in self.pin {
            text.push_str(&format!("{b:02x}"));
        }
        text.push(':');
        for b in self.secret.iter() {
            text.push_str(&format!("{b:02x}"));
        }
        text
    }

    pub fn parse(text: &str) -> Result<Self, Error> {
        let text = text.trim();
        let mut parts = text.split(':');
        if parts.next() != Some("cayman-direct-v1") {
            return Err("invalid TLS invitation".into());
        }
        fn decode(s: Option<&str>) -> Result<[u8; 32], Error> {
            let s = s.ok_or("invalid TLS invitation")?;
            if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err("invalid TLS invitation".into());
            }
            let mut output = [0; 32];
            for (i, byte) in output.iter_mut().enumerate() {
                *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16)?;
            }
            Ok(output)
        }
        let pin = decode(parts.next())?;
        let secret = Zeroizing::new(decode(parts.next())?);
        if parts.next().is_some() {
            return Err("invalid TLS invitation".into());
        }
        Ok(Self { pin, secret })
    }
}

pub fn server() -> Result<(Arc<ServerConfig>, Invitation), Error> {
    let certified = rcgen::generate_simple_self_signed(vec!["cayman.invalid".into()])?;
    let cert = certified.cert.der().clone();
    let pin = Sha256::digest(&cert).into();
    let mut secret = Zeroizing::new([0; 32]);
    getrandom::fill(secret.as_mut()).map_err(|e| format!("random source failed: {e}"))?;
    let key = PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());
    let mut config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_single_cert(vec![cert], key.into())?;
    config.alpn_protocols = vec![b"cayman-direct/1".to_vec()];
    config.send_tls13_tickets = 0;
    Ok((Arc::new(config), Invitation { pin, secret }))
}

pub fn client(invitation: &Invitation) -> Result<Arc<ClientConfig>, Error> {
    let mut config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(Pinned(invitation.pin)))
            .with_no_client_auth();
    config.alpn_protocols = vec![b"cayman-direct/1".to_vec()];
    config.resumption = rustls::client::Resumption::disabled();
    Ok(Arc::new(config))
}

/// A pin is an out-of-band trust anchor, not a hostname/CA trust decision.
/// TLS CertificateVerify signatures are still verified by rustls's provider.
#[derive(Debug)]
struct Pinned([u8; 32]);
impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        cert: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let actual: [u8; 32] = Sha256::digest(cert).into();
        if actual != self.0 {
            return Err(rustls::Error::General("certificate pin mismatch".into()));
        }
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2 is disabled".into()))
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            signature,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    #[test]
    fn invitation_roundtrips_and_rejects_short_passwords() {
        let (_, invitation) = server().unwrap();
        let code = invitation.encode();
        let parsed = Invitation::parse(&code).unwrap();
        assert_eq!(parsed.pin, invitation.pin);
        assert_eq!(*parsed.secret, *invitation.secret);
        for text in ["123456", "secret-words", "cayman-direct-v1:abc:def"] {
            assert!(Invitation::parse(text).is_err());
        }
    }

    #[tokio::test]
    async fn tls_accepts_only_pinned_certificate() {
        for wrong_pin in [false, true] {
            let (config, mut invitation) = server().unwrap();
            if wrong_pin {
                invitation.pin[0] ^= 1;
            }
            let client_config = client(&invitation).unwrap();
            let (a, b) = tokio::io::duplex(64 * 1024);
            let server = TlsAcceptor::from(config);
            let client = TlsConnector::from(client_config);
            let (accepted, connected) = tokio::join!(
                server.accept(a),
                client.connect("cayman.invalid".try_into().unwrap(), b)
            );
            if wrong_pin {
                assert!(connected.is_err());
            } else {
                assert!(accepted.is_ok());
                assert!(connected.is_ok());
            }
        }
    }
}
