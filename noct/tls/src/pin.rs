//! Trusting a single, named certificate instead of a certificate authority.
//!
//! ## Why this exists
//!
//! A pool operator running from home has no domain name and cannot get a
//! certificate from Let's Encrypt. Their realistic options are a self-signed
//! certificate that clients cannot verify, or no TLS at all — and the second is
//! what actually happens, because the first produces scary errors.
//!
//! Pinning gives a third option with a well-understood security argument: the
//! operator publishes the SHA-256 of their certificate, and clients accept that
//! certificate and nothing else. This is the SSH host-key model. No authority
//! attests to the identity, so the *first* delivery of the fingerprint has to be
//! trustworthy (a pool's website, a forum post, word of mouth); every connection
//! afterwards is verified against it, and an attacker who intercepts the
//! connection cannot produce a certificate that matches.
//!
//! ## What it deliberately does not do
//!
//! It does not accept *any* self-signed certificate, and there is no
//! "skip verification" flag anywhere in this crate. A knob that disables
//! verification is the knob everyone ends up turning, and it converts TLS into
//! an expensive way to send plaintext.
//!
//! ## What a pin does not check
//!
//! Pinning replaces the entire chain-of-trust check, which means it also
//! replaces the **expiry** and **hostname** checks — a pinned certificate is
//! trusted after it expires, and at whatever address you dialled. That is
//! coherent (the identity being verified is the key, not the name or the
//! calendar) but it is a real difference from CA verification and is why the
//! CA path stays the default whenever a domain name exists.
//!
//! ## What is still checked
//!
//! Everything else. Only the *certificate identity* decision is replaced here;
//! rustls still performs the handshake signature verification that proves the
//! peer holds the matching private key — delegated below to the provider's own
//! implementation rather than reimplemented. Without that, pinning a public
//! certificate would prove nothing, since certificates are public by nature.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error, SignatureScheme};
use sha2::{Digest, Sha256};

/// SHA-256 of a DER-encoded certificate: the value a client pins.
pub fn fingerprint(der: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(der);
    h.finalize().into()
}

/// Parse a fingerprint as written by a human.
///
/// Accepts bare hex and the colon-separated form `openssl x509 -fingerprint`
/// prints, in either case, because both are what people will paste.
pub fn parse_fingerprint(s: &str) -> Result<[u8; 32], String> {
    let cleaned: String = s.chars().filter(|c| !matches!(c, ':' | ' ' | '-')).collect();
    let bytes = hex::decode(&cleaned)
        .map_err(|_| format!("`{s}` is not a hex SHA-256 fingerprint"))?;
    <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| format!("a SHA-256 fingerprint is 32 bytes (64 hex characters); got {}", cleaned.len() / 2))
}

/// Render a fingerprint for an operator to publish.
pub fn show_fingerprint(fp: &[u8; 32]) -> String {
    hex::encode(fp)
}

/// Accepts exactly one certificate, identified by its SHA-256.
#[derive(Debug)]
pub struct PinnedServerCertVerifier {
    pin: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl PinnedServerCertVerifier {
    pub fn new(pin: [u8; 32], provider: Arc<CryptoProvider>) -> Self {
        PinnedServerCertVerifier { pin, provider }
    }
}

impl ServerCertVerifier for PinnedServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        // Only the leaf is considered. Intermediates are irrelevant when there
        // is no authority to chain up to, and accepting a match anywhere in the
        // chain would let anyone holding a certificate signed by the pinned one
        // impersonate the server.
        let seen = fingerprint(end_entity);
        if constant_time_eq(&seen, &self.pin) {
            Ok(ServerCertVerified::assertion())
        } else {
            // rustls will surface this to the user; make it actionable, since the
            // overwhelmingly likely cause is a rotated certificate rather than an
            // attack — and the operator needs to know which value to republish.
            Err(Error::General(format!(
                "certificate fingerprint mismatch: the server presented {}, but {} was pinned. \
                 If the pool rotated its certificate, get the new fingerprint from the operator \
                 over a channel you trust.",
                show_fingerprint(&seen),
                show_fingerprint(&self.pin),
            )))
        }
    }

    // The two signature checks below are what prove the peer actually holds the
    // private key for the pinned certificate. They are delegated to the crypto
    // provider verbatim — reimplementing them is precisely the mistake that
    // turns a custom verifier into a vulnerability.
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// Compare without an early exit.
///
/// A fingerprint is public, so a timing leak here is not a real attack — but a
/// comparison against a secret is one line away from this one, and the habit is
/// worth more than the microseconds.
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// People paste fingerprints from `openssl`, which colon-separates them, and
    /// from a web page, which usually does not. Both must work; anything that is
    /// not a 32-byte hex value must be refused rather than silently truncated.
    #[test]
    fn fingerprints_parse_in_the_forms_people_paste() {
        let raw = [0xABu8; 32];
        let hexed = hex::encode(raw);
        assert_eq!(parse_fingerprint(&hexed).unwrap(), raw);
        assert_eq!(parse_fingerprint(&hexed.to_uppercase()).unwrap(), raw);

        let colons = hexed
            .as_bytes()
            .chunks(2)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join(":");
        assert_eq!(parse_fingerprint(&colons).unwrap(), raw);

        for bad in ["", "zz", &hexed[..62], &format!("{hexed}00")] {
            assert!(parse_fingerprint(bad).is_err(), "`{bad}` should be refused");
        }
    }

    /// The pin must be the hash of the certificate actually served, or the whole
    /// scheme is decorative.
    #[test]
    fn the_pin_is_the_hash_of_the_served_certificate() {
        let gen = crate::selfsigned(&["localhost".to_string()]).unwrap();
        // Recompute from the PEM the way a client recomputes from the DER it is
        // handed on the wire.
        let der = rustls_pemfile::certs(&mut gen.cert_pem.as_bytes())
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(fingerprint(&der), gen.fingerprint);
    }

    /// The property the module exists for: the pinned certificate is accepted and
    /// every other certificate is refused — including another perfectly valid
    /// self-signed one for the same host name, which is exactly what an attacker
    /// would present.
    #[test]
    fn only_the_pinned_certificate_is_accepted() {
        let real = crate::selfsigned(&["localhost".to_string()]).unwrap();
        let impostor = crate::selfsigned(&["localhost".to_string()]).unwrap();
        assert_ne!(real.fingerprint, impostor.fingerprint);

        let verifier = PinnedServerCertVerifier::new(
            real.fingerprint,
            Arc::new(rustls::crypto::ring::default_provider()),
        );
        let der_of = |pem: &str| -> CertificateDer<'static> {
            rustls_pemfile::certs(&mut pem.as_bytes()).next().unwrap().unwrap()
        };
        let name = ServerName::try_from("localhost").unwrap();
        let now = UnixTime::since_unix_epoch(std::time::Duration::from_secs(1_760_000_000));

        assert!(verifier
            .verify_server_cert(&der_of(&real.cert_pem), &[], &name, &[], now)
            .is_ok());

        let err = verifier
            .verify_server_cert(&der_of(&impostor.cert_pem), &[], &name, &[], now)
            .unwrap_err();
        assert!(format!("{err}").contains("fingerprint mismatch"), "{err}");
    }

    /// A certificate that merely *contains* the pinned one deeper in the chain
    /// must not be accepted — only the leaf counts.
    #[test]
    fn a_match_among_the_intermediates_does_not_count() {
        let real = crate::selfsigned(&["localhost".to_string()]).unwrap();
        let impostor = crate::selfsigned(&["localhost".to_string()]).unwrap();
        let verifier = PinnedServerCertVerifier::new(
            real.fingerprint,
            Arc::new(rustls::crypto::ring::default_provider()),
        );
        let der_of = |pem: &str| -> CertificateDer<'static> {
            rustls_pemfile::certs(&mut pem.as_bytes()).next().unwrap().unwrap()
        };
        let name = ServerName::try_from("localhost").unwrap();
        let now = UnixTime::since_unix_epoch(std::time::Duration::from_secs(1_760_000_000));

        assert!(verifier
            .verify_server_cert(
                &der_of(&impostor.cert_pem),
                &[der_of(&real.cert_pem)],
                &name,
                &[],
                now,
            )
            .is_err());
    }

    #[test]
    fn constant_time_eq_still_compares_correctly() {
        let a = [7u8; 32];
        let mut b = a;
        assert!(constant_time_eq(&a, &b));
        b[31] ^= 1;
        assert!(!constant_time_eq(&a, &b));
        b = a;
        b[0] ^= 0x80;
        assert!(!constant_time_eq(&a, &b));
    }
}
