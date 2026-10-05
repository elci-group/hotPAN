use crate::{decode32, SealError};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::path::Path;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// Signing + key-exchange secrets. Both zeroize on drop.
pub struct Keypair {
    pub(crate) signing: SigningKey,
    pub(crate) kex: StaticSecret,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct PublicKeys {
    pub signing: String,
    pub kex: String,
}

impl Keypair {
    pub fn generate() -> Self {
        Self { signing: SigningKey::generate(&mut OsRng), kex: StaticSecret::random_from_rng(OsRng) }
    }

    pub fn public(&self) -> PublicKeys {
        PublicKeys {
            signing: hex::encode(self.signing.verifying_key().as_bytes()),
            kex: hex::encode(PublicKey::from(&self.kex).as_bytes()),
        }
    }

    pub fn sign(&self, domain: &[u8], msg: &[u8]) -> String {
        let mut buf = Vec::with_capacity(domain.len() + msg.len());
        buf.extend_from_slice(domain);
        buf.extend_from_slice(msg);
        hex::encode(self.signing.sign(&buf).to_bytes())
    }

    pub(crate) fn kex_secret(&self) -> &StaticSecret {
        &self.kex
    }

    /// Raw x25519 secret, for use as a Noise static key.
    pub fn kex_secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.kex.to_bytes())
    }

    /// Load a persisted keypair (orchestrator only — nodes never persist keys).
    pub fn load(path: &Path) -> Result<Self, SealError> {
        let text = Zeroizing::new(std::fs::read_to_string(path).map_err(|e| SealError::Io(e.to_string()))?);
        let raw = Zeroizing::new(hex::decode(text.trim()).map_err(|e| SealError::Encoding(e.to_string()))?);
        if raw.len() != 64 {
            return Err(SealError::Encoding("key file must hold 64 bytes".into()));
        }
        let mut s = Zeroizing::new([0u8; 32]);
        let mut k = Zeroizing::new([0u8; 32]);
        s.copy_from_slice(&raw[..32]);
        k.copy_from_slice(&raw[32..]);
        Ok(Self { signing: SigningKey::from_bytes(&s), kex: StaticSecret::from(*k) })
    }

    /// Persist with owner-only permissions. Refuses to overwrite.
    pub fn save(&self, path: &Path) -> Result<(), SealError> {
        use std::io::Write;
        let mut raw = Zeroizing::new(Vec::with_capacity(64));
        raw.extend_from_slice(&self.signing.to_bytes());
        raw.extend_from_slice(self.kex.as_bytes());
        let text = Zeroizing::new(hex::encode(&*raw));
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(path).map_err(|e| SealError::Io(e.to_string()))?;
        f.write_all(text.as_bytes()).map_err(|e| SealError::Io(e.to_string()))
    }
}

pub(crate) fn verify(signing_pub: &str, domain: &[u8], msg: &[u8], sig: &str) -> Result<(), SealError> {
    let key = VerifyingKey::from_bytes(&decode32(signing_pub)?).map_err(|e| SealError::Encoding(e.to_string()))?;
    let sig_bytes: [u8; 64] = hex::decode(sig)
        .map_err(|e| SealError::Encoding(e.to_string()))?
        .try_into()
        .map_err(|_| SealError::Encoding("expected 64-byte signature".into()))?;
    let mut buf = Vec::with_capacity(domain.len() + msg.len());
    buf.extend_from_slice(domain);
    buf.extend_from_slice(msg);
    key.verify(&buf, &ed25519_dalek::Signature::from_bytes(&sig_bytes)).map_err(|_| SealError::BadSignature)
}

const HELLO: &[u8] = b"hotpan/hello/v1\0";
const WELCOME: &[u8] = b"hotpan/welcome/v1\0";

/// The control plane proves it is the pinned orchestrator *and* the other end
/// of this encrypted channel by signing the channel binding (handshake hash).
pub fn welcome_proof(keys: &Keypair, binding: &str) -> String {
    keys.sign(WELCOME, binding.as_bytes())
}

pub fn verify_welcome_proof(signing_pub: &str, binding: &str, proof: &str) -> Result<(), SealError> {
    verify(signing_pub, WELCOME, binding.as_bytes(), proof)
}

/// A peer proves possession of its session signing key by signing the
/// channel binding (the Noise handshake hash).
pub fn hello_proof(keys: &Keypair, binding: &str) -> String {
    keys.sign(HELLO, binding.as_bytes())
}

pub fn verify_hello_proof(signing_pub: &str, binding: &str, proof: &str) -> Result<(), SealError> {
    verify(signing_pub, HELLO, binding.as_bytes(), proof)
}

/// Keyed proof that the peer knows the fabric pairing secret, bound to the
/// channel binding and the peer's session key (so it cannot be replayed).
pub fn pairing_proof(secret: &str, binding: &str, signing_pub: &str) -> String {
    let key = blake3::derive_key("hotpan pairing v1", secret.as_bytes());
    let mut h = blake3::Hasher::new_keyed(&key);
    h.update(binding.as_bytes());
    h.update(b"\0");
    h.update(signing_pub.as_bytes());
    h.finalize().to_hex().to_string()
}

pub fn verify_pairing_proof(secret: &str, binding: &str, signing_pub: &str, proof: &str) -> bool {
    let expected = pairing_proof(secret, binding, signing_pub);
    match (blake3::Hash::from_hex(&expected), blake3::Hash::from_hex(proof)) {
        // blake3::Hash equality is constant-time.
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random_nonce() -> String {
        use rand_core::RngCore;
        let mut n = [0u8; 32];
        OsRng.fill_bytes(&mut n);
        hex::encode(n)
    }

    #[test]
    fn save_load_round_trip_and_no_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("orch.key");
        let k = Keypair::generate();
        k.save(&p).unwrap();
        assert!(k.save(&p).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        }
        assert_eq!(Keypair::load(&p).unwrap().public(), k.public());
    }

    #[test]
    fn hello_and_pairing() {
        let k = Keypair::generate();
        let n = random_nonce();
        let pk = k.public().signing;
        verify_hello_proof(&pk, &n, &hello_proof(&k, &n)).unwrap();
        verify_welcome_proof(&pk, &n, &welcome_proof(&k, &n)).unwrap();
        // Domain separation: a hello proof is not a welcome proof.
        assert!(verify_welcome_proof(&pk, &n, &hello_proof(&k, &n)).is_err());
        assert!(verify_hello_proof(&pk, &random_nonce(), &hello_proof(&k, &n)).is_err());
        let proof = pairing_proof("s3cret", &n, &pk);
        assert!(verify_pairing_proof("s3cret", &n, &pk, &proof));
        assert!(!verify_pairing_proof("wrong", &n, &pk, &proof));
        assert!(!verify_pairing_proof("s3cret", &random_nonce(), &pk, &proof));
        assert!(!verify_pairing_proof("s3cret", &n, &pk, "zz"));
    }
}
