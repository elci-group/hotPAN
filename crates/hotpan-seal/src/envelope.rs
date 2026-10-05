use crate::{decode32, Keypair, SealError};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::Zeroizing;

/// A payload sealed to one recipient's x25519 key. Each envelope uses a fresh
/// ephemeral sender key, so compromising one envelope reveals nothing else.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Envelope {
    pub ephemeral: String,
    pub nonce: String,
    pub ciphertext: String,
}

fn derive(shared: &[u8; 32], eph: &[u8; 32], recipient: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut h = blake3::Hasher::new_derive_key("hotpan envelope v1");
    h.update(shared);
    h.update(eph);
    h.update(recipient);
    Zeroizing::new(*h.finalize().as_bytes())
}

/// Seal `plaintext` to `recipient_kex` (hex), binding it to `aad`
/// (callers pass the lease id so envelopes cannot be swapped between leases).
pub fn seal(recipient_kex: &str, aad: &[u8], plaintext: &[u8]) -> Result<Envelope, SealError> {
    let recipient = PublicKey::from(decode32(recipient_kex)?);
    let eph = EphemeralSecret::random_from_rng(OsRng);
    let eph_pub = PublicKey::from(&eph);
    let shared = eph.diffie_hellman(&recipient);
    if !shared.was_contributory() {
        return Err(SealError::Encoding("non-contributory recipient key".into()));
    }
    let key = derive(shared.as_bytes(), eph_pub.as_bytes(), recipient.as_bytes());
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ct = ChaCha20Poly1305::new(key.as_ref().into())
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad })
        .map_err(|_| SealError::Open)?;
    Ok(Envelope { ephemeral: hex::encode(eph_pub.as_bytes()), nonce: hex::encode(nonce), ciphertext: hex::encode(ct) })
}

pub fn open(keys: &Keypair, env: &Envelope, aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, SealError> {
    let eph = PublicKey::from(decode32(&env.ephemeral)?);
    let nonce: [u8; 12] = hex::decode(&env.nonce)
        .map_err(|e| SealError::Encoding(e.to_string()))?
        .try_into()
        .map_err(|_| SealError::Encoding("expected 12-byte nonce".into()))?;
    let ct = hex::decode(&env.ciphertext).map_err(|e| SealError::Encoding(e.to_string()))?;
    let secret = keys.kex_secret();
    let shared = secret.diffie_hellman(&eph);
    let key = derive(shared.as_bytes(), eph.as_bytes(), PublicKey::from(secret).as_bytes());
    ChaCha20Poly1305::new(key.as_ref().into())
        .decrypt(Nonce::from_slice(&nonce), Payload { msg: &ct, aad })
        .map(Zeroizing::new)
        .map_err(|_| SealError::Open)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_round_trip_and_binding() {
        let r = Keypair::generate();
        let env = seal(&r.public().kex, b"lease-1", b"hello node").unwrap();
        assert_eq!(&**open(&r, &env, b"lease-1").unwrap(), b"hello node");
        // Wrong aad (envelope moved to another lease), wrong recipient, tampering.
        assert_eq!(open(&r, &env, b"lease-2"), Err(SealError::Open));
        assert_eq!(open(&Keypair::generate(), &env, b"lease-1"), Err(SealError::Open));
        let mut t = env.clone();
        let mut ct = hex::decode(&t.ciphertext).unwrap();
        ct[0] ^= 1;
        t.ciphertext = hex::encode(ct);
        assert_eq!(open(&r, &t, b"lease-1"), Err(SealError::Open));
        // Fresh ephemeral per envelope.
        assert_ne!(seal(&r.public().kex, b"a", b"x").unwrap().ephemeral, env.ephemeral);
    }

    #[test]
    fn rejects_low_order_key() {
        assert!(seal(&hex::encode([0u8; 32]), b"", b"x").is_err());
    }
}
