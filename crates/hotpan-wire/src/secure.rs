//! The encrypted, authenticated channel every hotPAN connection runs over.
//!
//! Before any protocol message is exchanged the dialler (node or client) and
//! the control plane run a `Noise_XX_25519_ChaChaPoly_BLAKE2s` handshake. Each
//! side's Noise static key is its existing x25519 key, so the channel is tied
//! to the same identity that envelopes are sealed to.
//!
//! Noise XX on its own proves possession of static keys, not *which* keys are
//! trusted. hotPAN closes that gap one layer up: the control plane signs the
//! handshake hash with its pinned ed25519 key (`Welcome::proof`), and peers
//! sign it with their session key (`Hello::proof`). A man in the middle runs
//! two handshakes with two different hashes and cannot produce either
//! signature.
//!
//! After the handshake every frame is encrypted and authenticated with
//! strictly increasing nonces, so tampering, reordering, replay and truncation
//! all surface as errors. Frames longer than one Noise message are split into
//! chunks; the frame length travels *inside* the first encrypted chunk.

use crate::{WireError, MAX_FRAME};
use serde::{de::DeserializeOwned, Serialize};
use snow::{Builder, HandshakeState, StatelessTransportState};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const NOISE_PARAMS: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
/// Mixed into the handshake: peers speaking another protocol revision fail
/// the handshake instead of misparsing each other.
const PROLOGUE: &[u8] = b"hotpan/3";
const MAX_NOISE: usize = 65_535;
const TAG: usize = 16;
const CHUNK: usize = MAX_NOISE - TAG;

/// What the handshake established.
#[derive(Clone, Debug)]
pub struct Session {
    /// The peer's Noise static (x25519) public key.
    pub remote_static: [u8; 32],
    /// Unique to this channel; everything authenticated above is bound to it.
    pub handshake_hash: Vec<u8>,
}

impl Session {
    /// Hex handshake hash: the value proofs are signed over.
    pub fn binding(&self) -> String {
        hex::encode(&self.handshake_hash)
    }

    pub fn remote_static_hex(&self) -> String {
        hex::encode(self.remote_static)
    }
}

pub struct SecureReader<R> {
    inner: R,
    state: Arc<StatelessTransportState>,
    nonce: u64,
    /// Largest frame this reader will assemble; see [`SecureReader::set_max_frame`].
    max_frame: usize,
}

/// Frame cap before the peer has authenticated (`Hello` and `Welcome`).
pub const HANDSHAKE_FRAME: usize = 256 << 10;
/// Frame cap for client requests.
pub const CLIENT_FRAME: usize = 4 << 20;

pub struct SecureWriter<W> {
    inner: W,
    state: Arc<StatelessTransportState>,
    nonce: u64,
}

fn noise(e: snow::Error) -> WireError {
    WireError::Noise(e.to_string())
}

async fn send_raw<W: AsyncWrite + Unpin>(w: &mut W, bytes: &[u8]) -> Result<(), WireError> {
    debug_assert!(bytes.len() <= MAX_NOISE);
    w.write_all(&(bytes.len() as u16).to_be_bytes()).await?;
    w.write_all(bytes).await?;
    Ok(())
}

async fn recv_raw<R: AsyncRead + Unpin>(r: &mut R) -> Result<Vec<u8>, WireError> {
    let mut len = [0u8; 2];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Err(WireError::Closed),
        Err(e) => return Err(e.into()),
    }
    let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}

fn builder(local_static: &[u8; 32]) -> Result<Builder<'_>, WireError> {
    #[allow(clippy::expect_used)] // constant, covered by every handshake test
    let params = NOISE_PARAMS.parse().expect("valid noise params");
    Builder::new(params).prologue(PROLOGUE).map_err(noise)?.local_private_key(local_static).map_err(noise)
}

fn finish<R, W>(hs: HandshakeState, r: R, w: W) -> Result<(SecureReader<R>, SecureWriter<W>, Session), WireError> {
    let remote: [u8; 32] = hs
        .get_remote_static()
        .and_then(|k| k.try_into().ok())
        .ok_or_else(|| WireError::Noise("peer sent no static key".into()))?;
    let session = Session { remote_static: remote, handshake_hash: hs.get_handshake_hash().to_vec() };
    let state = Arc::new(hs.into_stateless_transport_mode().map_err(noise)?);
    Ok((
        SecureReader { inner: r, state: state.clone(), nonce: 0, max_frame: HANDSHAKE_FRAME },
        SecureWriter { inner: w, state, nonce: 0 },
        session,
    ))
}

/// Dialler side: `-> e`, `<- e, ee, s, es`, `-> s, se`.
pub async fn initiate<R, W>(
    mut r: R,
    mut w: W,
    local_static: &[u8; 32],
) -> Result<(SecureReader<R>, SecureWriter<W>, Session), WireError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut hs = builder(local_static)?.build_initiator().map_err(noise)?;
    let mut buf = vec![0u8; MAX_NOISE];
    let n = hs.write_message(&[], &mut buf).map_err(noise)?;
    send_raw(&mut w, &buf[..n]).await?;
    let msg = recv_raw(&mut r).await?;
    hs.read_message(&msg, &mut buf).map_err(noise)?;
    let n = hs.write_message(&[], &mut buf).map_err(noise)?;
    send_raw(&mut w, &buf[..n]).await?;
    w.flush().await?;
    finish(hs, r, w)
}

/// Listener side of [`initiate`].
pub async fn respond<R, W>(
    mut r: R,
    mut w: W,
    local_static: &[u8; 32],
) -> Result<(SecureReader<R>, SecureWriter<W>, Session), WireError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut hs = builder(local_static)?.build_responder().map_err(noise)?;
    let mut buf = vec![0u8; MAX_NOISE];
    let msg = recv_raw(&mut r).await?;
    hs.read_message(&msg, &mut buf).map_err(noise)?;
    let n = hs.write_message(&[], &mut buf).map_err(noise)?;
    send_raw(&mut w, &buf[..n]).await?;
    w.flush().await?;
    let msg = recv_raw(&mut r).await?;
    hs.read_message(&msg, &mut buf).map_err(noise)?;
    finish(hs, r, w)
}

#[cfg(test)]
impl<W> SecureWriter<W> {
    /// A writer with this channel's keys and nonce position whose bytes land
    /// in a `Vec` instead (tests inspect and corrupt the ciphertext).
    pub(crate) fn tap(&self) -> SecureWriter<Vec<u8>> {
        SecureWriter { inner: Vec::new(), state: self.state.clone(), nonce: self.nonce }
    }
}

#[cfg(test)]
impl SecureWriter<Vec<u8>> {
    pub(crate) fn into_inner(self) -> Vec<u8> {
        self.inner
    }
}

#[cfg(test)]
impl<R> SecureReader<R> {
    pub(crate) fn reader_over<'a>(&self, bytes: &'a [u8]) -> SecureReader<&'a [u8]> {
        SecureReader { inner: bytes, state: self.state.clone(), nonce: self.nonce, max_frame: self.max_frame }
    }
}

impl<W: AsyncWrite + Unpin> SecureWriter<W> {
    pub async fn send<T: Serialize>(&mut self, msg: &T) -> Result<(), WireError> {
        let body = serde_json::to_vec(msg)?;
        if body.len() > MAX_FRAME {
            return Err(WireError::TooLarge(body.len()));
        }
        let mut plain = Vec::with_capacity(4 + body.len());
        plain.extend_from_slice(&(body.len() as u32).to_be_bytes());
        plain.extend_from_slice(&body);
        let mut ct = vec![0u8; MAX_NOISE];
        for chunk in plain.chunks(CHUNK) {
            let n = self.state.write_message(self.nonce, chunk, &mut ct).map_err(noise)?;
            self.nonce += 1;
            send_raw(&mut self.inner, &ct[..n]).await?;
        }
        self.inner.flush().await?;
        Ok(())
    }
}

impl<R: AsyncRead + Unpin> SecureReader<R> {
    /// Set the frame cap once the peer's role is known. While a frame
    /// arrives, a peer can make this reader hold at most this many bytes, so
    /// memory per connection stays bounded by role. It is never above
    /// [`MAX_FRAME`].
    pub fn set_max_frame(&mut self, bytes: usize) {
        self.max_frame = bytes.min(MAX_FRAME);
    }

    async fn next_chunk(&mut self) -> Result<Vec<u8>, WireError> {
        let ct = recv_raw(&mut self.inner).await?;
        let mut plain = vec![0u8; ct.len()];
        let n = self.state.read_message(self.nonce, &ct, &mut plain).map_err(noise)?;
        self.nonce += 1;
        plain.truncate(n);
        Ok(plain)
    }

    pub async fn recv<T: DeserializeOwned>(&mut self) -> Result<T, WireError> {
        let first = self.next_chunk().await?;
        let [a, b, c, d, ..] = first[..] else { return Err(WireError::Noise("short first chunk".into())) };
        let len = u32::from_be_bytes([a, b, c, d]) as usize;
        if len > self.max_frame {
            return Err(WireError::TooLarge(len));
        }
        // The buffer grows only as authenticated chunks arrive. It is never
        // preallocated from the length, which the peer chooses.
        let mut body = first[4..].to_vec();
        while body.len() < len {
            body.extend(self.next_chunk().await?);
            if body.len() > len {
                return Err(WireError::Noise("frame longer than declared".into()));
            }
        }
        if body.len() != len {
            return Err(WireError::Noise("frame length mismatch".into()));
        }
        Ok(serde_json::from_slice(&body)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; 32] {
        *hotpan_seal::Keypair::generate().kex_secret_bytes()
    }

    type Pair = (
        (
            SecureReader<tokio::io::ReadHalf<tokio::io::DuplexStream>>,
            SecureWriter<tokio::io::WriteHalf<tokio::io::DuplexStream>>,
            Session,
        ),
        (
            SecureReader<tokio::io::ReadHalf<tokio::io::DuplexStream>>,
            SecureWriter<tokio::io::WriteHalf<tokio::io::DuplexStream>>,
            Session,
        ),
    );

    async fn pair() -> Pair {
        let (a, b) = tokio::io::duplex(1 << 20);
        let (ar, aw) = tokio::io::split(a);
        let (br, bw) = tokio::io::split(b);
        let (ka, kb) = (key(), key());
        let (x, y) = tokio::join!(initiate(ar, aw, &ka), respond(br, bw, &kb));
        (x.unwrap(), y.unwrap())
    }

    #[tokio::test]
    async fn round_trip_small_and_multi_chunk() {
        let ((mut ar, mut aw, sa), (mut br, mut bw, sb)) = pair().await;
        assert_eq!(sa.handshake_hash, sb.handshake_hash);
        assert_ne!(sa.remote_static, sb.remote_static);
        aw.send(&"hello").await.unwrap();
        assert_eq!(br.recv::<String>().await.unwrap(), "hello");
        // Exactly at, just over, and well over one chunk.
        ar.set_max_frame(MAX_FRAME);
        for size in [CHUNK - 6, CHUNK - 5, CHUNK * 3 + 7, 1 << 20] {
            let big = "x".repeat(size);
            // Concurrently: a frame larger than the pipe buffer would
            // otherwise block the writer forever.
            let (sent, got) = tokio::join!(bw.send(&big), ar.recv::<String>());
            sent.unwrap();
            assert_eq!(got.unwrap().len(), size);
        }
    }

    #[tokio::test]
    async fn ciphertext_is_opaque_and_tamper_evident() {
        // Capture what a sender puts on the wire, using a Vec as the transport.
        let (ka2, kb2) = (key(), key());
        let (c, d) = tokio::io::duplex(1 << 20);
        let (cr, cw) = tokio::io::split(c);
        let (dr, dw) = tokio::io::split(d);
        let (x, y) = tokio::join!(initiate(cr, cw, &ka2), respond(dr, dw, &kb2));
        let (_cr, cw, _) = x.unwrap();
        let (dr, _dw, _) = y.unwrap();
        let mut tap = SecureWriter { inner: Vec::new(), state: cw.state.clone(), nonce: cw.nonce };
        tap.send(&"top-secret-task").await.unwrap();
        let wire = tap.inner.clone();
        assert!(!wire.windows(10).any(|w| w == b"top-secret"));

        // Unmodified bytes decrypt.
        let mut ok = SecureReader { inner: &wire[..], state: dr.state.clone(), nonce: 0, max_frame: MAX_FRAME };
        assert_eq!(ok.recv::<String>().await.unwrap(), "top-secret-task");
        // A flipped bit does not.
        let mut bad = wire.clone();
        *bad.last_mut().unwrap() ^= 1;
        let mut r = SecureReader { inner: &bad[..], state: dr.state.clone(), nonce: 0, max_frame: MAX_FRAME };
        assert!(matches!(r.recv::<String>().await, Err(WireError::Noise(_))));
        // Replaying it at a later position (wrong nonce) does not.
        let mut r = SecureReader { inner: &wire[..], state: dr.state.clone(), nonce: 1, max_frame: MAX_FRAME };
        assert!(matches!(r.recv::<String>().await, Err(WireError::Noise(_))));
    }

    #[tokio::test]
    async fn frame_cap_follows_role() {
        let big = "x".repeat(HANDSHAKE_FRAME + 1);
        // Before authentication the cap is small.
        let ((mut ar, _aw, _), (_br, mut bw, _)) = pair().await;
        let (sent, got) = tokio::join!(bw.send(&big), ar.recv::<String>());
        sent.unwrap();
        assert!(matches!(got, Err(WireError::TooLarge(_))));
        // Once the role allows it, the same frame is accepted.
        let ((mut ar, _aw, _), (_br, mut bw, _)) = pair().await;
        ar.set_max_frame(CLIENT_FRAME);
        let (sent, got) = tokio::join!(bw.send(&big), ar.recv::<String>());
        sent.unwrap();
        assert_eq!(got.unwrap().len(), big.len());
        // The cap can never be raised past the protocol maximum.
        ar.set_max_frame(usize::MAX);
        assert_eq!(ar.max_frame, MAX_FRAME);
    }

    #[tokio::test]
    async fn prologue_mismatch_fails_handshake() {
        let (a, b) = tokio::io::duplex(1 << 16);
        let (ar, aw) = tokio::io::split(a);
        let (mut br, mut bw) = tokio::io::split(b);
        let ka = key();
        let kb = key();
        let other = async move {
            let mut hs = Builder::new(NOISE_PARAMS.parse().unwrap())
                .prologue(b"hotpan/0")
                .unwrap()
                .local_private_key(&kb)
                .unwrap()
                .build_responder()
                .unwrap();
            let mut buf = vec![0u8; MAX_NOISE];
            let m = recv_raw(&mut br).await.unwrap();
            hs.read_message(&m, &mut buf).unwrap();
            let n = hs.write_message(&[], &mut buf).unwrap();
            send_raw(&mut bw, &buf[..n]).await.unwrap();
        };
        let (r, _) = tokio::join!(initiate(ar, aw, &ka), other);
        assert!(r.is_err());
    }
}
