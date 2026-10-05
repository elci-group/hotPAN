//! hotPAN wire protocol.
//!
//! Every connection is *outbound from the node*: a phone never needs an
//! inbound public port. A connection starts with a Noise_XX handshake
//! ([`secure`]); everything after it is encrypted and authenticated. Inside
//! the channel the control plane sends [`Welcome`], proving it is the pinned
//! orchestrator by signing the handshake hash, and the peer answers with a
//! [`Hello`] that signs the same hash with its session key (and, optionally,
//! proves knowledge of the fabric pairing secret, also bound to the hash).
//!
//! [`read_frame`]/[`write_frame`] are the plaintext length-prefixed JSON
//! codec, used only beneath the secure layer and in tests.

#![forbid(unsafe_code)]
// No panics reachable from peer input (DIRECTIVE P1.6): fallible paths
// return errors; the few infallible serializations carry a local allow.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use hotpan_core::*;
use hotpan_sandbox::{Outcome, PurgeReceipt};
use hotpan_seal::{Attestation, Envelope, PublicKeys, SignedLease};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[cfg(test)]
mod props;
pub mod secure;
pub use secure::{initiate, respond, SecureReader, SecureWriter, Session, CLIENT_FRAME, HANDSHAKE_FRAME};

pub const PROTOCOL_VERSION: u32 = 3;
pub const MAX_FRAME: usize = 8 << 20;
pub const DEFAULT_PORT: u16 = 7450;

#[derive(Debug, thiserror::Error)]
pub enum WireError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("frame of {0} bytes exceeds limit")]
    TooLarge(usize),
    #[error("decode: {0}")]
    Decode(#[from] serde_json::Error),
    #[error("connection closed")]
    Closed,
    #[error("secure channel: {0}")]
    Noise(String),
}

pub async fn write_frame<W: AsyncWrite + Unpin, T: Serialize>(w: &mut W, msg: &T) -> Result<(), WireError> {
    let body = serde_json::to_vec(msg)?;
    if body.len() > MAX_FRAME {
        return Err(WireError::TooLarge(body.len()));
    }
    w.write_all(&(body.len() as u32).to_be_bytes()).await?;
    w.write_all(&body).await?;
    w.flush().await?;
    Ok(())
}

pub async fn read_frame<R: AsyncRead + Unpin, T: DeserializeOwned>(r: &mut R) -> Result<T, WireError> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Err(WireError::Closed),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(WireError::TooLarge(len));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    Ok(serde_json::from_slice(&body)?)
}

/// First frame inside the secure channel, sent by the control plane.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Welcome {
    pub protocol: u32,
    pub orchestrator: PublicKeys,
    /// Orchestrator signature over the channel binding (handshake hash).
    pub proof: String,
    pub heartbeat_ms: u64,
}

/// The peer's reply to [`Welcome`].
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "role")]
pub enum Hello {
    Node {
        protocol: u32,
        advertisement: Box<Advertisement>,
        /// Signature over the channel binding with the advertised session key.
        proof: String,
        /// Keyed proof of the pairing secret, if the node has one.
        pairing: Option<String>,
    },
    Client {
        protocol: u32,
        /// Clients identify with a throwaway session key, too.
        signing_key: String,
        proof: String,
        pairing: Option<String>,
    },
}

/// What a node hands back inside the sealed result envelope.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ResultPayload {
    pub lease_id: LeaseId,
    pub fragment_id: String,
    pub outcome: Outcome,
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
    pub wall_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum NodeMsg {
    Heartbeat {
        vector: Box<CapabilityVector>,
    },
    Accepted {
        lease_id: LeaseId,
    },
    Rejected {
        lease_id: LeaseId,
        reason: String,
    },
    /// Execution began.
    Executing {
        lease_id: LeaseId,
    },
    Result {
        lease_id: LeaseId,
        envelope: Envelope,
        attestation: Attestation,
    },
    Purged {
        receipt: PurgeReceipt,
    },
    /// The node is leaving the fabric on purpose.
    Withdraw,
    /// Reply to [`OrchMsg::Ping`], echoing its nonce.
    Pong {
        nonce: u64,
    },
}

// Messages are built once and serialized immediately; boxing buys nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum OrchMsg {
    Registered {
        node_id: NodeId,
        trust: TrustLevel,
    },
    Provision {
        lease: SignedLease,
        task: Envelope,
    },
    Revoke {
        lease_id: LeaseId,
        reason: RevokeReason,
    },
    Purge {
        lease_id: LeaseId,
    },
    Refused {
        reason: String,
    },
    /// Keepalive. A node that hears nothing from the control plane for
    /// several heartbeat intervals treats it as gone and dissolves everything.
    Ping {
        nonce: u64,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum ClientMsg {
    Submit { job: JobSpec },
    Status { job_id: JobId },
    Fleet,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum ClientReply {
    Submitted { job_id: JobId },
    Job { report: JobReport },
    Fleet { nodes: Vec<FleetEntry> },
    Error { message: String },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum FragmentState {
    Pending,
    Leased { lease_id: LeaseId, node_id: NodeId },
    Done { node_id: NodeId, result: ResultPayload },
    Failed { reason: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FragmentReport {
    pub id: String,
    pub attempts: u32,
    pub state: FragmentState,
    /// Why the fragment could not be placed on the last scheduling pass.
    pub blocked_by: Vec<hotpan_heuristic::Gate>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JobReport {
    pub job_id: JobId,
    pub name: String,
    pub finished: bool,
    pub fragments: Vec<FragmentReport>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FleetEntry {
    pub node_id: NodeId,
    pub label: String,
    pub device_class: DeviceClass,
    pub trust: TrustLevel,
    pub active_leases: u32,
    pub max_leases: u32,
    pub vector: CapabilityVector,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn frames_round_trip_and_limits() {
        let (mut a, mut b) = tokio::io::duplex(1 << 16);
        write_frame(&mut a, &ClientMsg::Fleet).await.unwrap();
        let m: ClientMsg = read_frame(&mut b).await.unwrap();
        assert!(matches!(m, ClientMsg::Fleet));

        let mut buf = Vec::new();
        buf.extend_from_slice(&((MAX_FRAME as u32) + 1).to_be_bytes());
        let mut r = &buf[..];
        assert!(matches!(read_frame::<_, ClientMsg>(&mut r).await, Err(WireError::TooLarge(_))));

        drop(a);
        assert!(matches!(read_frame::<_, ClientMsg>(&mut b).await, Err(WireError::Closed)));
    }
}
