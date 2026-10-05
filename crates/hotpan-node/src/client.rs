use hotpan_core::*;
use hotpan_seal::{hello_proof, pairing_proof, verify_welcome_proof, Keypair};
use hotpan_wire::*;
use std::time::{Duration, Instant};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error(transparent)]
    Wire(#[from] WireError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("orchestrator key {0} does not match pinned key")]
    PinMismatch(String),
    #[error("orchestrator: {0}")]
    Remote(String),
    #[error("unexpected reply")]
    Unexpected,
    #[error("timed out waiting for job")]
    Timeout,
    #[error("orchestrator did not prove it terminates this channel")]
    ChannelBinding,
}

/// A submitter's connection to the control plane.
pub struct Client {
    rd: SecureReader<OwnedReadHalf>,
    wr: SecureWriter<OwnedWriteHalf>,
}

impl Client {
    /// Connect with a throwaway identity (quotas apply to it alone).
    pub async fn connect(addr: &str, pairing_secret: Option<&str>, pin: Option<&str>) -> Result<Self, ClientError> {
        Self::connect_as(addr, &Keypair::generate(), pairing_secret, pin).await
    }

    /// Connect as a persistent client identity: the control plane keys
    /// per-client quotas to `keys`' signing key.
    pub async fn connect_as(
        addr: &str,
        keys: &Keypair,
        pairing_secret: Option<&str>,
        pin: Option<&str>,
    ) -> Result<Self, ClientError> {
        let s = TcpStream::connect(addr).await?;
        let (rd, wr) = s.into_split();
        let (mut rd, mut wr, session) = initiate(rd, wr, &keys.kex_secret_bytes()).await?;
        let binding = session.binding();
        let welcome: Welcome = rd.recv().await?;
        if let Some(pin) = pin {
            if pin != welcome.orchestrator.signing {
                return Err(ClientError::PinMismatch(welcome.orchestrator.signing));
            }
        }
        if verify_welcome_proof(&welcome.orchestrator.signing, &binding, &welcome.proof).is_err()
            || welcome.orchestrator.kex != session.remote_static_hex()
        {
            return Err(ClientError::ChannelBinding);
        }
        let signing_key = keys.public().signing;
        let hello = Hello::Client {
            protocol: PROTOCOL_VERSION,
            proof: hello_proof(keys, &binding),
            pairing: pairing_secret.map(|s| pairing_proof(s, &binding, &signing_key)),
            signing_key,
        };
        wr.send(&hello).await?;
        // Job reports carry results, and they come from the pinned orchestrator.
        rd.set_max_frame(MAX_FRAME);
        Ok(Self { rd, wr })
    }

    pub async fn request(&mut self, msg: &ClientMsg) -> Result<ClientReply, ClientError> {
        self.wr.send(msg).await?;
        match self.rd.recv().await? {
            ClientReply::Error { message } => Err(ClientError::Remote(message)),
            r => Ok(r),
        }
    }

    pub async fn submit(&mut self, job: JobSpec) -> Result<JobId, ClientError> {
        match self.request(&ClientMsg::Submit { job }).await? {
            ClientReply::Submitted { job_id } => Ok(job_id),
            _ => Err(ClientError::Unexpected),
        }
    }

    pub async fn status(&mut self, job_id: JobId) -> Result<JobReport, ClientError> {
        match self.request(&ClientMsg::Status { job_id }).await? {
            ClientReply::Job { report } => Ok(report),
            _ => Err(ClientError::Unexpected),
        }
    }

    pub async fn fleet(&mut self) -> Result<Vec<FleetEntry>, ClientError> {
        match self.request(&ClientMsg::Fleet).await? {
            ClientReply::Fleet { nodes } => Ok(nodes),
            _ => Err(ClientError::Unexpected),
        }
    }

    pub async fn wait(&mut self, job_id: JobId, timeout: Duration) -> Result<JobReport, ClientError> {
        let deadline = Instant::now() + timeout;
        loop {
            let r = self.status(job_id).await?;
            if r.finished {
                return Ok(r);
            }
            if Instant::now() >= deadline {
                return Err(ClientError::Timeout);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}
