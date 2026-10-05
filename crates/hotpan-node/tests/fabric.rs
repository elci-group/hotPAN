//! End-to-end over real TCP: an orchestrator, transient nodes dialling out,
//! and a client submitting work.

use hotpan_core::*;
use hotpan_heuristic::Protection;
use hotpan_node::*;
use hotpan_orchestrator::server::{Server, ServerConfig};
use hotpan_orchestrator::{ControlPlane, PlaneConfig};
use hotpan_probe::{template, Probe, ScriptedProbe};
use hotpan_sandbox::Policy;
use hotpan_seal::Keypair;
use hotpan_wire::FragmentState;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

struct Fabric {
    addr: String,
    server: Server,
    key: String,
    events: tempfile::TempDir,
}

async fn fabric(cfg: ServerConfig) -> Fabric {
    fabric_with(cfg, PlaneConfig::default()).await
}

async fn fabric_with(cfg: ServerConfig, base: PlaneConfig) -> Fabric {
    let events = tempfile::tempdir().unwrap();
    let plane_cfg = PlaneConfig { heartbeat_ms: 200, node_timeout_ms: 1_000, ..base };
    let plane = ControlPlane::new(Keypair::generate(), plane_cfg);
    let key = plane.public().signing;
    let cfg = ServerConfig { event_log: Some(events.path().join("events.jsonl")), ..cfg };
    let server = Server::new(plane, cfg).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(server.clone().serve(listener));
    Fabric { addr, server, key, events }
}

fn agent(f: &Fabric, label: &str, workroot: &std::path::Path, secret: Option<&str>) -> AgentConfig {
    AgentConfig {
        addr: f.addr.clone(),
        settings: NodeSettings {
            label: label.into(),
            policy: Policy {
                allowed_programs: BTreeSet::from(["/bin/sh".to_string()]),
                max: ResourceCeiling::default(),
                workroot: workroot.to_path_buf(),
            },
            max_leases: 2,
            protection: Protection::default(),
        },
        pin: Some(f.key.clone()),
        pairing_secret: secret.map(String::from),
    }
}

fn spawn_node(
    cfg: AgentConfig,
    class: DeviceClass,
    tweak: impl FnOnce(&mut CapabilityVector),
) -> (tokio::task::JoinHandle<Result<SessionEnd, AgentError>>, ScriptedProbe) {
    let mut v = template(class);
    tweak(&mut v);
    let probe = ScriptedProbe::new(class, v);
    let p: Arc<dyn Probe> = Arc::new(probe.clone());
    (tokio::spawn(async move { run_session(&cfg, p).await }), probe)
}

async fn wait_nodes(f: &Fabric, n: usize) {
    wait_nodes_paired(f, n, None).await
}

async fn wait_nodes_paired(f: &Fabric, n: usize, secret: Option<&str>) {
    let mut c = Client::connect(&f.addr, secret, Some(&f.key)).await.unwrap();
    for _ in 0..100 {
        if c.fleet().await.unwrap().len() == n {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("fleet never reached {n} nodes");
}

fn frag(id: &str, profile: WorkloadProfile, task: TaskSpec) -> FragmentSpec {
    FragmentSpec {
        id: id.into(),
        profile,
        requires: BTreeSet::new(),
        locality: None,
        privacy: Privacy::Anywhere,
        min_trust: TrustLevel::Unverified,
        ceiling: ResourceCeiling::default(),
        task,
    }
}

fn workspaces(dir: &std::path::Path) -> usize {
    std::fs::read_dir(dir).map(|r| r.count()).unwrap_or(0)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn job_runs_across_transient_nodes() {
    let f = fabric(ServerConfig::default()).await;
    let (wa, wb) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (_a, _) = spawn_node(agent(&f, "phone", wa.path(), None), DeviceClass::Phone, |v| {
        v.capabilities.insert(Capability::Camera);
        v.power = PowerState::battery(20.0, false);
        v.user_activity = UserActivity::Active;
    });
    let (_b, _) = spawn_node(agent(&f, "desk", wb.path(), None), DeviceClass::Desktop, |_| {});
    wait_nodes(&f, 2).await;

    let mut capture = frag(
        "capture",
        WorkloadProfile::SensorBound,
        TaskSpec::Exec {
            program: "/bin/sh".into(),
            args: vec!["-c".into(), "echo captured-in-$PWD | grep -c hotpan-lease".into()],
            stdin: None,
        },
    );
    capture.requires.insert(Capability::Camera);
    let mut fragments = vec![capture];
    for i in 0..4 {
        fragments.push(frag(
            &format!("map{i}"),
            WorkloadProfile::ParallelLowRelational,
            TaskSpec::Builtin(BuiltinTask::PrimeCount { upto: 10_000 * (i + 1) }),
        ));
    }
    let job = JobSpec { name: "e2e".into(), max_attempts: 3, fragments };

    let mut c = Client::connect(&f.addr, None, Some(&f.key)).await.unwrap();
    let id = c.submit(job).await.unwrap();
    let r = c.wait(id, Duration::from_secs(20)).await.unwrap();
    let fleet = c.fleet().await.unwrap();
    let label = |n: NodeId| fleet.iter().find(|e| e.node_id == n).unwrap().label.clone();

    let mut outputs = std::collections::BTreeMap::new();
    for fr in &r.fragments {
        match &fr.state {
            FragmentState::Done { node_id, result } => {
                outputs.insert(fr.id.clone(), (label(*node_id), result.stdout.trim().to_string()));
            }
            s => panic!("{} not done: {s:?}", fr.id),
        }
    }
    assert_eq!(outputs["capture"], ("phone".into(), "1".into()));
    // pi(10k), pi(20k), pi(30k), pi(40k) — all on the desktop: the active,
    // 20%-battery phone has no business doing parallel compute.
    for (i, expect) in ["1229", "2262", "3245", "4203"].iter().enumerate() {
        assert_eq!(outputs[&format!("map{i}")], ("desk".into(), expect.to_string()));
    }

    // Purges complete shortly after results return.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(workspaces(wa.path()) + workspaces(wb.path()), 0);
    let log = std::fs::read_to_string(f.events.path().join("events.jsonl")).unwrap();
    assert!(log.contains("\"phase\":\"dissolved\""));
    assert!(log.contains("\"event\":\"job_finished\""));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn node_vanishing_mid_execution_moves_the_work() {
    let f = fabric(ServerConfig::default()).await;
    let (wa, wb) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    // The strong node takes the job first...
    let (a, _) =
        spawn_node(agent(&f, "strong", wa.path(), None), DeviceClass::Desktop, |v| v.compute.logical_cpus = 64);
    wait_nodes(&f, 1).await;
    let mut c = Client::connect(&f.addr, None, Some(&f.key)).await.unwrap();
    let id = c
        .submit(JobSpec {
            name: "long".into(),
            max_attempts: 3,
            fragments: vec![frag(
                "f",
                WorkloadProfile::ComputeBound,
                TaskSpec::Builtin(BuiltinTask::Sleep { ms: 1_500 }),
            )],
        })
        .await
        .unwrap();
    for _ in 0..100 {
        if matches!(c.status(id).await.unwrap().fragments[0].state, FragmentState::Leased { .. }) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // ...then a phone appears, and the strong node drops off the network.
    let (_b, _) = spawn_node(agent(&f, "phone", wb.path(), None), DeviceClass::Phone, |v| {
        v.power = PowerState::battery(90.0, true)
    });
    wait_nodes(&f, 2).await;
    a.abort();

    let r = c.wait(id, Duration::from_secs(20)).await.unwrap();
    let fleet = c.fleet().await.unwrap();
    match &r.fragments[0].state {
        FragmentState::Done { node_id, result } => {
            assert_eq!(fleet.iter().find(|e| e.node_id == *node_id).unwrap().label, "phone");
            assert_eq!(result.stdout, "slept 1500ms");
        }
        s => panic!("{s:?}"),
    }
    assert_eq!(r.fragments[0].attempts, 2);
    // The vanished node's orphaned workspace is purged once its worker stops.
    tokio::time::sleep(Duration::from_millis(1_000)).await;
    assert_eq!(workspaces(wa.path()), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn control_plane_shutdown_dissolves_node_authority() {
    let f = fabric(ServerConfig::default()).await;
    let w = tempfile::tempdir().unwrap();
    let (a, _) = spawn_node(agent(&f, "n", w.path(), None), DeviceClass::Desktop, |_| {});
    wait_nodes(&f, 1).await;
    let mut c = Client::connect(&f.addr, None, Some(&f.key)).await.unwrap();
    c.submit(JobSpec {
        name: "x".into(),
        max_attempts: 1,
        fragments: vec![frag(
            "f",
            WorkloadProfile::ComputeBound,
            TaskSpec::Exec {
                program: "/bin/sh".into(),
                args: vec!["-c".into(), "echo data > scratch; sleep 30".into()],
                stdin: None,
            },
        )],
    })
    .await
    .unwrap();
    for _ in 0..100 {
        if workspaces(w.path()) == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(workspaces(w.path()), 1);
    f.server.shutdown();
    let end = tokio::time::timeout(Duration::from_secs(10), a).await.unwrap().unwrap().unwrap();
    assert_eq!(end.leases_completed, 0);
    // The 30s sleeper was killed and its workspace purged, well before 30s.
    assert_eq!(workspaces(w.path()), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pairing_and_pinning() {
    let f = fabric(ServerConfig {
        pairing_secret: Some("fabric-secret".into()),
        require_pairing: true,
        ..Default::default()
    })
    .await;
    let w = tempfile::tempdir().unwrap();
    let probe: Arc<dyn Probe> = Arc::new(ScriptedProbe::new(DeviceClass::Phone, template(DeviceClass::Phone)));

    let r = run_session(&agent(&f, "n", w.path(), Some("wrong")), probe.clone()).await;
    assert!(matches!(r, Err(AgentError::Refused(ref m)) if m.contains("pairing")), "{r:?}");

    let mut bad_pin = agent(&f, "n", w.path(), Some("fabric-secret"));
    bad_pin.pin = Some(Keypair::generate().public().signing);
    assert!(matches!(run_session(&bad_pin, probe.clone()).await, Err(AgentError::PinMismatch { .. })));

    let (_h, _) = spawn_node(agent(&f, "n", w.path(), Some("fabric-secret")), DeviceClass::Phone, |_| {});
    let mut c = Client::connect(&f.addr, Some("fabric-secret"), Some(&f.key)).await.unwrap();
    for _ in 0..100 {
        if let Some(e) = c.fleet().await.unwrap().first() {
            assert_eq!(e.trust, TrustLevel::Paired);
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let mut unpaired = Client::connect(&f.addr, None, Some(&f.key)).await.unwrap();
    assert!(matches!(unpaired.fleet().await, Err(ClientError::Remote(m)) if m.contains("pairing")));
}

/// A TCP relay that records every byte in both directions.
async fn wiretap(upstream: String) -> (String, Arc<std::sync::Mutex<Vec<u8>>>) {
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let rec = seen.clone();
    tokio::spawn(async move {
        loop {
            let (down, _) = listener.accept().await.unwrap();
            let up = tokio::net::TcpStream::connect(&upstream).await.unwrap();
            let (dr, dw) = down.into_split();
            let (ur, uw) = up.into_split();
            for (mut from, mut to, rec) in [
                (
                    Box::new(dr) as Box<dyn tokio::io::AsyncRead + Unpin + Send>,
                    Box::new(uw) as Box<dyn tokio::io::AsyncWrite + Unpin + Send>,
                    rec.clone(),
                ),
                (Box::new(ur), Box::new(dw), rec.clone()),
            ] {
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = [0u8; 4096];
                    while let Ok(n) = from.read(&mut buf).await {
                        if n == 0 || to.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                        rec.lock().unwrap().extend_from_slice(&buf[..n]);
                    }
                });
            }
        }
    });
    (addr, seen)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn passive_observer_sees_no_plaintext() {
    let f = fabric(ServerConfig {
        pairing_secret: Some("fabric-secret".into()),
        require_pairing: true,
        ..Default::default()
    })
    .await;
    let (tap, seen) = wiretap(f.addr.clone()).await;
    let w = tempfile::tempdir().unwrap();
    let mut cfg = agent(&f, "observable-label", w.path(), Some("fabric-secret"));
    cfg.addr = tap.clone();
    let (_n, _) = spawn_node(cfg, DeviceClass::Phone, |v| {
        v.capabilities.insert(Capability::LocalData("medical-records".into()));
    });
    wait_nodes_paired(&f, 1, Some("fabric-secret")).await;
    let mut c = Client::connect(&tap, Some("fabric-secret"), Some(&f.key)).await.unwrap();
    let id = c
        .submit(JobSpec {
            name: "confidential-job-name".into(),
            max_attempts: 1,
            fragments: vec![frag(
                "f",
                WorkloadProfile::SensorBound,
                TaskSpec::Builtin(BuiltinTask::Echo { payload: "very-secret-payload".into() }),
            )],
        })
        .await
        .unwrap();
    let r = c.wait(id, Duration::from_secs(10)).await.unwrap();
    assert!(
        matches!(&r.fragments[0].state, FragmentState::Done { result, .. } if result.stdout == "very-secret-payload")
    );
    tokio::time::sleep(Duration::from_millis(300)).await;

    let wire = seen.lock().unwrap().clone();
    assert!(wire.len() > 1000, "tap saw only {} bytes", wire.len());
    for needle in [
        "very-secret-payload",
        "confidential-job-name",
        "observable-label",
        "medical-records",
        "heartbeat",
        "lease_id",
        "signing",
        "provision",
        "battery",
        &f.key,
    ] {
        assert!(!wire.windows(needle.len()).any(|w| w == needle.as_bytes()), "`{needle}` visible on the wire");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn impostor_with_the_right_public_key_is_rejected() {
    // The impostor knows the real orchestrator's *public* keys (they are not
    // secret) and so passes the pin check, but cannot sign this channel.
    let real = Keypair::generate();
    let real_pub = real.public();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let pubkeys = real_pub.clone();
    tokio::spawn(async move {
        let impostor = Keypair::generate();
        loop {
            let (s, _) = listener.accept().await.unwrap();
            let (rd, wr) = s.into_split();
            let Ok((_rd, mut wr, session)) = hotpan_wire::respond(rd, wr, &impostor.kex_secret_bytes()).await else {
                continue;
            };
            let _ = wr
                .send(&hotpan_wire::Welcome {
                    protocol: hotpan_wire::PROTOCOL_VERSION,
                    orchestrator: pubkeys.clone(),
                    // Its own signature over the binding: wrong key.
                    proof: hotpan_seal::welcome_proof(&impostor, &session.binding()),
                    heartbeat_ms: 1000,
                })
                .await;
        }
    });
    let w = tempfile::tempdir().unwrap();
    let cfg = AgentConfig {
        addr: addr.clone(),
        settings: agent_settings(w.path()),
        pin: Some(real_pub.signing.clone()),
        pairing_secret: Some("fabric-secret".into()),
    };
    let probe: Arc<dyn Probe> = Arc::new(ScriptedProbe::new(DeviceClass::Phone, template(DeviceClass::Phone)));
    let r = run_session(&cfg, probe).await;
    assert!(matches!(r, Err(AgentError::ChannelBinding)), "{r:?}");
    let c = Client::connect(&addr, Some("fabric-secret"), Some(&real_pub.signing)).await;
    assert!(matches!(c, Err(ClientError::ChannelBinding)));
}

fn agent_settings(workroot: &std::path::Path) -> NodeSettings {
    NodeSettings {
        label: "n".into(),
        policy: Policy {
            allowed_programs: BTreeSet::new(),
            max: ResourceCeiling::default(),
            workroot: workroot.to_path_buf(),
        },
        max_leases: 1,
        protection: Protection::default(),
    }
}

// ------------------------------------------------------------ Phase 1 bounds

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connection_flood_and_slowloris_are_bounded() {
    use hotpan_orchestrator::server::ServerLimits;
    let limits = ServerLimits {
        max_connections: 16,
        max_handshakes: 4,
        handshake_timeout: Duration::from_millis(300),
        ..Default::default()
    };
    let f = fabric(ServerConfig { limits, ..Default::default() }).await;
    // 40 idle sockets that never speak: a slowloris flood.
    let mut idle = Vec::new();
    for _ in 0..40 {
        idle.push(tokio::net::TcpStream::connect(&f.addr).await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let s = f.server.stats();
    assert!(s.connections_live <= 16, "{s:?}");
    assert!(s.connections_refused >= 24, "{s:?}");
    // Handshake deadlines free the slots; a real node then joins.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(f.server.stats().connections_live, 0, "{:?}", f.server.stats());
    assert!(f.server.stats().handshakes_failed >= 4);
    let w = tempfile::tempdir().unwrap();
    let (_n, _) = spawn_node(agent(&f, "real", w.path(), None), DeviceClass::Desktop, |_| {});
    wait_nodes(&f, 1).await;
    drop(idle);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn node_dissolves_when_control_plane_goes_silent() {
    // A control plane that completes the handshake, registers the node, then
    // never speaks again (a half-open connection looks exactly like this).
    let orch = Keypair::generate();
    let pin = orch.public().signing;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        let (s, _) = listener.accept().await.unwrap();
        let (rd, wr) = s.into_split();
        let (mut rd, mut wr, session) = hotpan_wire::respond(rd, wr, &orch.kex_secret_bytes()).await.unwrap();
        wr.send(&hotpan_wire::Welcome {
            protocol: hotpan_wire::PROTOCOL_VERSION,
            orchestrator: orch.public(),
            proof: hotpan_seal::welcome_proof(&orch, &session.binding()),
            heartbeat_ms: 100,
        })
        .await
        .unwrap();
        let hello: hotpan_wire::Hello = rd.recv().await.unwrap();
        let hotpan_wire::Hello::Node { advertisement, .. } = hello else { panic!() };
        wr.send(&hotpan_wire::OrchMsg::Registered { node_id: advertisement.node_id, trust: TrustLevel::Unverified })
            .await
            .unwrap();
        // Swallow heartbeats forever, never reply.
        while rd.recv::<hotpan_wire::NodeMsg>().await.is_ok() {}
    });
    let w = tempfile::tempdir().unwrap();
    let cfg = AgentConfig { addr, settings: agent_settings(w.path()), pin: Some(pin), pairing_secret: None };
    let probe: Arc<dyn Probe> = Arc::new(ScriptedProbe::new(DeviceClass::Phone, template(DeviceClass::Phone)));
    let t0 = std::time::Instant::now();
    let r = tokio::time::timeout(Duration::from_secs(10), run_session(&cfg, probe)).await.unwrap();
    assert!(matches!(r, Err(AgentError::Silent(_))), "{r:?}");
    assert!(t0.elapsed() < Duration::from_secs(5));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn quotas_follow_client_identity_over_the_wire() {
    let f = fabric_with(ServerConfig::default(), PlaneConfig { max_jobs_per_client: 1, ..Default::default() }).await;
    let me = Keypair::generate();
    let job = || JobSpec {
        name: "q".into(),
        max_attempts: 1,
        fragments: vec![frag(
            "f",
            WorkloadProfile::ComputeBound,
            TaskSpec::Builtin(BuiltinTask::Echo { payload: "x".into() }),
        )],
    };
    let mut c = Client::connect_as(&f.addr, &me, None, Some(&f.key)).await.unwrap();
    c.submit(job()).await.unwrap();
    // Same identity on a new connection: still over quota (no fleet to finish it).
    let mut c2 = Client::connect_as(&f.addr, &me, None, Some(&f.key)).await.unwrap();
    assert!(matches!(c2.submit(job()).await, Err(ClientError::Remote(m)) if m.contains("quota")));
    // A different identity has its own quota.
    let mut other = Client::connect(&f.addr, None, Some(&f.key)).await.unwrap();
    other.submit(job()).await.unwrap();
}
