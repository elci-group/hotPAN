use super::*;
use hotpan_core::{BuiltinTask, LeaseId};
use std::sync::atomic::{AtomicBool, Ordering};

fn policy(root: &std::path::Path) -> Policy {
    Policy {
        allowed_programs: ["/bin/sh", "/bin/echo", "/bin/cat"].into_iter().map(String::from).collect(),
        max: ResourceCeiling::default(),
        workroot: root.to_path_buf(),
    }
}

fn never() -> Option<String> {
    None
}

fn sh(script: &str) -> TaskSpec {
    TaskSpec::Exec { program: "/bin/sh".into(), args: vec!["-c".into(), script.into()], stdin: None }
}

fn sh_scope() -> Vec<Scope> {
    vec![Scope::Exec("/bin/sh".into())]
}

#[test]
fn builtins_compute_correctly() {
    let d = tempfile::tempdir().unwrap();
    let p = policy(d.path());
    let ws = Workspace::create(d.path(), LeaseId::random()).unwrap();
    let c = ResourceCeiling::default();
    let r = execute(
        &p,
        &ws,
        &TaskSpec::Builtin(BuiltinTask::PrimeCount { upto: 1_000_000 }),
        &c,
        &[Scope::Builtin("prime_count".into())],
        &never,
    );
    assert_eq!(r.outcome, Outcome::Completed { exit_code: 0 });
    assert_eq!(r.stdout, "78498");
    for (n, expect) in [(0, "0"), (2, "1"), (10, "4"), (100, "25"), (65_537, "6543")] {
        let r = execute(
            &p,
            &ws,
            &TaskSpec::Builtin(BuiltinTask::PrimeCount { upto: n }),
            &c,
            &[Scope::Builtin("prime_count".into())],
            &never,
        );
        assert_eq!(r.stdout, expect, "pi({n})");
    }
    let r = execute(
        &p,
        &ws,
        &TaskSpec::Builtin(BuiltinTask::Blake3 { data: "abc".into() }),
        &c,
        &[Scope::Builtin("blake3".into())],
        &never,
    );
    assert_eq!(r.stdout, blake3::hash(b"abc").to_hex().to_string());
}

#[test]
fn exec_runs_scrubbed_in_workspace() {
    let d = tempfile::tempdir().unwrap();
    let p = policy(d.path());
    let ws = Workspace::create(d.path(), LeaseId::random()).unwrap();
    std::env::set_var("HOTPAN_TEST_SECRET", "leak");
    let r = execute(
        &p,
        &ws,
        &sh("pwd; echo ${HOTPAN_TEST_SECRET:-clean}; echo err >&2; exit 3"),
        &ResourceCeiling::default(),
        &sh_scope(),
        &never,
    );
    assert_eq!(r.outcome, Outcome::Completed { exit_code: 3 });
    let lines: Vec<&str> = r.stdout.lines().collect();
    assert_eq!(std::path::Path::new(lines[0]).canonicalize().unwrap(), ws.path().canonicalize().unwrap());
    assert_eq!(lines[1], "clean");
    assert_eq!(r.stderr.trim(), "err");

    let cat = TaskSpec::Exec { program: "/bin/cat".into(), args: vec![], stdin: Some("piped in".into()) };
    let r = execute(&p, &ws, &cat, &ResourceCeiling::default(), &[Scope::Exec("/bin/cat".into())], &never);
    assert_eq!(r.stdout, "piped in");
}

#[test]
fn authority_requires_both_lease_scope_and_local_allowlist() {
    let d = tempfile::tempdir().unwrap();
    let p = policy(d.path());
    let ws = Workspace::create(d.path(), LeaseId::random()).unwrap();
    let c = ResourceCeiling::default();
    // Allowed locally, not granted by lease.
    let r = execute(&p, &ws, &sh("true"), &c, &[Scope::Exec("/bin/echo".into())], &never);
    assert!(matches!(r.outcome, Outcome::Rejected(_)));
    // Granted by lease, not allowed locally.
    let t = TaskSpec::Exec { program: "/usr/bin/env".into(), args: vec![], stdin: None };
    let r = execute(&p, &ws, &t, &c, &[Scope::Exec("/usr/bin/env".into())], &never);
    assert!(matches!(r.outcome, Outcome::Rejected(ref m) if m.contains("allowlist")));
    // Relative program names are never resolved.
    let t = TaskSpec::Exec { program: "sh".into(), args: vec![], stdin: None };
    let r = execute(&p, &ws, &t, &c, &[Scope::Exec("sh".into())], &never);
    assert!(matches!(r.outcome, Outcome::Rejected(_)));
    // Ceiling above node policy.
    let big = ResourceCeiling { memory_mb: 1 << 30, ..c };
    let r = execute(&p, &ws, &sh("true"), &big, &sh_scope(), &never);
    assert!(matches!(r.outcome, Outcome::Rejected(_)));
}

#[test]
fn wall_clock_and_output_ceilings() {
    let d = tempfile::tempdir().unwrap();
    let p = policy(d.path());
    let ws = Workspace::create(d.path(), LeaseId::random()).unwrap();
    let c = ResourceCeiling { wall_ms: 300, ..Default::default() };
    let t0 = std::time::Instant::now();
    // The background sleep must die with the group, or reading stdout would hang.
    let r = execute(&p, &ws, &sh("sleep 30 & sleep 30"), &c, &sh_scope(), &never);
    assert_eq!(r.outcome, Outcome::TimedOut);
    assert!(t0.elapsed().as_secs() < 5);

    let c = ResourceCeiling { output_bytes: 10, ..Default::default() };
    let r = execute(&p, &ws, &sh("yes | head -c 100000"), &c, &sh_scope(), &never);
    assert_eq!(r.outcome, Outcome::Completed { exit_code: 0 });
    assert_eq!(r.stdout.len(), 10);
    assert!(r.truncated);
}

#[test]
fn cpu_ceiling_kills_spinners() {
    let d = tempfile::tempdir().unwrap();
    let p = policy(d.path());
    let ws = Workspace::create(d.path(), LeaseId::random()).unwrap();
    let c = ResourceCeiling { cpu_ms: 1000, wall_ms: 20_000, ..Default::default() };
    let r = execute(&p, &ws, &sh("while :; do :; done"), &c, &sh_scope(), &never);
    assert!(matches!(r.outcome, Outcome::CeilingExceeded(_) | Outcome::Failed(_)), "{:?}", r.outcome);
    assert!(r.wall_ms < 10_000);
}

#[test]
fn guard_preempts_exec_and_builtins() {
    let d = tempfile::tempdir().unwrap();
    let p = policy(d.path());
    let ws = Workspace::create(d.path(), LeaseId::random()).unwrap();
    let flag = AtomicBool::new(false);
    let guard = || flag.load(Ordering::SeqCst).then(|| "battery fell below floor".to_string());
    std::thread::scope(|s| {
        s.spawn(|| {
            std::thread::sleep(std::time::Duration::from_millis(150));
            flag.store(true, Ordering::SeqCst);
        });
        let r = execute(&p, &ws, &sh("sleep 30"), &ResourceCeiling::default(), &sh_scope(), &guard);
        assert_eq!(r.outcome, Outcome::Preempted("battery fell below floor".into()));
    });
    let r = execute(
        &p,
        &ws,
        &TaskSpec::Builtin(BuiltinTask::Sleep { ms: 10_000 }),
        &ResourceCeiling::default(),
        &[Scope::Builtin("sleep".into())],
        &guard,
    );
    assert!(matches!(r.outcome, Outcome::Preempted(_)));
}

#[test]
fn purge_removes_everything_even_readonly() {
    let d = tempfile::tempdir().unwrap();
    let p = policy(d.path());
    let ws = Workspace::create(d.path(), LeaseId::random()).unwrap();
    let dir = ws.path().to_path_buf();
    let r = execute(
        &p,
        &ws,
        &sh("mkdir -p a/b && echo hi > a/b/f && echo xx > g && chmod -R a-w a"),
        &ResourceCeiling::default(),
        &sh_scope(),
        &never,
    );
    assert!(r.outcome.succeeded(), "{r:?}");
    let receipt = ws.purge().unwrap();
    assert_eq!(receipt.files_removed, 2);
    assert_eq!(receipt.bytes_removed, 6);
    assert!(!dir.exists());

    // Drop is a backstop.
    let ws = Workspace::create(d.path(), LeaseId::random()).unwrap();
    let dir = ws.path().to_path_buf();
    drop(ws);
    assert!(!dir.exists());

    // Stale workspaces from a crashed session are wiped.
    std::fs::create_dir_all(d.path().join("hotpan-lease-stale/x")).unwrap();
    std::fs::create_dir_all(d.path().join("unrelated")).unwrap();
    assert_eq!(purge_stale(d.path()), 1);
    assert!(d.path().join("unrelated").exists());
}
