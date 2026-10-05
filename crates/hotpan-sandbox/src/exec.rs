use crate::{ExecReport, Guard, Outcome, Workspace};
use hotpan_core::ResourceCeiling;
use std::io::{Read, Write};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

// glibc types the resource argument specially; bionic (Android) and musl use c_int.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
type Resource = libc::__rlimit_resource_t;
#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
type Resource = libc::c_int;

fn set_limit(resource: Resource, value: u64) -> std::io::Result<()> {
    let lim = libc::rlimit { rlim_cur: value as libc::rlim_t, rlim_max: value as libc::rlim_t };
    // SAFETY: setrlimit is async-signal-safe and `lim` is a valid pointer.
    if unsafe { libc::setrlimit(resource, &lim) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Read up to `cap` bytes, then keep draining (so the child never blocks on
/// a full pipe) while discarding the excess.
fn capped_reader<R: Read + Send + 'static>(mut r: R, cap: usize) -> std::thread::JoinHandle<(Vec<u8>, bool)> {
    std::thread::spawn(move || {
        let mut kept = Vec::new();
        let mut truncated = false;
        let mut buf = [0u8; 8192];
        loop {
            match r.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let room = cap.saturating_sub(kept.len());
                    kept.extend_from_slice(&buf[..n.min(room)]);
                    if n > room {
                        truncated = true;
                    }
                }
            }
        }
        (kept, truncated)
    })
}

fn kill_group(pid: u32) {
    // SAFETY: plain syscall; negative pid targets the child's process group,
    // which it leads because it called setsid().
    unsafe {
        libc::kill(-(pid as libc::pid_t), libc::SIGKILL);
    }
}

pub(crate) fn run(
    program: &str,
    args: &[String],
    stdin: Option<&str>,
    ws: &Workspace,
    ceiling: &ResourceCeiling,
    guard: Guard<'_>,
    started: Instant,
) -> ExecReport {
    let deadline = started + Duration::from_millis(ceiling.wall_ms);
    let program_dir = std::path::Path::new(program).parent().map(|p| p.display().to_string()).unwrap_or_default();
    let cpu_secs = ceiling.cpu_ms.div_ceil(1000).max(1);
    let mem_bytes = ceiling.memory_mb.saturating_mul(1 << 20);
    // Files written into the workspace are bounded too.
    let fsize = ceiling.output_bytes.saturating_mul(4).max(1 << 20);

    let mut cmd = Command::new(program);
    cmd.args(args)
        .env_clear()
        .env("PATH", format!("{program_dir}:/usr/bin:/bin"))
        .env("HOME", ws.path())
        .env("TMPDIR", ws.path())
        .env("HOTPAN_LEASE", ws.lease().to_string())
        .current_dir(ws.path())
        .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: the closure only makes async-signal-safe syscalls.
    unsafe {
        cmd.pre_exec(move || {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            set_limit(libc::RLIMIT_CPU, cpu_secs)?;
            set_limit(libc::RLIMIT_AS, mem_bytes)?;
            set_limit(libc::RLIMIT_FSIZE, fsize)?;
            set_limit(libc::RLIMIT_CORE, 0)?;
            Ok(())
        });
    }

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return ExecReport::bare(Outcome::Failed(format!("spawn {program}: {e}")), started),
    };
    let pid = child.id();
    let out = capped_reader(child.stdout.take().expect("piped"), ceiling.output_bytes as usize);
    let err = capped_reader(child.stderr.take().expect("piped"), (ceiling.output_bytes as usize).min(64 << 10));
    if let (Some(input), Some(mut w)) = (stdin.map(str::to_owned), child.stdin.take()) {
        std::thread::spawn(move || {
            let _ = w.write_all(input.as_bytes());
        });
    }

    let outcome = loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                // Reap any stragglers the task left in its group.
                kill_group(pid);
                break match (status.code(), status.signal()) {
                    (Some(code), _) => Outcome::Completed { exit_code: code },
                    (None, Some(libc::SIGXCPU)) => Outcome::CeilingExceeded("cpu time".into()),
                    (None, Some(libc::SIGXFSZ)) => Outcome::CeilingExceeded("file size".into()),
                    (None, Some(sig)) => Outcome::Failed(format!("killed by signal {sig}")),
                    (None, None) => Outcome::Failed("unknown exit".into()),
                };
            }
            Ok(None) => {}
            Err(e) => {
                kill_group(pid);
                let _ = child.wait();
                break Outcome::Failed(format!("wait: {e}"));
            }
        }
        let stop = if Instant::now() >= deadline { Some(Outcome::TimedOut) } else { guard().map(Outcome::Preempted) };
        if let Some(o) = stop {
            kill_group(pid);
            let _ = child.wait();
            break o;
        }
        std::thread::sleep(Duration::from_millis(15));
    };

    let (stdout, t1) = out.join().unwrap_or_default();
    let (stderr, _) = err.join().unwrap_or_default();
    ExecReport {
        outcome,
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
        truncated: t1,
        wall_ms: started.elapsed().as_millis() as u64,
    }
}
