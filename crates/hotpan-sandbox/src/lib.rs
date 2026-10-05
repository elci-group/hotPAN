//! Node-side execution for hotPAN leases.
//!
//! Every task runs inside a [`Workspace`] — a private per-lease directory that
//! is purged when the lease ends (and on drop, as a backstop). Execution is
//! bounded on every axis the lease names:
//!
//! * **authority** — the task must be within the lease's scopes *and* the
//!   node operator's local allowlist; neither alone is sufficient;
//! * **resources** — wall-clock deadline, `RLIMIT_CPU`, `RLIMIT_AS`,
//!   `RLIMIT_FSIZE`, no core dumps, capped captured output;
//! * **environment** — scrubbed env, workspace as cwd/HOME/TMPDIR, own
//!   session so the whole process group can be killed;
//! * **protection** — a guard callback polled during execution; when it
//!   returns a reason (battery dropped, device heating, lease revoked) the
//!   work is stopped immediately and reported as preempted.
//!
//! This is the only hotPAN crate permitted `unsafe` (for `setrlimit`,
//! `setsid` and process-group `kill`). Every block must carry a `SAFETY:`
//! comment; the lints below make that a build error.

#![deny(clippy::undocumented_unsafe_blocks, unsafe_op_in_unsafe_fn)]

mod builtin;
mod exec;
mod workspace;

pub use workspace::{purge_stale, PurgeReceipt, Workspace};

use hotpan_core::{ResourceCeiling, TaskSpec};
use hotpan_seal::{task_permitted, Scope};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::Instant;

/// The node operator's local policy. Leases can narrow it, never widen it.
#[derive(Clone, Debug)]
pub struct Policy {
    /// Absolute paths of programs `exec` tasks may run.
    pub allowed_programs: BTreeSet<String>,
    /// The most any single lease may consume on this node.
    pub max: ResourceCeiling,
    /// Where per-lease workspaces are created.
    pub workroot: PathBuf,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "status", content = "detail")]
pub enum Outcome {
    Completed {
        exit_code: i32,
    },
    /// Refused before anything ran.
    Rejected(String),
    /// Stopped by node protection or revocation.
    Preempted(String),
    TimedOut,
    CeilingExceeded(String),
    Failed(String),
}

impl Outcome {
    pub fn succeeded(&self) -> bool {
        matches!(self, Outcome::Completed { exit_code: 0 })
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ExecReport {
    pub outcome: Outcome,
    /// Captured stdout (lossily decoded as UTF-8), capped at the lease's `output_bytes`.
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
    pub wall_ms: u64,
}

impl ExecReport {
    pub(crate) fn bare(outcome: Outcome, started: Instant) -> Self {
        Self {
            outcome,
            stdout: String::new(),
            stderr: String::new(),
            truncated: false,
            wall_ms: started.elapsed().as_millis() as u64,
        }
    }
}

/// Polled during execution; `Some(reason)` stops the task.
pub type Guard<'a> = &'a (dyn Fn() -> Option<String> + Sync);

/// Execute `task` under `ceiling` and `scopes` inside `ws`.
pub fn execute(
    policy: &Policy,
    ws: &Workspace,
    task: &TaskSpec,
    ceiling: &ResourceCeiling,
    scopes: &[Scope],
    guard: Guard<'_>,
) -> ExecReport {
    let started = Instant::now();
    if !ceiling.fits_within(&policy.max) {
        return ExecReport::bare(Outcome::Rejected("lease ceiling exceeds node policy".into()), started);
    }
    if let Err(e) = task_permitted(task, scopes) {
        return ExecReport::bare(Outcome::Rejected(e), started);
    }
    if let Some(reason) = guard() {
        return ExecReport::bare(Outcome::Preempted(reason), started);
    }
    match task {
        TaskSpec::Builtin(b) => builtin::run(b, ceiling, guard, started),
        TaskSpec::Exec { program, args, stdin } => {
            if !program.starts_with('/') {
                return ExecReport::bare(Outcome::Rejected("exec programs must be absolute paths".into()), started);
            }
            if !policy.allowed_programs.contains(program) {
                return ExecReport::bare(
                    Outcome::Rejected(format!("{program} is not in this node's allowlist")),
                    started,
                );
            }
            exec::run(program, args, stdin.as_deref(), ws, ceiling, guard, started)
        }
    }
}

#[cfg(test)]
mod tests;
