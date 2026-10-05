use crate::{ExecReport, Guard, Outcome};
use hotpan_core::{BuiltinTask, ResourceCeiling};
use std::time::{Duration, Instant};

/// Shared interruption check for in-process kernels.
fn interrupted(guard: Guard<'_>, deadline: Instant) -> Option<Outcome> {
    if Instant::now() >= deadline {
        return Some(Outcome::TimedOut);
    }
    guard().map(Outcome::Preempted)
}

pub(crate) fn run(task: &BuiltinTask, ceiling: &ResourceCeiling, guard: Guard<'_>, started: Instant) -> ExecReport {
    let deadline = started + Duration::from_millis(ceiling.wall_ms);
    let result: Result<String, Outcome> = match task {
        BuiltinTask::Echo { payload } => Ok(payload.clone()),
        BuiltinTask::Blake3 { data } => Ok(blake3::hash(data.as_bytes()).to_hex().to_string()),
        BuiltinTask::Sleep { ms } => {
            let until = started + Duration::from_millis(*ms);
            loop {
                if let Some(o) = interrupted(guard, deadline) {
                    break Err(o);
                }
                if Instant::now() >= until {
                    break Ok(format!("slept {ms}ms"));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        BuiltinTask::PrimeCount { upto } => prime_count(*upto, ceiling, guard, deadline).map(|n| n.to_string()),
    };
    let mut report = ExecReport::bare(Outcome::Completed { exit_code: 0 }, started);
    match result {
        Ok(mut out) => {
            let cap = ceiling.output_bytes as usize;
            if out.len() > cap {
                let mut cut = cap;
                while !out.is_char_boundary(cut) {
                    cut -= 1;
                }
                out.truncate(cut);
                report.truncated = true;
            }
            report.stdout = out;
        }
        Err(o) => report.outcome = o,
    }
    report.wall_ms = started.elapsed().as_millis() as u64;
    report
}

/// Segmented sieve: memory is O(sqrt(n) + segment), interruptible per segment.
fn prime_count(upto: u64, ceiling: &ResourceCeiling, guard: Guard<'_>, deadline: Instant) -> Result<u64, Outcome> {
    if upto < 2 {
        return Ok(0);
    }
    let root = (upto as f64).sqrt() as u64 + 1;
    if root.saturating_mul(2) > ceiling.memory_mb.saturating_mul(1 << 20) {
        return Err(Outcome::CeilingExceeded("sieve base exceeds memory ceiling".into()));
    }
    let mut small = vec![true; root as usize + 1];
    let mut base = Vec::new();
    for i in 2..=root as usize {
        if small[i] {
            base.push(i as u64);
            let mut j = i * i;
            while j <= root as usize {
                small[j] = false;
                j += i;
            }
        }
    }
    const SEG: u64 = 1 << 16;
    let mut count = 0;
    let mut seg = vec![true; SEG as usize];
    let mut lo = 2;
    while lo <= upto {
        if let Some(o) = interrupted(guard, deadline) {
            return Err(o);
        }
        let hi = (lo + SEG - 1).min(upto);
        seg.iter_mut().for_each(|b| *b = true);
        for &p in &base {
            if p * p > hi {
                break;
            }
            let mut m = (lo.div_ceil(p) * p).max(p * p);
            while m <= hi {
                seg[(m - lo) as usize] = false;
                m += p;
            }
        }
        count += seg[..(hi - lo + 1) as usize].iter().filter(|&&b| b).count() as u64;
        lo = hi + 1;
    }
    Ok(count)
}
