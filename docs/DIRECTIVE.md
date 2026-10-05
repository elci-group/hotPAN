# hotPAN — Technical Directive: Path to Production Readiness

Status: **active** · Owner: hotPAN maintainers · Baseline: v0.2.1 (2026-10-05)

This directive defines what "production ready" means for hotPAN, the phases
that get it there, and how completion of each phase is *proved*. It is binding
on everyone (human or agent) working in this repository: a phase is complete
only when its Deliver gate passes, never because someone says it is.

## 1. Product definition

hotPAN promotes devices into a transient, constrained compute fabric, for
exactly as long as some workload fragment benefits from them. Each
participation is a lease that goes through
`observe → score → promote → provision → execute → attest → return → purge → dissolve`.

"Production ready" means an operator can run one control plane and a fleet of
heterogeneous devices (Android phones first) on an untrusted network, and
trust that all of the following hold:

| # | Property | Meaning |
|---|---|---|
| P1 | **Safe for devices** | A node never runs work outside its operator's allowlist and ceilings, never runs compute-heavy work below its battery or thermal floor, and leaves nothing behind after a lease. |
| P2 | **Safe for submitters** | A result is accepted only if it is attested by the session that held the lease, and is never silently lost. |
| P3 | **Secure on hostile networks** | All traffic is confidential and authenticated, with pinned identities and no inbound ports on devices. |
| P4 | **Bounded** | No input from a peer can exhaust the control plane's memory, CPU, connections or disk. |
| P5 | **Operable** | Health, metrics, structured logs, drain, documented upgrade and recovery procedures. |
| P6 | **Durable** | The control plane survives a crash or restart without losing accepted jobs or completed results. Nodes are deliberately stateless. |
| P7 | **Verifiable** | Every claim above is backed by an automated check that runs in CI and in the commit gate. |

## 2. Non-negotiable invariants (carried from v0.x)

These hold in every phase. Phase gates re-verify them through `deliver/base.toml`.

1. **Ephemeral node authority.** A node's identity and keys exist for one session only, and are never persisted.
2. **Two-key permission.** A task runs only if it is both within the lease's signed scopes and on the node operator's allowlist.
3. **Explicit ceilings on every lease**, enforced on the node.
4. **One protection rule.** The scheduler gate and the node's preemption check use the same function (`protection_gates`).
5. **Sealed payloads and a secure channel.** Both are always in use. Neither replaces the other.
6. **No inbound networking on nodes.** Nodes dial out, and the control plane never dials a node.
7. **No fabricated verification.** Docs, roadmap checkboxes and evidence files must match what the gates actually check. The drift guard enforces this.

## 3. Engineering standards

- **Language and toolchain:** Rust, edition 2021. MSRV is declared in `Cargo.toml` and checked.
- **`unsafe`:** forbidden in every crate except `hotpan-sandbox`. There, every `unsafe` block carries a `// SAFETY:` comment, enforced by `clippy::undocumented_unsafe_blocks`.
- **Lints:** `cargo clippy --all-targets -- -D warnings` is clean. Network-facing code paths contain no `unwrap()`/`expect()` on peer-controlled data.
- **Formatting:** `cargo fmt --check` is clean.
- **Dependencies:** `cargo deny check` (licenses, advisories, bans, sources) and `cargo audit` are clean. New dependencies need a reason in the PR or commit.
- **Tests:** unit tests next to the code, a control-plane harness in-process, real-TCP end-to-end tests in `hotpan-node/tests`, property tests for decoders and state machines, and fuzz targets for every peer-facing parser.
- **Docs:** README, ARCHITECTURE, ROADMAP and RUNBOOK are kept in sync with behaviour, and the drift guard enforces it.
- **No `TODO`/`FIXME`/`unimplemented!`/`todo!`** in shipped crates. Unfinished work belongs in the ROADMAP, not in the code.

## 4. Deliver integration (how completion is proved)

[Deliver](https://github.com/elci-group/deliver) is the single source of truth
for whether a phase is done.

```
deliver/
  base.toml          invariants every phase keeps (fmt, clippy, tests, no-TODO, docs present)
  phase-0.toml       extends base.toml      + Phase 0 deliverables
  phase-1.toml       extends phase-0.toml   + Phase 1 deliverables
  ...
  phase-7.toml       extends phase-6.toml   + Phase 7 deliverables (= production gate)
deliver.toml         extends the highest *completed* phase (the live gate)
docs/evidence/       deliver JSON reports captured when each phase closed
```

Rules:

1. **Cumulative gates.** Phase *N*'s spec extends phase *N−1*, so closing a
   phase re-proves every earlier one. A regression in an old phase blocks
   new work.
2. **Phase exit = `deliver --spec deliver/phase-N.toml --strict` exits 0.**
   Nothing else closes a phase.
3. **The commit gate is Deliver.** kaptaind's `[test] command` runs the live
   `deliver.toml` with `--strict`. A commit that breaks any completed phase
   cannot land.
4. **CI runs the same gate** and uploads SARIF, so failures show up as code
   scanning annotations.
5. **Evidence is kept.** When a phase closes, its `deliver --format json`
   report is saved to `docs/evidence/phase-N.json` and summarised in
   `docs/PHASE_LOG.md`.
6. **Drift guard.** Each phase spec uses `require_regex` to check that the
   ROADMAP ticks that phase's items. Unticking a box, or ticking one without
   its gate, fails the build.
7. **Honesty clause.** If something in a phase cannot be verified in this
   environment (for example, execution on physical Android hardware), the
   phase log says so explicitly. The gate checks what *can* be checked, such
   as a successful cross-build, and the roadmap item is marked
   "verified: build only" rather than ticked as fully verified.

## 5. Phases

Each phase lists its objective, deliverables, and exit gate. Detailed
checklists are in [ROADMAP.md](ROADMAP.md).

### Phase 0 — Delivery governance
Put the machinery in place that proves everything after it.
- Deliver spec hierarchy, live `deliver.toml`, and a kaptaind gate that runs Deliver.
- Declared and checked MSRV.
- `cargo deny` config, plus clean `deny` and `audit` runs.
- `forbid(unsafe_code)` everywhere except the sandbox, which uses documented `unsafe`.
- CI workflow (fmt, clippy, test, MSRV, deny, audit, Deliver + SARIF).
- SECURITY, CONTRIBUTING and CHANGELOG files.
- Phase log and evidence capture.

**Gate:** `deliver/phase-0.toml`.

### Phase 1 — Protocol and control-plane hardening (P3, P4)
- Hard bounds on everything a peer controls: connections, concurrent handshakes, frame sizes per message class, jobs per client, fragments per job, nodes, leases, and the sizes of event and report payloads.
- Bounded channels with back-pressure in place of unbounded queues.
- Handshake, idle and request deadlines.
- Strict input validation (string lengths, capability counts, ceilings, finite floats in vectors).
- No panics reachable from peer input.
- Property tests for the codec and the lifecycle, and fuzz targets for frame decoding and message parsing.

**Gate:** `deliver/phase-1.toml`, including a connection-flood test and fuzz smoke runs.

### Phase 2 — Observability and operations (P5)
- Orchestrator config file (`orchestrator.toml`) with validation.
- Prometheus metrics endpoint.
- Liveness and readiness endpoints.
- JSON log format.
- Event-log size rotation.
- Drain mode: stop promoting, finish in-flight leases, then exit.
- `hotpan doctor` for node pre-flight checks.

**Gate:** `deliver/phase-2.toml`, including a scrape test against the live server.

### Phase 3 — Control-plane durability (P2, P6)
- Write-ahead journal of job submissions, results and failures.
- Replay on start: in-flight leases are treated as lost and fragments are re-queued.
- Idempotent submission keys.
- Results are retrievable after the client reconnects.
- Journal compaction.

**Gate:** `deliver/phase-3.toml`, including a crash-recovery test (kill -9 mid-job, restart, the job completes, with no duplicated or lost results).

### Phase 4 — Workload model
- Fragment dependencies (DAG) with validation (unknown references, cycles).
- Upstream outputs passed to downstream fragments.
- Job cancellation with lease revocation.
- Per-client fair scheduling and quotas.
- Job priorities.

**Gate:** `deliver/phase-4.toml`.

### Phase 5 — Device platform (P1)
- Android `aarch64-linux-android` cross-build via `cargo-ndk`, in CI.
- Protocol-level RTT measurement (ping/pong) feeding `network.rtt_ms`.
- Per-lease battery-drain budget, enforced by the node guard.
- Best-effort user-activity probing.
- `PR_SET_NO_NEW_PRIVS` for exec tasks.
- cgroup v2 memory limits when they are available, falling back to `RLIMIT_AS`.

**Gate:** `deliver/phase-5.toml`. On-device execution is *not* verifiable here; see §4 rule 7.

### Phase 6 — Security assurance (P3, P7)
- Threat model (STRIDE over every trust boundary).
- Orchestrator key rotation, with nodes accepting a pin set.
- CycloneDX SBOM.
- Fuzz corpora committed.
- Coverage floor enforced.
- Security review findings recorded and closed.

**Gate:** `deliver/phase-6.toml`.

### Phase 7 — Release and production readiness
- Protocol compatibility policy and version negotiation errors.
- systemd unit for the orchestrator and a Termux service script for nodes.
- Operator RUNBOOK (install, pin distribution, rotation, drain/upgrade, incident response).
- Release workflow with checksums.
- Version 1.0.0.
- The final cumulative gate.

**Gate:** `deliver/phase-7.toml`, which is the production gate.

## 6. Out of scope for 1.0 (explicit)

- **Hardware-backed attestation (Android Keystore/StrongBox).** It needs a native Android companion app with JNI. It is tracked post-1.0, and `HardwareAttested` trust stays ungranted until then.
- **Multi-orchestrator high availability and consensus.** 1.0 is a single durable control plane with fast restart.
- **Arbitrary container images or WASM workloads.** 1.0 workloads are builtins and allowlisted exec tasks.
- **Non-phone device adapters** (TVs, vehicles). The protocol supports them, but no 1.0 probes are shipped.

## 7. Change control

Changes to this directive are commits to `docs/DIRECTIVE.md` with a matching
ROADMAP update. A phase's scope may shrink only if the removed items move to
the ROADMAP's deferred section with a reason. Scope is never removed silently.
