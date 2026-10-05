# hotPAN Roadmap to 1.0

The binding plan is [DIRECTIVE.md](DIRECTIVE.md). Each phase closes only when
`deliver --spec deliver/phase-N.toml --strict` passes. The phase specs check
the ticked items below, so a box is ticked only when its gate exists and
passes.

## Shipped

### v0.1
- [x] Core model: capability vector, workloads, ceilings, checked lifecycle
- [x] Workload-relative scoring, protection gates, promotion threshold, comparative-advantage planner
- [x] Signed capability-scoped leases, sealed envelopes, session-key attestation, pairing proofs, key pinning
- [x] Linux/Android sysfs probe, Termux sensor discovery, scripted probes
- [x] rlimit/deadline/allowlist sandbox, process-group kill, guard-driven preemption, purge receipts
- [x] Orchestrator: registry, scheduling, expiry, node-loss rescheduling, attempts, event log, graceful shutdown
- [x] Outbound-only node agent with reconnect, client, CLI, `simulate`

### v0.2
- [x] Encrypted, authenticated transport: Noise_XX, with the channel binding signed by the pinned orchestrator key
- [x] Peer proofs and pairing proofs bound to the channel; advertised kex key must equal the channel's remote static
- [x] Wiretap test (no plaintext crosses the wire) and impostor test (correct public key, wrong channel → rejected)

## Phase 0 — Delivery governance
- [x] P0.1 Deliver spec hierarchy with cumulative phase gates and a live deliver.toml
- [x] P0.2 kaptaind commit gate runs Deliver in strict mode
- [x] P0.3 MSRV declared and verified
- [x] P0.4 cargo-deny policy and clean cargo-deny and cargo-audit runs
- [x] P0.5 unsafe code forbidden outside the sandbox; sandbox unsafe blocks documented
- [x] P0.6 CI workflow: fmt, clippy, test, MSRV, deny, audit, Deliver with SARIF
- [x] P0.7 SECURITY, CONTRIBUTING and CHANGELOG
- [x] P0.8 Phase log and evidence capture

## Phase 1 — Protocol and control-plane hardening
- [ ] P1.1 Connection, handshake and node limits with refusal on overload
- [ ] P1.2 Bounded outbound channels with back-pressure and slow-peer eviction
- [ ] P1.3 Handshake, idle and request deadlines
- [ ] P1.4 Strict validation of advertisements, heartbeats and job specs
- [ ] P1.5 Per-client job and fragment quotas
- [ ] P1.6 No panics reachable from peer input
- [ ] P1.7 Property tests for codec, secure channel and lifecycle
- [ ] P1.8 Fuzz targets for frame and message decoding with smoke runs

## Phase 2 — Observability and operations
- [ ] P2.1 Validated orchestrator configuration file
- [ ] P2.2 Prometheus metrics endpoint
- [ ] P2.3 Liveness and readiness endpoints
- [ ] P2.4 JSON log output
- [ ] P2.5 Event log rotation
- [ ] P2.6 Drain mode
- [ ] P2.7 hotpan doctor node pre-flight

## Phase 3 — Control-plane durability
- [ ] P3.1 Write-ahead journal of jobs, results and failures
- [ ] P3.2 Replay on restart re-queues in-flight fragments
- [ ] P3.3 Idempotent submission keys
- [ ] P3.4 Journal compaction
- [ ] P3.5 Crash-recovery test (kill -9 mid-job)

## Phase 4 — Workload model
- [ ] P4.1 Fragment dependencies with cycle and reference validation
- [ ] P4.2 Upstream outputs passed to dependent fragments
- [ ] P4.3 Job cancellation revokes live leases
- [ ] P4.4 Job priorities
- [ ] P4.5 Per-client fair scheduling

## Phase 5 — Device platform
- [ ] P5.1 Android aarch64 cross-build (verified: build only)
- [ ] P5.2 Protocol RTT measurement
- [ ] P5.3 Per-lease battery-drain budget
- [ ] P5.4 Best-effort user-activity probing
- [ ] P5.5 PR_SET_NO_NEW_PRIVS for exec tasks
- [ ] P5.6 cgroup v2 memory limits with rlimit fallback

## Phase 6 — Security assurance
- [ ] P6.1 STRIDE threat model
- [ ] P6.2 Orchestrator key rotation with pin sets
- [ ] P6.3 CycloneDX SBOM
- [ ] P6.4 Fuzz corpora committed
- [ ] P6.5 Coverage floor enforced
- [ ] P6.6 Security review findings recorded and closed

## Phase 7 — Release and production readiness
- [ ] P7.1 Protocol compatibility policy and version negotiation
- [ ] P7.2 systemd unit and Termux service script
- [ ] P7.3 Operator runbook
- [ ] P7.4 Release workflow with checksums
- [ ] P7.5 Version 1.0.0 and final production gate

## Deferred past 1.0 (with reason)

- **Hardware-backed attestation (Android Keystore/StrongBox).** Needs a native Android companion app with JNI, which is outside a Rust CLI.
- **Multi-orchestrator high availability.** 1.0 targets a single durable control plane with fast restart.
- **WASM or container workloads.** The 1.0 sandbox model is builtins plus allowlisted exec.
- **Non-phone device adapters.** The protocol supports them, but no probes exist for them yet.

## Known limitations (kept current)

- Peers that do not use `--pin` trust the orchestrator key on first use.
- Connection timing and encrypted message sizes are visible to an observer.
- Attestation uses the session key only, not a hardware-backed key.
- stdout is decoded as UTF-8 with lossy replacement, so it is not binary-safe.
