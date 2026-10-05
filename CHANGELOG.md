# Changelog

All notable changes to hotPAN. Versions are assigned by kaptaind.

## [Unreleased]
### Added
- Technical directive and enterprise roadmap to 1.0 (`docs/DIRECTIVE.md`, `docs/ROADMAP.md`).
- Phase 0, delivery governance:
  - Cumulative Deliver gates (`deliver/`), with `deliver.toml` as the live gate.
  - kaptaind commit gate runs Deliver.
  - MSRV 1.88 is declared and checked, with the MSRV-aware resolver.
  - `cargo deny` policy.
  - `forbid(unsafe_code)` outside the sandbox.
  - CI with SARIF upload.
  - SECURITY, CONTRIBUTING and CHANGELOG files, and a phase log with evidence capture.

### Changed (Phase 1, protocol and control-plane hardening)
- Protocol v3 (prologue `hotpan/3`). It adds an orchestrator→node `Ping`/`Pong`
  keepalive, and nodes dissolve when the control plane is silent.
- Bounds on everything a peer controls:
  - connections, concurrent handshakes and handshake deadline
  - per-role frame caps
  - bounded per-node queues with slow-peer eviction
  - node and client idle timeouts
  - fleet size, plus fabric-wide and per-client job quotas
  - retention of finished jobs
- Strict validation of advertisements, heartbeats and job specs (`hotpan_core::Limits`).
  A node that sends an invalid heartbeat is ejected.
- Default `output_bytes` ceiling lowered to 256 KiB, with a hard limit of 512 KiB, so
  every result fits in one frame.
- `hotpan submit --identity` sets a persistent client key, and quotas are applied per key.
- Network-facing crates deny `unwrap`/`expect`/`panic` outside tests. Mutex locks
  recover from poisoning.
- Property tests (lifecycle, planner, codec, secure channel) and cargo-fuzz targets.

## [0.2.1] - 2026-10-05
### Added
- Noise_XX encrypted, authenticated transport. The channel binding is signed by the pinned orchestrator key.
- Peer and pairing proofs are bound to the channel.
- Wiretap and impostor end-to-end tests.

## [0.1.0] - 2026-10-05
### Added
- Initial transient-node fabric:
  - core model and lifecycle
  - heuristic scoring and comparative-advantage planner
  - signed leases, sealed envelopes and attestation
  - Linux/Android probing
  - bounded sandbox
  - control plane, outbound-only node agent, CLI and simulation
