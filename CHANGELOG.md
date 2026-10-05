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
