# Phase log

One entry per closed phase. Each entry links to its Deliver evidence in
`docs/evidence/`. The evidence is the record. This log summarises it and
notes anything that could not be verified in this environment
(DIRECTIVE §4 rule 7).

## Phase 0 — Delivery governance

- Gate: `deliver/phase-0.toml`, which extends `deliver/base.toml`.
- Evidence: `docs/evidence/phase-0.json`.
- MSRV is 1.88. It was found empirically with the installed toolchains.
  1.82 fails because `base64ct` 1.8 uses edition 2024 and `clap` 4.6 needs
  1.85. 1.85 fails because `wasip2` needs 1.87. With `resolver = "3"`,
  `uuid` is held at 1.26.1, since 1.27 needs 1.89.
- The gate runs `cargo deny` and `cargo audit` offline, so the commit gate
  does not depend on the network. CI runs both online.
- **Not verifiable here:** the GitHub Actions workflow is checked
  structurally (YAML schema plus required steps) by the gate, but it has not
  been run on GitHub from this environment. Check its first run on the
  Actions tab.

## Phase 1 — Protocol and control-plane hardening

- Gate: `deliver/phase-1.toml`, which extends Phase 0.
- Evidence: `docs/evidence/phase-1.json`.
- Defects found and fixed by this phase (all predate it):
  - **Half-open connections.** The orchestrator never spoke unprompted, so a
    node behind a dead or half-open connection kept running leases for a
    control plane that no longer existed. Fix: `Ping`/`Pong` keepalive, and
    the node dissolves after 4 silent heartbeats. Test:
    `node_dissolves_when_control_plane_goes_silent`.
  - **Results could exceed the frame limit.** The default 1 MiB
    `output_bytes`, after worst-case JSON escaping (6×) and hex sealing (2×),
    could exceed the 8 MiB frame. The result could then not be sent, and the
    lease silently expired. Fix: the default ceiling is 256 KiB and validation
    caps it at 512 KiB. Test: `default_output_ceiling_fits_a_frame`.
  - **Unbounded state.**
    - Per-node outbound queues were unbounded.
    - The job table never evicted finished jobs.
    - There were no caps on connections, handshakes, nodes or jobs.
    - Every connection could make the server assemble an 8 MiB frame
      (about 8 GiB across 1,024 connections).
  - **Poisoned mutexes.** One panic while holding the plane lock would have
    poisoned it for every later request. Fix: `hotpan_core::lock` recovers the
    data.
- Protocol bumped to v3 (prologue `hotpan/3`) because `Ping`/`Pong` were added.
  v2 peers fail the handshake cleanly instead of misparsing messages.
- Fuzzing: `wire_messages`, `job_spec` and `frame_decode` each ran 20 s while
  this phase was being built (about 2.4M executions, no crashes). The gate
  re-runs each for 10 s.
