# Roadmap and known gaps

## Shipped (v0.1)

- [x] Core model: capability vector, workloads, ceilings, checked lifecycle
- [x] Workload-relative scoring, protection gates, promotion threshold, comparative-advantage planner
- [x] Signed capability-scoped leases, sealed envelopes, session-key attestation, pairing proofs, key pinning
- [x] Linux/Android sysfs probe, Termux sensor discovery, scripted probes
- [x] rlimit/deadline/allowlist sandbox, process-group kill, guard-driven preemption, purge receipts
- [x] Orchestrator: registry, scheduling, expiry, node-loss rescheduling, attempts, event log, graceful shutdown
- [x] Outbound-only node agent with reconnect, client, CLI, `simulate`

## Shipped (v0.2)

- [x] Encrypted, authenticated transport: Noise_XX, with the channel binding signed by the pinned orchestrator key
- [x] Peer proofs and pairing proofs bound to the channel; advertised kex key must equal the channel's remote static
- [x] Wiretap test (no plaintext crosses the wire) and impostor test (correct public key, wrong channel → rejected)

## Security gaps (read before deploying)

- **Unpinned peers trust on first use.** Without `--pin`, a node or client
  accepts whatever orchestrator key it is shown, and an active attacker on
  that first connection can impersonate the control plane. Always pin. The
  transport also cannot stop an on-path attacker from dropping or delaying
  traffic; hotPAN treats that as node loss.
- **Metadata still leaks.** Connection timing and encrypted message sizes are
  visible to an observer.
- **Without `--require-pairing`, anyone who can reach the port can submit
  jobs.** Nodes are still protected by their own allowlists and ceilings, but
  builtins (including CPU-heavy `prime_count`) will run.
- **Attestation is session-key only.** It proves which session produced a
  result, not what hardware produced it. `HardwareAttested` trust needs
  Android Keystore / StrongBox key attestation.
- `RLIMIT_AS` limits address space, not resident memory. Some runtimes (JVM,
  Go) reserve large virtual ranges and will fail under tight `memory_mb`.
  cgroups would be a better fit where they are available.

## Not yet done

- [ ] Periodic rekeying for very long-lived sessions
- [ ] Hardware-backed node keys and attestation on Android
- [ ] Android build verified on a real device (`aarch64-linux-android`); the code avoids glibc-only APIs, but no Android build has been run
- [ ] User-activity probing (screen/input idleness) — today it is operator-declared or `unknown`
- [ ] RTT measurement into `network.rtt_ms`
- [ ] Fragment dependencies (true DAGs) and data passing between fragments
- [ ] Orchestrator persistence for jobs across control-plane restarts (nodes stay deliberately stateless)
- [ ] Non-phone promotion adapters (TVs, consoles, vehicles) — the protocol already supports them, but no probes exist for them
- [ ] Binary-safe stdout (stdout is currently decoded as UTF-8 with lossy replacement)
