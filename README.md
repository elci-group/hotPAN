# hotPAN

**Heuristically Orchestrated Transient Phone-as-Node.**

hotPAN is a just-in-time compute fabric. It does not enrol a phone as a server.
It promotes a device into a constrained, addressable execution node for exactly
as long as some fragment of a workload benefits from that device, and then
dissolves the node and its authority.

```
observe → score → promote → provision → execute → attest → return → purge → dissolve
```

Node selection depends on the workload, not just the device. The orchestrator
never asks "is this phone powerful enough?" It asks "is there a fragment of this
execution graph that this device is currently best placed to run?" A phone at
18% battery that someone is using scores near zero for compilation, but it can
still be the only node able to run a camera capture or work with data that must
stay on that phone.

hotPAN is a protocol for transient nodes, and phones are its first
implementation. The orchestrator sees capability vectors, not product
categories, so laptops, tablets and home servers join the same fabric the same
way.

## Quick start

```sh
cargo build --release
B=target/release/hotpan

$B simulate                       # scripted household fabric, real control plane + sandbox

$B keygen --out orchestrator.key  # prints the signing key nodes should --pin
export HOTPAN_PAIR_SECRET=...     # optional fabric pairing secret (env only, never a flag)
$B orchestrate --key orchestrator.key --events events.jsonl --require-pairing

# on each device (Linux, or Android via Termux): dials OUT, needs no inbound port
$B node --connect orchestrator-host:7450 --pin <signing-key> --config examples/node.toml --reconnect

$B fleet   --to orchestrator-host:7450 --pin <signing-key>
$B explain examples/photo-pipeline.toml --to orchestrator-host:7450
$B submit  examples/photo-pipeline.toml --to orchestrator-host:7450 --pin <signing-key>
$B probe                          # what this device would advertise
```

Jobs are TOML or JSON. Each fragment declares a profile (`compute_bound`,
`parallel_low_relational`, `sensor_bound`, `credential_bound`, `network_bound`,
`monitoring`), the capabilities it requires, its privacy and locality
constraints, a minimum trust level, an explicit resource ceiling, and a task
(a builtin or an allowlisted `exec`). See `examples/`.

## Architectural invariants and where they live

| Invariant | Enforcement |
|---|---|
| Ephemeral authority | Each node session generates a fresh node id and fresh ed25519/x25519 keys. They are never persisted, and they are zeroized on drop (`hotpan-node`, `hotpan-seal`). |
| Capability-scoped permissions | Every lease is signed and lists the minimal scopes for its fragment. A task runs only if it is within the lease scopes **and** on the node operator's allowlist (`hotpan-seal::lease`, `hotpan-sandbox`). |
| Explicit resource ceilings | Every lease carries wall, CPU, memory and output limits. The node refuses ceilings above what it offered and enforces them with `RLIMIT_*`, a deadline and capped output capture. |
| Thermal and battery protection | The same `protection_gates` rule gates placement in the scheduler and preempts running work on the node. |
| Encrypted transport | Every connection starts with a Noise_XX handshake (`Noise_XX_25519_ChaChaPoly_BLAKE2s`). The orchestrator signs the handshake hash with its pinned ed25519 key, so a relay or impostor cannot sit in the middle. Everything after the handshake is encrypted and authenticated (`hotpan-wire::secure`). |
| Encrypted task envelopes | Tasks and results are also sealed end to end with X25519 + ChaCha20-Poly1305, using a fresh ephemeral key per envelope and AEAD-bound to the lease id. |
| Workload sandboxing | Each lease gets a private 0700 workspace, a scrubbed environment and its own process session. On timeout or preemption the whole process group is killed. |
| Attested results | The node signs (lease, fragment, node, blake3 digest). The control plane verifies the signature against the key advertised for that session before accepting a result. |
| Automatic revocation | Leases expire. A silent node is declared lost and its leases are revoked and rescheduled. When the control plane disappears, a node cancels and purges everything. |
| No assumed node persistence | No node state survives a session. A reconnecting device joins as a new node, and workspaces left by a crash are wiped at startup. |
| No inbound public networking | Nodes always dial out. The orchestrator never dials a node. |

## Layout

| Crate | Role |
|---|---|
| `hotpan-core` | Capability vector, workloads, resource ceilings, the lifecycle state machine |
| `hotpan-heuristic` | Workload-relative scoring, hard protection gates, comparative-advantage assignment |
| `hotpan-seal` | Keys, signed leases, sealed envelopes, attestations, pairing proofs |
| `hotpan-probe` | Linux/Android sysfs probing, Termux sensor discovery, scripted probes |
| `hotpan-sandbox` | Bounded, preemptible, purgeable execution |
| `hotpan-wire` | Noise_XX secure channel, framing, and message types |
| `hotpan-orchestrator` | Synchronous `ControlPlane` state machine and its TCP server |
| `hotpan-node` | `NodeCore`, the outbound-only agent, and the submit client |
| `hotpan-cli` | The `hotpan` binary and the `simulate` scenario |

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the design and
[docs/ROADMAP.md](docs/ROADMAP.md) for what is still missing, including known
security gaps you should read before running this outside a trusted network.

## Testing

```sh
cargo test --workspace         # unit, control-plane and real-TCP end-to-end tests
cargo clippy --all-targets
```

License: MIT.
