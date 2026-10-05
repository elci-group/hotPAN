# hotPAN architecture

## The lease is the unit

hotPAN never schedules a *device*. It schedules a **lease**: the authority to
run one fragment on one node, under one ceiling, until one expiry time. Every
lease goes through the lifecycle in `hotpan-core::lifecycle`:

```
Observed → Scored → Promoted → Provisioned → Executing → Attested → Returned → Purged → Dissolved
                       └──────────┴────────────┴────────────┴──────────┴─→ Revoked ─→ Purged/Dissolved
```

Transitions are checked. A lease cannot skip attestation, and it cannot come
back after `Dissolved`. Every abnormal exit goes through `Revoked` with a
reason (`NodeLost`, `Preempted`, `Expired`, `Rejected`, `BadResult`,
`TaskFailed`, `Withdrawn`) and still ends in `Dissolved`, so authority is never
left dangling. Each transition is emitted as an event; `--events` writes them
to a JSONL file.

## Scoring: `H = f(...)`

`hotpan-heuristic::assess` scores one (node, fragment) pair in two stages.

1. **Hard gates.** These cover required capabilities, privacy locality (`MustStayOn(tag)`
   needs `local_data:tag`), site/LAN locality, trust, the ceiling against the
   node's offer, the exec program against the node's allowlist, memory,
   connectivity, battery and thermal protection, free slots, and finally the
   promotion threshold. If any gate fails, the score is 0 and the failed gates
   are reported, so the job report can say why a fragment is still waiting.
2. **Soft score.** This is a profile-weighted sum of energy, thermal headroom,
   compute throughput, memory, network, idleness, cost and trust. For
   compute-heavy profiles, the sum is also multiplied by energy × idleness, so
   no amount of CPU can outweigh draining the battery of a phone someone is
   using.

The protection rule is a single function, `protection_gates`. The scheduler uses
it to gate placement, and the node's `ProtectionGuard` uses it to preempt work
that is already running. Both sides apply the same rule.

## Assignment: comparative advantage

`hotpan-heuristic::plan` places fragments **scarcest first** (the fragment with
the fewest eligible nodes goes first). Each choice is discounted by an
**opportunity cost**: using a node that is one of very few able to serve
another pending fragment costs more. A naive greedy planner would give the
fastest node (which also has the only camera) the compile job and leave the
capture with nowhere to run. The planner does not do this, and a test covers
the case.

## Control plane

`ControlPlane` is synchronous and deterministic: every method takes `now`
explicitly and returns outbound messages. Three things drive it:

- `server::Server`, the TCP front end, which ticks it every 200 ms;
- the `hotpan simulate` scenario;
- the control-plane tests, which run real `NodeCore`s, real leases, real
  envelopes and real sandbox execution on a synthetic clock.

When a node is lost (it disconnected or missed `node_timeout_ms` of heartbeats),
every lease it held with live authority is revoked. Its fragments go back to the
queue with that node excluded, and are retried up to `max_attempts`.

## Node

`NodeCore` handles each provisioned lease in this order:

1. Verify the issuer, signature, node binding and validity window.
2. Reject the lease if it was already seen, or if no slot is free.
3. Reject it if its ceiling exceeds what the node offered.
4. Check the protection gates against a fresh sample.
5. Decrypt the task, bound to the lease id.
6. Check the task against the lease scopes and the local allowlist.
7. Create the workspace.

Execution runs on a blocking worker with a guard that combines revocation,
lease expiry and device protection. The result is sealed to the orchestrator
and attested with the session key. If a lease is revoked while it is running,
**no result is released**: the workspace is purged and only the purge receipt
is sent.

The agent always dials out. If the connection drops, it cancels every lease,
purges every workspace and ends the session. With `--reconnect`, the device
rejoins as a brand-new node with new keys.

## Wire protocol

Every connection is dialled by the node or client; the control plane never
dials out.

1. **Noise_XX handshake** (`Noise_XX_25519_ChaChaPoly_BLAKE2s`, prologue
   `hotpan/2`). Each side's Noise static key is its x25519 key: the
   orchestrator's long-lived key, a node's session key, or a client's
   throwaway key. The handshake hash is the **channel binding**.
2. The server sends `Welcome {orchestrator keys, proof, heartbeat}`. `proof` is
   the orchestrator's ed25519 signature over the binding. The peer checks three
   things: the signing key matches its `--pin`, the signature verifies, and the
   advertised x25519 key is the Noise static key it actually handshook with.
3. The peer replies with `Hello::Node {advertisement, proof, pairing?}` or
   `Hello::Client {...}`. `proof` signs the binding with the peer's session
   key. `pairing` is a keyed BLAKE3 proof of the fabric secret over the binding
   and that session key. For nodes, the server also checks that the advertised
   x25519 key equals the channel's remote static, because task envelopes will be
   sealed to it.

A man in the middle has to run two handshakes, which produce two different
bindings. It cannot sign either one as the orchestrator, and any proof it
relays is bound to the wrong channel.

After the handshake, each message is JSON with its length prefixed **inside**
the first encrypted chunk. A message larger than one Noise message (64 KiB) is
split into chunks. Nonces increase strictly in each direction, so tampering,
replay, reordering and truncation all show up as errors. Messages are capped at
8 MiB.

Nodes are `Unverified` unless they prove the pairing secret, in which case they
are `Paired`. `HardwareAttested` exists in the model, but nothing grants it yet
(see ROADMAP).
