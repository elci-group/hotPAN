# Contributing to hotPAN

## Ground rules

- Read [docs/DIRECTIVE.md](docs/DIRECTIVE.md). It defines the invariants, the
  phase plan, and what "done" means.
- A change is complete only when the live gate passes:

  ```sh
  deliver --spec deliver.toml --strict
  ```

  The gate is cumulative. It re-checks every completed phase: fmt, clippy
  with `-D warnings`, all tests, MSRV 1.88, `cargo deny`, `cargo audit`, the
  unsafe policy, docs, and roadmap drift.
- Commits go through **kaptaind**. Its commit gate runs the same Deliver
  command, and it bumps the version and pushes. Do not bypass it with raw
  `git commit`/`git push` on `master`.
- No `TODO`/`FIXME`/`unimplemented!`/`todo!` in `crates/`. Put unfinished
  work in `docs/ROADMAP.md`.
- `unsafe` is only allowed in `hotpan-sandbox`, and every block needs a
  `// SAFETY:` comment.
- Keep the docs in step with behaviour. If you tick a roadmap box, the phase
  gate must actually check it.

## Closing a phase

```sh
scripts/close-phase.sh <N>
```

This runs `deliver/phase-N.toml` in strict mode. If it passes, the script
writes `docs/evidence/phase-N.json` and moves `deliver.toml` to extend phase
N. If it fails, the script refuses. Then add the phase's entry to
`docs/PHASE_LOG.md`.

## Tests

- Unit tests live next to the code.
- Control-plane behaviour: `crates/hotpan-orchestrator/src/tests.rs`, which
  runs real `NodeCore`s against a synthetic clock.
- End-to-end over real TCP and the secure channel:
  `crates/hotpan-node/tests/fabric.rs`.
