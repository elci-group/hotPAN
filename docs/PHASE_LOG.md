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
