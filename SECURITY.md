# Security Policy

hotPAN runs other people's work on people's personal devices. We treat
vulnerabilities in it as serious, and we welcome reports.

## Supported versions

| Version | Supported |
|---|---|
| latest `master` | yes |
| 0.2.x | yes (security fixes) |
| 0.1.x | no. It has a cleartext control channel, so upgrade. |

## Reporting a vulnerability

Please **do not open a public issue**. Report privately through GitHub's
"Report a vulnerability" (Security Advisories) on
`github.com/elci-group/hotPAN`. Include the affected version or commit,
reproduction steps, and the impact you see.

We aim to acknowledge reports within 3 working days and to agree a disclosure
date with you. Fixes ship with a regression test and a CHANGELOG entry.

## Scope

The following are in scope:

- **Lease authority bypass.** A node runs work outside its lease scopes or its allowlist, or above its ceilings.
- **Protection bypass.** Compute-heavy work runs below the battery or thermal floors.
- **Transport and channel-binding weaknesses.** Impersonating the orchestrator or a node, or reading or modifying traffic.
- **Result forgery.** Getting a result accepted that was not attested by the lease holder.
- **Workspace escapes.** Leftover data after a purge.
- **Denial of service against the control plane** from unauthenticated peers.

Known limitations are listed in `docs/ROADMAP.md`. These include
trust-on-first-use without `--pin`, traffic-analysis metadata, and
attestation that uses the session key only. They are not considered
vulnerabilities unless you find a way to go beyond their stated limits.
