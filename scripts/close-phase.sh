#!/usr/bin/env bash
# Close a phase: run its cumulative gate in strict mode, keep the JSON
# evidence, and advance the live gate. Refuses if the gate fails.
#   usage: scripts/close-phase.sh <N>
set -euo pipefail
N="${1:?usage: scripts/close-phase.sh <phase-number>}"
cd "$(dirname "$0")/.."
spec="deliver/phase-${N}.toml"
[[ -f "$spec" ]] || { echo "no such gate: $spec" >&2; exit 2; }
out="docs/evidence/phase-${N}.json"
mkdir -p docs/evidence
tmp="$(mktemp)"
if ! deliver --spec "deliver/phase-${N}.toml" --strict --format json > "$tmp"; then
  echo "phase ${N} gate FAILED; evidence not recorded:" >&2
  python3 -c 'import json,sys; [print("  ✗", c["name"], "—", c["message"]) for c in json.load(open(sys.argv[1]))["checks"] if not c["pass"]]' "$tmp" >&2 || cat "$tmp" >&2
  rm -f "$tmp"; exit 1
fi
mv "$tmp" "$out"
printf 'extends = "deliver/phase-%s.toml"\n# The live gate: always extends the highest *completed* phase. kaptaind runs\n# this before every commit, and CI runs it on every push. See docs/DIRECTIVE.md §4.\n' "$N" > deliver.toml
python3 - "$out" "$N" <<'PY'
import json, sys, datetime
r = json.load(open(sys.argv[1])); n = sys.argv[2]
checks = r["checks"]
print(f"phase {n}: PASS — {sum(c['pass'] for c in checks)}/{len(checks)} checks in {r['duration_ms']/1000:.1f}s; evidence at {sys.argv[1]}")
PY
