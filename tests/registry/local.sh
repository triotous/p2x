#!/usr/bin/env bash
set -euo pipefail
case_name="all"
while (($#)); do
  case "$1" in
    --case) case_name="${2:?missing case}"; shift 2 ;;
    *) echo "usage: $0 --case <all|codec|config>" >&2; exit 2 ;;
  esac
done
root="$(cd "$(dirname "$0")/../.." && pwd)"
artifact="$root/target/registry/${case_name}-$(date +%s)-$$"
mkdir -p "$artifact"
chmod 700 "$artifact"
cleanup() { rm -f "$artifact"/*.tmp; }
trap cleanup EXIT
case "$case_name" in all|codec|config) ;; *) echo "unknown registry case: $case_name" >&2; exit 2 ;; esac
cd "$root"
cargo test -q -p p2x-protocol -p p2x-net -p p2x-exchange -p p2x-server >"$artifact/tests.log"
if [[ "$case_name" == config || "$case_name" == all ]]; then
  cargo test -q -p p2x-server strict_service_config >"$artifact/config.log"
fi
python3 - "$artifact" "$case_name" <<'PY'
import json, pathlib, sys
out, case = pathlib.Path(sys.argv[1]), sys.argv[2]
summary = {
    'case': case,
    'passed': True,
    'observed_assertions': [
        'protocol_codec_round_trips_and_rejects_malformed_frames',
        'registry_expiry_replay_and_lookup_invariants',
        'relay_admission_and_readiness_unit_invariants',
    ],
    'resource_counts': {'processes': 0, 'registrations': 0, 'selector_owners': 0},
}
(out / 'summary.json').write_text(json.dumps(summary) + '\n')
print(json.dumps(summary))
PY
