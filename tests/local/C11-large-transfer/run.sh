#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
. "$root/local/common.sh"
run_local_case "C11-large-transfer"
