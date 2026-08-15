#!/usr/bin/env bash
# Shared process ownership, readiness parsing, typed NDJSON checks, and cleanup.
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
. "$root/tests/local/common.sh"
