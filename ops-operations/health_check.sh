#!/usr/bin/env bash
# ops-operations/health_check.sh — OP-326 operation catalog (issue #830).
#
# health_check: bounded, READ-ONLY host diagnostics.
# This is the one operation whose semantics are fully knowable from this lane,
# so its body is fully implemented. It executes ONLY through the hardened
# relay: the operation enum + the fail-closed config laws + the exact host-key
# pin all ran BEFORE this file was allowed to start.
#
# Parameter contract (set by the relay, validated by the law library):
#   RELAY_RUN_ID — the GitHub Actions run id (numeric, audit trace)

set -euo pipefail

echo "== ops-relay health_check (run ${RELAY_RUN_ID:-unknown}) =="
echo "-- time (utc): $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "-- uptime:"
uptime
echo "-- disk:"
df -h / /srv 2>/dev/null || df -h /
echo "-- memory:"
free -m 2>/dev/null || true
echo "-- releases root (newest first):"
ls -lat /srv/ops/releases 2>/dev/null | head -10 || echo "(releases root absent)"
echo "-- current release pointer:"
readlink /srv/ops/current 2>/dev/null || echo "(no current pointer)"
echo "-- listening services (first 15):"
ss -tlnp 2>/dev/null | head -15 || netstat -tln 2>/dev/null | head -15 || echo "(no socket tool available)"
echo "-- ops root (newest first):"
ls -lat /srv/ops 2>/dev/null | head -10 || true
echo "== health_check complete =="
