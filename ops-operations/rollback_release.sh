#!/usr/bin/env bash
# ops-operations/rollback_release.sh — OP-326 operation catalog (issue #830).
#
# rollback_release: return the managed host to a prior pinned release.
#
# Parameter contract (set by the relay, validated by the law library):
#   RELAY_RUN_ID — the GitHub Actions run id (numeric, audit trace)
#
# THE BODY IS AN ACCOUNT-OWNER LEG (issue #830): the rollback procedure for
# the managed host is operational knowledge held by the account owner — the
# prior 42 relay batches were owner-authored (the OP-326 audit of record), and
# this lane will not invent production rollback commands it has never seen.
# Until the owner composes the body inside this reviewed template, the
# operation FAILS CLOSED: it can never execute an undefined procedure.
#
# Owner fill-in guidance (keep inside this reviewed file, keep it versioned):
#   1. accept the target release name through a RELAY_TARGET variable (add the
#      field to the relay envelope law first; validate against the same
#      /srv/ops/releases/<name> pinned-root law),
#   2. re-point /srv/ops/current atomically to the pinned prior release,
#   3. restart the documented service set,
#   4. print a bounded, secret-free rollback report.

set -euo pipefail

echo "REJECTED: rollback_release body not yet composed by the account owner (issue #830 operator leg) — fail closed" >&2
echo "The enum entry, the parameter contract and the fill-in guidance of record are ready inside this template." >&2
exit 9
