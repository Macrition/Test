#!/usr/bin/env bash
# ops-operations/deploy_release.sh — OP-326 operation catalog (issue #830).
#
# deploy_release: activate a digest-verified release artifact on the managed host.
#
# Parameter contract (set by the relay, validated by the law library):
#   RELAY_RUN_ID  — the GitHub Actions run id (numeric, audit trace)
#   RELAY_PAYLOAD — the remote path of the uploaded artifact; the relay verified
#                   its sha256 against the dispatch-declared digest BEFORE upload,
#                   and the destination is pinned under /srv/ops/releases/<name>
#   RELAY_DEST    — the same pinned destination path
#
# THE BODY IS AN ACCOUNT-OWNER LEG (issue #830): the deployment procedure for
# the managed host is operational knowledge held by the account owner — the
# prior 42 relay batches were owner-authored (the OP-326 audit of record), and
# this lane will not invent production deployment commands it has never seen.
# Until the owner composes the body inside this reviewed template, the
# operation FAILS CLOSED: it can never execute an undefined procedure.
#
# Owner fill-in guidance (keep inside this reviewed file, keep it versioned):
#   1. verify the payload integrity on-host (sha256 against a dispatch-declared
#      digest forwarded through a RELAY_SHA256 variable — add it to the relay
#      envelope law first),
#   2. unpack into a staging dir under /srv/ops/releases/<name> ONLY,
#   3. atomically flip the /srv/ops/current pointer,
#   4. restart the documented service set,
#   5. print a bounded, secret-free activation report.

set -euo pipefail

echo "REJECTED: deploy_release body not yet composed by the account owner (issue #830 operator leg) — fail closed" >&2
echo "The enum entry, the parameter contract and the fill-in guidance of record are ready inside this template." >&2
exit 9
