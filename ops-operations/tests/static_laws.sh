#!/usr/bin/env bash
# ops-operations/tests/static_laws.sh — the OP-326 static law battery (issue #830).
#
# Proves the STRUCTURAL laws of the hardened relay by asserting the workflow
# file and the law library of record. Every assertion is a hard fail.

set -euo pipefail
cd "$(dirname "$0")/../.."
WF=".github/workflows/ops-relay.yml"
LIB="ops-operations/lib/relay_laws.sh"

FAIL=0
check_absent() { # check_absent <pattern> <file> <law>
    if grep -qF -- "$1" "$2"; then
        echo "FAIL: $3 — forbidden pattern present: $1"
        FAIL=1
    else
        echo "PASS: $3 (absent: $1)"
    fi
}
check_present() { # check_present <pattern> <file> <law>
    if grep -qF -- "$1" "$2"; then
        echo "PASS: $3 (present)"
    else
        echo "FAIL: $3 — required pattern missing: $1"
        FAIL=1
    fi
}

echo "== static law battery: $WF =="
# The abolished caller-controlled contracts must not exist anywhere.
check_absent "client_payload.fetch_url" "$WF" "L2: the caller-selected fetch_url contract is abolished"
check_absent "batch_b64" "$WF" "L1: the caller-selected batch_b64 contract is abolished"
# The enum + allowlist + gate structure must exist.
check_present "types: [ops-exec]" "$WF" "L1: the ops-exec dispatch contract restored under the laws"
check_present "environment: ops-production" "$WF" "the host-mutation approval gate is declared"
check_present "actions/checkout" "$WF" "the operation catalog is checked out, not inlined"
check_present "ops-operations/lib/relay_laws.sh" "$WF" "the workflow sources the single law library"
check_present "construct_asset_url" "$WF" "L2: the URL is server-side constructed only"
check_present "sha256sum -c" "$WF" "L2: the artifact digest is verified"
check_present "verify_scanned_fingerprint" "$WF" "L3: the exact-field fingerprint law is wired"
check_present "seal_envelope" "$WF" "L4: the encrypt-then-MAC seal is wired"
# The operation templates must exist and the fail-closed pair must stay fail-closed.
for op in health_check deploy_release rollback_release; do
    check_present "set -euo pipefail" "ops-operations/${op}.sh" "catalog: ops-operations/${op}.sh is a guarded script"
done
check_present "exit 9" "ops-operations/deploy_release.sh" "catalog: deploy_release stays fail-closed until the owner composes it"
check_present "exit 9" "ops-operations/rollback_release.sh" "catalog: rollback_release stays fail-closed until the owner composes it"

echo "== static law battery: $LIB =="
check_present "OPS_RELAY_PINNED_FETCH_REPO=\"Macrition/Storing-System-Macrition\"" "$LIB" "L2: the pinned origin identity of record"
check_present "grep -qE '^SHA256:[A-Za-z0-9+/]{43}=\$'" "$LIB" "L3: the fingerprint format law"
check_present "hmac-sha256-encrypt-then-mac" "$LIB" "L4: the encrypt-then-MAC envelope of record"
check_present "envelope_version" "$LIB" "L4: versioned envelope metadata"

if [ "$FAIL" -ne 0 ]; then
    echo "== STATIC LAW BATTERY: FAIL =="
    exit 1
fi
echo "== STATIC LAW BATTERY: ALL PASS =="
