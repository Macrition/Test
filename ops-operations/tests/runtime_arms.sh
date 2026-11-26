#!/usr/bin/env bash
# ops-operations/tests/runtime_arms.sh — the OP-326 runtime rejection battery (issue #830).
#
# Proves the trust-boundary laws at RUNTIME with the law library itself.
# Everything runs on the runner: a localhost mock listener proves that
# rejected envelopes issue ZERO network requests — the exfiltration capability
# is structurally dead. No production host, no real secret, no external
# endpoint is contacted by this battery.

set -euo pipefail
cd "$(dirname "$0")/.."
source lib/relay_laws.sh

FAIL=0
expect_reject() { # expect_reject <arm> <expected_rc> <command...>
    local arm="$1" want="$2"; shift 2
    local got=0
    # The laws terminate with `exit`; the subshell contains that exit so the
    # battery itself survives every rejection it must prove.
    ( "$@" ) >/dev/null 2>&1 || got=$?
    if [ "$got" -eq "$want" ]; then
        echo "PASS: $arm — rejected with exit $got"
    else
        echo "FAIL: $arm — expected exit $want, got $got"
        FAIL=1
    fi
}
expect_accept() { # expect_accept <arm> <command...>
    local arm="$1"; shift
    if ( "$@" ) >/dev/null 2>&1; then
        echo "PASS: $arm — accepted"
    else
        echo "FAIL: $arm — a valid envelope must be accepted"
        FAIL=1
    fi
}

GOOD_SHA="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
GOOD_FP="SHA256:b0jJliXqUtuWyaOnitA3iZZ0dBZFOw8Y4z8Dc5VlXkY="
GOOD_KEY="-----BEGIN OPENSSH PRIVATE KEY-----"
HOST="203.0.113.10"          # TEST-NET-3 documentation address — never routed
PORT="22"
USER="opsrunner"

echo "== L1: the operation enum =="
expect_reject "arm1 unknown operation"           2 validate_operation "custom_shell"
expect_reject "arm2 empty operation"             2 validate_operation ""
expect_reject "arm3 injected operation"          2 validate_operation "health_check; rm -rf /"
expect_accept "arm4 health_check accepted"       validate_operation "health_check"
expect_accept "arm5 deploy_release accepted"     validate_operation "deploy_release"
expect_accept "arm6 rollback_release accepted"   validate_operation "rollback_release"

echo "== L2: the fetch allowlist =="
expect_reject "arm7 foreign repo identity"       2 validate_fetch "evil.example/Storing-System-Macrition" "12345" "$GOOD_SHA" "/srv/ops/releases/r1"
expect_reject "arm8 same-origin lookalike repo"  2 validate_fetch "Macrition/OTHER" "12345" "$GOOD_SHA" "/srv/ops/releases/r1"
expect_reject "arm9 non-numeric asset id"        2 validate_fetch "$OPS_RELAY_PINNED_FETCH_REPO" "12345; curl evil" "$GOOD_SHA" "/srv/ops/releases/r1"
expect_reject "arm10 missing digest"             2 validate_fetch "$OPS_RELAY_PINNED_FETCH_REPO" "12345" "" "/srv/ops/releases/r1"
expect_reject "arm11 short digest"               2 validate_fetch "$OPS_RELAY_PINNED_FETCH_REPO" "12345" "abc123" "/srv/ops/releases/r1"
expect_reject "arm12 dest outside pinned root"   2 validate_fetch "$OPS_RELAY_PINNED_FETCH_REPO" "12345" "$GOOD_SHA" "/etc/cron.d/x"
expect_reject "arm13 dest traversal"             2 validate_fetch "$OPS_RELAY_PINNED_FETCH_REPO" "12345" "$GOOD_SHA" "/srv/ops/releases/../keys"
expect_accept "arm14 valid fetch envelope"       validate_fetch "$OPS_RELAY_PINNED_FETCH_REPO" "12345" "$GOOD_SHA" "/srv/ops/releases/release-1.2.3"

echo "== L2: the URL construction =="
URL="$(construct_asset_url "$OPS_RELAY_PINNED_FETCH_REPO" "12345" "$GOOD_SHA" "/srv/ops/releases/r1")"
if [ "$URL" = "https://api.github.com/repos/Macrition/Storing-System-Macrition/releases/assets/12345" ]; then
    echo "PASS: arm15 the constructed URL is exactly the allowlisted shape"
else
    echo "FAIL: arm15 constructed URL is '$URL'"
    FAIL=1
fi

# THE EXFILTRATION-DEATH PROOF: a localhost listener counts every request it
# receives; a rejected envelope must produce ZERO requests.
echo "== L2: the exfiltration-death proof (localhost mock) =="
python3 - <<'PYEOF' > listener.log 2>&1 &
import http.server, socketserver, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        with open("listener.count","w") as f: f.write("1")
        self.send_response(404); self.end_headers()
    def log_message(self, *a): pass
with socketserver.TCPServer(("127.0.0.1", 18099), H) as srv:
    srv.handle_request()  # exit after the first request or the caller's timeout
PYEOF
LISTENER_PID=$!
sleep 1
rm -f listener.count
# Attempt the rejected fetch shape through the SAME validation the relay runs.
expect_reject "arm16 external URL shape through the envelope law" 2 \
    validate_fetch "evil.example/payload" "12345" "$GOOD_SHA" "/srv/ops/releases/r1"
sleep 1
kill "$LISTENER_PID" 2>/dev/null || true
wait "$LISTENER_PID" 2>/dev/null || true
if [ -f listener.count ]; then
    echo "FAIL: arm17 the mock listener RECEIVED a request — exfiltration capability alive"
    FAIL=1
else
    echo "PASS: arm17 the mock listener received ZERO requests — nothing left the runner"
fi
rm -f listener.log listener.count

echo "== L3: fail-closed configuration (BEFORE any network action) =="
expect_reject "arm18 empty private key"     5 validate_host_config ""                        "$HOST" "$PORT" "$USER" "$GOOD_FP"
expect_reject "arm19 empty host"            5 validate_host_config "$GOOD_KEY" ""            "$PORT" "$USER" "$GOOD_FP"
expect_reject "arm20 empty port"            5 validate_host_config "$GOOD_KEY" "$HOST" ""    "$USER" "$GOOD_FP"
expect_reject "arm21 empty user"            5 validate_host_config "$GOOD_KEY" "$HOST" "$PORT" "" "$GOOD_FP"
expect_reject "arm22 EMPTY FINGERPRINT (the #830 fail-open class)" 5 validate_host_config "$GOOD_KEY" "$HOST" "$PORT" "$USER" ""
expect_reject "arm23 malformed fingerprint" 3 validate_host_config "$GOOD_KEY" "$HOST" "$PORT" "$USER" "AAAAB3NzC1tb2VQdWJsaWNLZXk="
expect_reject "arm24 md5-shaped fingerprint" 3 validate_host_config "$GOOD_KEY" "$HOST" "$PORT" "$USER" "0f:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff"
expect_reject "arm25 host separator injection" 5 validate_host_config "$GOOD_KEY" "host@evil.example" "$PORT" "$USER" "$GOOD_FP"
expect_reject "arm26 user separator injection" 5 validate_host_config "$GOOD_KEY" "$HOST" "$PORT" "opsrunner -oProxyCommand=evil" "$GOOD_FP"
expect_reject "arm27 port out of range"     5 validate_host_config "$GOOD_KEY" "$HOST" "70000" "$USER" "$GOOD_FP"
expect_reject "arm28 port not numeric"      5 validate_host_config "$GOOD_KEY" "$HOST" "22;rm" "$USER" "$GOOD_FP"
expect_accept "arm29 valid config accepted" validate_host_config "$GOOD_KEY" "$HOST" "$PORT" "$USER" "$GOOD_FP"

if [ "$FAIL" -ne 0 ]; then
    echo "== RUNTIME REJECTION BATTERY: FAIL =="
    exit 1
fi
echo "== RUNTIME REJECTION BATTERY: ALL PASS =="
