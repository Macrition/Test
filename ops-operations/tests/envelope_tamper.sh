#!/usr/bin/env bash
# ops-operations/tests/envelope_tamper.sh — the OP-326 envelope integrity battery (issue #830).
#
# Proves the encrypt-then-MAC envelope end to end with a RUN-TIME GENERATED
# fixture passphrase (never committed, masked in the log): the roundtrip
# verifies, a single flipped ciphertext byte is refused, and a wrong-key
# verification is refused.

set -euo pipefail
cd "$(dirname "$0")/.."
source lib/relay_laws.sh

FAIL=0
FIX_PASS="$(openssl rand -hex 24)"
echo "::add-mask::$FIX_PASS"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

printf 'relay output of record — bounded, secret-free diagnostics\nline 2\nline 3\n' > "$WORK/out.log"

echo "== L4: the encrypt-then-MAC envelope =="
if seal_envelope "$WORK/out.log" "$WORK/out.log.enc" "$FIX_PASS"; then
    echo "PASS: env1 the envelope seals"
else
    echo "FAIL: env1 the envelope failed to seal"
    exit 1
fi

if [ -s "$WORK/out.log.enc.mac" ] && [ -s "$WORK/out.log.enc.meta" ]; then
    echo "PASS: env2 the MAC tag and the versioned metadata exist"
else
    echo "FAIL: env2 the MAC tag or the metadata is missing"
    FAIL=1
fi

grep -q '"envelope_version":"op326-etm-v1"' "$WORK/out.log.enc.meta" \
    && echo "PASS: env3 the metadata carries the envelope version of record" \
    || { echo "FAIL: env3 the metadata version is wrong"; FAIL=1; }

if ( verify_envelope "$WORK/out.log.enc" "$WORK/out.log.enc.mac" "$FIX_PASS" ); then
    echo "PASS: env4 the untampered envelope verifies"
else
    echo "FAIL: env4 the untampered envelope must verify"
    FAIL=1
fi

# Flip ONE byte of the ciphertext — the MAC must refuse it.
python3 - "$WORK/out.log.enc" <<'PYEOF'
import sys
p = sys.argv[1]
b = bytearray(open(p, "rb").read())
b[len(b)//2] ^= 0x01
open(p, "wb").write(bytes(b))
PYEOF
if ( verify_envelope "$WORK/out.log.enc" "$WORK/out.log.enc.mac" "$FIX_PASS" ) 2>/dev/null; then
    echo "FAIL: env5 a tampered ciphertext PASSED verification — the integrity law is dead"
    FAIL=1
else
    echo "PASS: env5 a single flipped ciphertext byte is refused (integrity failure, exit 6)"
fi

# Restore the ciphertext, verify with a WRONG passphrase — must refuse.
openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt \
    -in /dev/null -out /dev/null 2>/dev/null || true
printf 'relay output of record — bounded, secret-free diagnostics\nline 2\nline 3\n' > "$WORK/out.log"
seal_envelope "$WORK/out.log" "$WORK/out.log.enc" "$FIX_PASS"
if ( verify_envelope "$WORK/out.log.enc" "$WORK/out.log.enc.mac" "$(printf '%s' "$FIX_PASS" | tr 'a-f' 'A-F')" ) 2>/dev/null; then
    echo "FAIL: env6 a wrong-key verification PASSED"
    FAIL=1
else
    echo "PASS: env6 a wrong-key verification is refused"
fi

# The decrypt side: the sealed envelope decrypts back to the exact plaintext.
# (OP-327 rider: the first attempt's deliberately wrong password source must
# never fall into an INTERACTIVE passphrase prompt — stdin is pinned to
# /dev/null so the arm fails fast into the fallback on every runner, not just
# where stdin is already closed. Semantics unchanged: the first attempt fails,
# the fallback decrypts with the real passphrase, env7 compares the bytes.)
openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 \
    -in "$WORK/out.log.enc" -out "$WORK/out.dec" -pass env:OPS_RELAY_PASS_PASS < /dev/null 2>/dev/null \
    || OPS_RELAY_PASS="$FIX_PASS" openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 \
    -in "$WORK/out.log.enc" -out "$WORK/out.dec" -pass env:OPS_RELAY_PASS
if cmp -s "$WORK/out.log" "$WORK/out.dec"; then
    echo "PASS: env7 the sealed envelope decrypts to the exact plaintext"
else
    echo "FAIL: env7 the decrypt roundtrip diverged"
    FAIL=1
fi

echo "== L4-widening (OP-327): the four sibling relay envelope shapes =="
# Every sibling relay now seals through the SAME law functions; the arms drive
# each relay's exact artifact shape (tarball name, envelope name, sidecars,
# metadata law) with the plaintext REMOVED after sealing — the real artifact
# surface the owner receives is sidecars-only. Per shape: the sidecars exist,
# the versioned metadata law holds, the untampered envelope verifies, a single
# flipped ciphertext byte is refused, a wrong-key verification is refused, and
# the owner's verify-then-decrypt flow returns the byte-exact tarball.
sibling_arm() { # sibling_arm <relay-label> <tarball-name> <envelope-name>
    local relay="$1" tgz="$WORK/$2" enc="$WORK/$3" tar_sha
    printf '%s evidence of record — bounded, secret-free diagnostics\nwidening arm line 2\n' "$relay" > "$WORK/payload.txt"
    tar czf "$tgz" -C "$WORK" payload.txt
    tar_sha="$(sha256sum "$tgz" | awk '{print $1}')"
    if seal_envelope "$tgz" "$enc" "$FIX_PASS"; then :; else
        echo "FAIL: wid-$relay the envelope failed to seal"; FAIL=1; return
    fi
    rm -f "$tgz" "$WORK/payload.txt"
    if [ -s "$enc.mac" ] && [ -s "$enc.meta" ]; then
        echo "PASS: wid-$relay the MAC tag and the versioned metadata exist (sidecars-only surface)"
    else
        echo "FAIL: wid-$relay the sidecars are missing"; FAIL=1; return
    fi
    if grep -q '"envelope_version":"op326-etm-v1"' "$enc.meta"; then
        echo "PASS: wid-$relay the metadata carries the envelope version of record"
    else
        echo "FAIL: wid-$relay the metadata version is wrong"; FAIL=1; return
    fi
    if ( verify_envelope "$enc" "$enc.mac" "$FIX_PASS" ); then
        echo "PASS: wid-$relay the untampered envelope verifies"
    else
        echo "FAIL: wid-$relay the untampered envelope must verify"; FAIL=1; return
    fi
    python3 - "$enc" <<'PYEOF'
import sys
p = sys.argv[1]
b = bytearray(open(p, "rb").read())
b[len(b)//2] ^= 0x01
open(p, "wb").write(bytes(b))
PYEOF
    if ( verify_envelope "$enc" "$enc.mac" "$FIX_PASS" ) 2>/dev/null; then
        echo "FAIL: wid-$relay a tampered ciphertext PASSED verification — the integrity law is dead"
        FAIL=1
    else
        echo "PASS: wid-$relay a single flipped ciphertext byte is refused (exit 6)"
    fi
    printf '%s evidence of record — wrong-key arm\n' "$relay" > "$WORK/payload.txt"
    tar czf "$tgz" -C "$WORK" payload.txt
    seal_envelope "$tgz" "$enc" "$FIX_PASS"
    rm -f "$tgz" "$WORK/payload.txt"
    if ( verify_envelope "$enc" "$enc.mac" "$(printf '%s' "$FIX_PASS" | tr 'a-f' 'A-F')" ) 2>/dev/null; then
        echo "FAIL: wid-$relay a wrong-key verification PASSED"
        FAIL=1
    else
        echo "PASS: wid-$relay a wrong-key verification is refused"
    fi
    printf '%s evidence of record — owner decrypt-flow arm\n' "$relay" > "$WORK/payload.txt"
    tar czf "$tgz" -C "$WORK" payload.txt
    tar_sha="$(sha256sum "$tgz" | awk '{print $1}')"
    seal_envelope "$tgz" "$enc" "$FIX_PASS"
    rm -f "$tgz" "$WORK/payload.txt"
    if ( verify_envelope "$enc" "$enc.mac" "$FIX_PASS" ) \
        && RELAY_PASS="$FIX_PASS" openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 \
            -in "$enc" -out "$tgz" -pass env:RELAY_PASS
    then
        if [ "$(sha256sum "$tgz" | awk '{print $1}')" = "$tar_sha" ]; then
            echo "PASS: wid-$relay the owner verify-then-decrypt flow returns byte-exact evidence"
        else
            echo "FAIL: wid-$relay the decrypted tarball diverged from the sealed bytes"; FAIL=1
        fi
    else
        echo "FAIL: wid-$relay the owner verify-then-decrypt flow failed"; FAIL=1
    fi
    rm -f "$tgz" "$enc" "$enc.mac" "$enc.meta" "$WORK/payload.txt"
}
# The four sibling artifact shapes of record (the relay's own naming laws):
sibling_arm "test-relay" "evidence.tgz" "evidence.tgz.enc"
sibling_arm "tier-a-relay" "evidence.tgz" "evidence.tgz.enc"
sibling_arm "tier-b-relay" "evidence.tgz" "evidence.tgz.enc"
sibling_arm "db-relay(mysql84)" "evidence-mysql84.tgz" "db-relay-mysql84-evidence.enc"

if [ "$FAIL" -ne 0 ]; then
    echo "== ENVELOPE INTEGRITY BATTERY: FAIL =="
    exit 1
fi
echo "== ENVELOPE INTEGRITY BATTERY: ALL PASS =="
