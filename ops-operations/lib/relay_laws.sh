#!/usr/bin/env bash
# ops-operations/lib/relay_laws.sh — the OP-326 law library of record (issue #830).
#
# The single authority for every trust-boundary law of the hardened ops relay.
# The workflow steps AND the negative security battery source THIS file — there
# is no second copy of any law, so the battery can never drift from the relay.
#
# Laws implemented here (each maps to a Director finding in issue #830):
#   L1 operation enum        — caller-selected base64 shell batches are abolished;
#                              only the versioned operation catalog executes.
#   L2 fetch allowlist       — the privileged PAT is never sent to a
#                              caller-selected URL. The URL is CONSTRUCTED
#                              server-side from validated fields against the
#                              pinned origin identity, and the artifact digest
#                              is mandatory.
#   L3 fail-closed config    — every required secret must be present and
#                              well-formed BEFORE any network or SSH action;
#                              an empty or malformed fingerprint can never
#                              match anything (the grep -qF "" fail-open class
#                              is abolished — exact-field equality only).
#   L4 encrypt-then-MAC      — the output envelope carries an HMAC-SHA256
#                              integrity tag over the ciphertext; the reader
#                              verifies before parsing.
#
# Sourcing this file has NO side effects: every law is a function.
# Nothing here ever prints a secret value.

# ---------------------------------------------------------------------------
# L1 — the operation enum (the versioned, audited execution catalog)
# ---------------------------------------------------------------------------
OPS_RELAY_OPERATIONS="deploy_release health_check rollback_release"

validate_operation() {
    case "${1:-}" in
        deploy_release|health_check|rollback_release)
            return 0
            ;;
        *)
            echo "REJECTED: unknown operation '${1:-<empty>}'" >&2
            echo "The enum of record is: ${OPS_RELAY_OPERATIONS}" >&2
            echo "Caller-selected shell was abolished at OP-326 (issue #830)." >&2
            return 2
            ;;
    esac
}

# ---------------------------------------------------------------------------
# L2 — the fetch allowlist (origin identity pinned HERE, never caller-chosen)
# ---------------------------------------------------------------------------
OPS_RELAY_PINNED_FETCH_REPO="Macrition/Storing-System-Macrition"
OPS_RELAY_ASSET_URL_PREFIX="https://api.github.com/repos/${OPS_RELAY_PINNED_FETCH_REPO}/releases/assets/"

relay_die() { # relay_die <message> <exit_code>
    echo "REJECTED: $1" >&2
    exit "${2:-2}"
}

validate_fetch() { # validate_fetch <repo> <asset_id> <sha256> <dest>
    [ "${1:-}" = "$OPS_RELAY_PINNED_FETCH_REPO" ] \
        || relay_die "fetch_repo '${1:-<empty>}' is not the pinned origin identity (${OPS_RELAY_PINNED_FETCH_REPO})" 2
    case "${2:-}" in
        ''|*[!0-9]*) relay_die "fetch_asset_id is missing or not numeric" 2 ;;
    esac
    printf '%s' "${3:-}" | grep -qE '^[0-9a-f]{64}$' \
        || relay_die "fetch_sha256 is missing or malformed — the artifact digest is mandatory (64 lowercase hex)" 2
    case "${4:-}" in *..*) relay_die "fetch_dest contains a path-traversal segment" 2 ;; esac
    printf '%s' "${4:-}" | grep -qE '^/srv/ops/releases/[A-Za-z0-9][A-Za-z0-9._-]*$' \
        || relay_die "fetch_dest is outside the pinned release root /srv/ops/releases/<name>" 2
    return 0
}

# The ONLY place a fetch URL comes into existence. Constructed from validated
# fields — never accepted as a string from the caller.
construct_asset_url() { # construct_asset_url <repo> <asset_id> <sha256> <dest>
    validate_fetch "$1" "$2" "$3" "$4" || return $?
    printf '%s%s' "$OPS_RELAY_ASSET_URL_PREFIX" "$2"
}

# ---------------------------------------------------------------------------
# L3 — fail-closed host configuration (validated BEFORE any network action)
# ---------------------------------------------------------------------------
validate_host_config() { # validate_host_config <key_pem> <host> <port> <user> <fingerprint>
    local v
    for v in "$@"; do
        [ -n "$v" ] || relay_die "required connection secret is EMPTY — fail closed (the fail-open empty-fingerprint class is abolished)" 5
    done
    case "$2" in
        *[/:@]*) relay_die "SSH host contains an injected separator (/ : @) — not a bare host" 5 ;;
    esac
    # Strict charset allowlists (not denylists): a hostname is letters, digits
    # and dots; a username is a POSIX-safe name. Spaces, option-like shapes and
    # separators can never reach the ssh/scp command line.
    printf '%s' "$2" | grep -qE '^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$' \
        || relay_die "SSH host is not a bare hostname — fail closed" 5
    printf '%s' "$4" | grep -qE '^[A-Za-z_][A-Za-z0-9._-]{0,31}$' \
        || relay_die "SSH user is not a plain username — fail closed" 5
    printf '%s' "$3" | grep -qE '^[0-9]{1,5}$' || relay_die "SSH port is not a valid port number" 5
    [ "$3" -ge 1 ] && [ "$3" -le 65535 ] || relay_die "SSH port out of range" 5
    printf '%s' "$5" | grep -qE '^SHA256:[A-Za-z0-9+/]{43}=$' \
        || relay_die "host fingerprint is not SHA256:<43 base64 chars>= format — fail closed" 3
    return 0
}

# The fingerprint law: EXACT equality on the EXTRACTED fingerprint field of the
# scanned key — never a substring search over the whole scan (the grep -qF ""
# empty-pattern fail-open class of issue #830 is structurally impossible here).
verify_scanned_fingerprint() { # verify_scanned_fingerprint <scanned_file> <expected_fp>
    [ -s "$1" ] || relay_die "host scan produced no keys — fail closed" 4
    local scanned_fp
    scanned_fp="$(ssh-keygen -lf "$1" 2>/dev/null | awk '{print $2}')"
    [ -n "$scanned_fp" ] || relay_die "could not extract the scanned fingerprint — fail closed" 3
    [ "$scanned_fp" = "$2" ] || relay_die "HOST KEY MISMATCH — abort" 3
    return 0
}

# ---------------------------------------------------------------------------
# L4 — the encrypt-then-MAC output envelope
# ---------------------------------------------------------------------------
OPS_RELAY_ENVELOPE_VERSION="op326-etm-v1"
OPS_RELAY_MAC_LABEL="ops-relay-mac-v1"

seal_envelope() { # seal_envelope <plaintext_in> <enc_out> <passphrase>
    local in="$1" out="$2" pass="$3"
    [ -s "$in" ] || printf '(no output produced)\n' > "$in"
    OPS_RELAY_PASS="$pass" openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt \
        -in "$in" -out "$out" -pass env:OPS_RELAY_PASS
    # HMAC-SHA256 over the CIPHERTEXT, keyed with a domain-separated derivation
    # of the envelope passphrase (encrypt-then-MAC; the unauthenticated
    # AES-CBC-only envelope of issue #830 is abolished).
    openssl dgst -sha256 -hmac "$(printf '%s|%s' "$OPS_RELAY_MAC_LABEL" "$pass")" -binary "$out" \
        | base64 -w0 > "${out}.mac"
    printf '{"envelope_version":"%s","cipher":"aes-256-cbc-pbkdf2-200000","mac":"hmac-sha256-encrypt-then-mac","created_utc":"%s"}\n' \
        "$OPS_RELAY_ENVELOPE_VERSION" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" > "${out}.meta"
}

verify_envelope() { # verify_envelope <enc_file> <mac_file> <passphrase>
    local computed expected
    [ -s "$1" ] && [ -s "$2" ] || relay_die "envelope or mac file missing/empty — fail closed" 6
    computed="$(openssl dgst -sha256 -hmac "$(printf '%s|%s' "$OPS_RELAY_MAC_LABEL" "$3")" -binary "$1" | base64 -w0)"
    expected="$(cat "$2")"
    [ "$computed" = "$expected" ] \
        || relay_die "ENVELOPE INTEGRITY FAILURE — the ciphertext does not match its MAC; refusing to parse" 6
    return 0
}
