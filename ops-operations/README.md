# ops-operations — the OP-326 operation catalog of record (issue #830)

This directory is the versioned, reviewed replacement for the caller-selected
`batch_b64` shell the Director's issue #830 abolished. Nothing in the relay
executes anything that is not a file in this directory, loaded through the
law library (`lib/relay_laws.sh`) and reached only after the dispatch envelope
and the connection configuration have passed the fail-closed validation.

## Layout

| Path | Role |
| --- | --- |
| `lib/relay_laws.sh` | The single authority for the trust-boundary laws (L1 enum, L2 fetch allowlist, L3 fail-closed config, L4 encrypt-then-MAC). Sourced by the relay AND the battery — no second copy of any law exists. |
| `health_check.sh` | Fully implemented, read-only host diagnostics. |
| `deploy_release.sh` | Enum entry + parameter contract + owner fill-in guidance. Fails closed (exit 9) until the account owner composes the body inside this reviewed template. |
| `rollback_release.sh` | Enum entry + parameter contract + owner fill-in guidance. Fails closed (exit 9) until the account owner composes the body inside this reviewed template. |
| `tests/static_laws.sh` | Structural proof: the abolished contracts are absent, the laws are wired. |
| `tests/runtime_arms.sh` | 29 rejection/acceptance arms + the localhost exfiltration-death proof. |
| `tests/envelope_tamper.sh` | Encrypt-then-MAC roundtrip, single-byte tamper refusal, wrong-key refusal. |

## The dispatch envelope contract (repository_dispatch type `ops-exec`)

| Field | Law | Meaning |
| --- | --- | --- |
| `operation` | L1 | One of `deploy_release`, `health_check`, `rollback_release`. Anything else is refused with exit 2. |
| `fetch_repo` | L2 | Must equal the pinned origin identity (`Macrition/Storing-System-Macrition`). Required only when an asset fetch is requested. |
| `fetch_asset_id` | L2 | Numeric GitHub release asset id. When present, the digest fields become mandatory. |
| `fetch_sha256` | L2 | The 64-hex digest of the artifact — verified against the downloaded bytes BEFORE anything else happens. |
| `fetch_dest` | L2 | Must be `/srv/ops/releases/<name>` — the pinned release root; traversal and separators are refused. |

The old contract (`fetch_url`, `batch_b64`) does not exist anymore: a caller
sending it fails the envelope validation before any secret is read, before any
request is made, and before any host is contacted.

## The evidence-envelope law (the OP-327 widening, issue #830 follow-up)

ALL FIVE relay workflows now seal their evidence through the ONE law library:
`seal_envelope` encrypts (AES-256-CBC + PBKDF2, 200,000 iterations) AND seals
an HMAC-SHA256 integrity tag over the ciphertext plus versioned metadata
(`op326-etm-v1`). `test-relay` / `tier-a-relay` / `tier-b-relay` / `db-relay`
previously sealed with a bare unauthenticated `openssl enc -aes-256-cbc`
construction (tier-a even omitted the 200k KDF parameter its siblings carried)
— that class is abolished: each relay file now sources `lib/relay_laws.sh`,
checks out the law library as its first step, seals through `seal_envelope`,
and uploads the `.enc.mac` + `.enc.meta` sidecars beside the ciphertext. The
widened static + envelope batteries prove the law per file and per artifact
shape (the `wid-*` arms), so the proof cannot drift from the relay.

The owner verify-then-decrypt (each relay's header documents its exact names):

    source ops-operations/lib/relay_laws.sh
    verify_envelope <artifact>.enc <artifact>.enc.mac "$RELAY_PASS"
    RELAY_PASS="$RELAY_PASS" openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 \
      -in <artifact>.enc -out <artifact>.tgz -pass env:RELAY_PASS

A tampered envelope is REFUSED (exit 6) before any parse. The hosted re-proof
of the widened arms rides `ops-relay-negative-tests.yml` (workflow_dispatch)
once the hardening branches are merged to the default branch — the workflow
file must exist on the default branch for the dispatch surface to exist, so
hosted execution is merge-gated (the standing OP-326 disclosure).
