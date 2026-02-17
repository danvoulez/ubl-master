# Configuration Reference

**Status**: active
**Owner**: Runtime + Gate
**Last reviewed**: 2026-02-17

This file lists runtime flags used by the current implementation.

## Core Security and Signing

| Variable | Default | Scope | Purpose |
|---|---|---|---|
| `SIGNING_KEY_HEX` | generated in dev if missing | runtime | Ed25519 signing key seed (32 bytes hex). |
| `UBL_CRYPTO_MODE` | `compat_v1` | runtime + rich URL verify | Signature mode: `compat_v1` or `hash_first_v2`. |
| `UBL_CRYPTO_V2_ENFORCE` | `false` | runtime + rich URL verify | Enforce dual-verify behavior for v2 hash-first. |
| `UBL_CRYPTO_V2_ENFORCE_SCOPES` | empty | runtime + rich URL verify | Per scope enforcement list (`app/tenant`, wildcards accepted). |
| `UBL_SIGN_DOMAIN_RECEIPT` | `ubl/receipt/v1` | receipt signing | Domain separator for unified receipt signatures. |
| `UBL_SIGN_DOMAIN_RUNTIME_ATTESTATION` | `ubl/runtime-attestation/v1` | runtime attestation | Domain separator for runtime self-attestation signatures. |
| `UBL_DIDKEY_FORMAT` | compat | kms | `strict` enables strict multicodec did:key generation. |

## Receipt Auth Chain / Runtime Metadata

| Variable | Default | Scope | Purpose |
|---|---|---|---|
| `UBL_STAGE_SECRET` | process-local derived value | receipt | Required stage-chain secret (set explicitly in staging/prod). |
| `UBL_STAGE_SECRET_PREV` | unset | receipt | Previous secret for key rotation grace verification. |
| `UBL_RUNTIME_ENV_LABELS` | empty | receipt runtime info | CSV `k=v` labels injected into receipt `rt.env`. |
| `UBL_RUNTIME_ENV_*` | empty | receipt runtime info | Prefix-based env labels for receipt `rt.env`. |
| `UBL_RUNTIME_CERTS` | empty | receipt runtime info | CSV `k=v` refs injected into receipt `rt.certs`. |
| `UBL_RUNTIME_CERT_*` | empty | receipt runtime info | Prefix-based cert refs for receipt `rt.certs`. |

## Rich URL Verification

| Variable | Default | Scope | Purpose |
|---|---|---|---|
| `UBL_RICHURL_VERIFY_MODE` | `shadow` | runtime | `shadow` logs soft-fail; `strict` fails closed. |
| `UBL_RICHURL_STRICT_SCOPES` | empty | runtime | Per scope strict mode (`app/tenant`, wildcards accepted). |

## Durable Store / Outbox (SQLite)

| Variable | Default | Scope | Purpose |
|---|---|---|---|
| `UBL_STORE_BACKEND` | `memory` | runtime | Set `sqlite` to enable durable transaction boundary. |
| `UBL_STORE_DSN` | `file:./data/ubl.db?mode=rwc&_journal_mode=WAL` | runtime | Primary SQLite DSN for durable store. |
| `UBL_IDEMPOTENCY_DSN` | fallback to `UBL_STORE_DSN` | runtime | Optional explicit idempotency DSN. |
| `UBL_OUTBOX_DSN` | fallback to `UBL_STORE_DSN` | runtime | Optional explicit outbox DSN. |
| `UBL_OUTBOX_WORKERS` | `1` | gate | Number of outbox worker loops in gate process. |

## Transition Registry

| Variable | Default | Scope | Purpose |
|---|---|---|---|
| `UBL_TR_BYTECODE_MAP_JSON` | empty | runtime TR | JSON map `@type -> hex bytecode` override. |
| `UBL_TR_PROFILE_MAP_JSON` | empty | runtime TR | JSON map `@type -> profile` override (`pass_v1`, `audit_v1`). |

## Miscellaneous

| Variable | Default | Scope | Purpose |
|---|---|---|---|
| `REGISTRY_BASE_URL` | `http://localhost:3000` | config crate | Base URL used by `ubl_config`. |
| `RUST_LOG` | internal default filter | gate | Controls tracing verbosity. |

## Staging/Prod Minimum

```env
UBL_STORE_BACKEND=sqlite
UBL_STORE_DSN=file:./data/ubl.db?mode=rwc&_journal_mode=WAL
UBL_OUTBOX_WORKERS=2
UBL_CRYPTO_MODE=compat_v1
UBL_RICHURL_VERIFY_MODE=shadow
UBL_STAGE_SECRET=hex:<32-byte-hex>
SIGNING_KEY_HEX=<32-byte-hex>
```
