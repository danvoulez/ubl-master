# Crypto Trust Model

**Status**: active
**Owner**: Security
**Last reviewed**: 2026-02-17

## Objective

Guarantee end-to-end verifiable receipts and rich URLs with deterministic canonical payloads.

## Current Production Default (P0)

- `UBL_CRYPTO_MODE=compat_v1`
- Receipt signing in WF via `UnifiedReceipt::finalize_and_sign`
- Rich URL verification in `shadow` or `strict` mode by flag/scope
- Canonical payload source is NRF bytes (`ubl_canon`)
- Primary production signature algorithm is Ed25519
- PQ dual-sign (`ML-DSA3`) is currently a feature-gated stub (`ubl_kms/pq_mldsa3`):
  wire/API shape exists, PQ signature value is `None` until backend integration

## Signature Domains

- Receipt: `ubl/receipt/v1` (`UBL_SIGN_DOMAIN_RECEIPT`)
- Rich URL: `ubl/rich-url/v1` (constant from `ubl_canon::domains::RICH_URL`)
- Runtime attestation: `ubl/runtime-attestation/v1` (`UBL_SIGN_DOMAIN_RUNTIME_ATTESTATION`)

## Verification Rules

1. Receipt verify recomputes payload from canonical receipt JSON (excluding `sig`).
2. Verify key is derived from `did:key` in receipt.
3. Rich URL verify checks:
   - payload signature
   - CID consistency
   - runtime hash (`rt`) consistency for hosted URLs
4. In `shadow` mode, failures are reported but can be non-blocking.
5. In `strict` mode, failures are fail-closed.

## did:key Interop

- Compat mode accepts legacy raw-32-byte did:key payload.
- Strict mode validates multicodec-ed25519 prefix (`0xED01`) in `did:key:z...`.
- Use `UBL_DIDKEY_FORMAT=strict` for hardened environments.

## Key Rotation Notes

- Signing key source is `SIGNING_KEY_HEX`.
- Receipt auth-chain secret supports overlap via `UBL_STAGE_SECRET_PREV`.
- Operational rotation must preserve verification continuity during overlap windows.
