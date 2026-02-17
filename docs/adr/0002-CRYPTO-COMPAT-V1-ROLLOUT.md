# ADR 0002: Crypto Rollout Default is compat_v1

**Status**: accepted
**Date**: 2026-02-17

## Context

The system requires cryptographic closure without breaking existing integrations.

## Decision

- Production default remains `UBL_CRYPTO_MODE=compat_v1` in P0.
- v2 hash-first runs in shadow/enforce by flags and scope.
- Rollout progression is shadow -> dual-verify -> strict.

## Consequences

- Safe migration with measurable divergence.
- Legacy compatibility preserved while hardening trust guarantees.
