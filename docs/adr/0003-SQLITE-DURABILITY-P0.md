# ADR 0003: SQLite is the P0 Durability Backend

**Status**: accepted
**Date**: 2026-02-17

## Context

Idempotency and outbox required real transactional durability in P0.

## Decision

- Use SQLite with WAL for durable store, idempotency, and outbox.
- Commit `receipts + idempotency + outbox` atomically in one transaction.
- Keep Postgres as P1 evolution path.

## Consequences

- Strong crash consistency with low operational complexity.
- Direct support for replay-safe behavior after restart.
