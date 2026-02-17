# ADR 0001: Documentation Governance and Canonical Sources

**Status**: accepted
**Date**: 2026-02-17

## Context

The repository had overlapping planning and strategy documents with conflicting status statements.

## Decision

- Adopt `docs/INDEX.md` as entry point.
- Keep one authoritative document per topic.
- Move non-canonical/legacy strategy docs to `docs/archive/YYYY-MM/`.
- Enforce metadata headers and update-in-same-PR discipline.

## Consequences

- Lower documentation drift.
- Faster onboarding and auditability.
- Historical context preserved without polluting implementation guidance.
