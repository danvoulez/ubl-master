# Governance

**Status**: active  
**Owner**: Repo Maintainer  
**Last reviewed**: 2026-02-20

## Purpose

Keep documentation and architecture decisions coherent, auditable, and low-drift.

## Canonical Rules

- One authoritative document per topic.
- `docs/INDEX.md` is the documentation entry point.
- `ARCHITECTURE.md` is normative for system design/invariants.
- `TASKLIST.md` tracks execution status.
- Vision and long-horizon narrative live under `docs/visao/`.

## Update Discipline

- Docs are updated in the same PR as behavior changes.
- Canon, crypto, and runtime-affecting changes must update relevant references.
- All canonical docs should carry metadata headers (`Status`, `Owner`, `Last reviewed`).

## ADR Process

- ADR index: `docs/adr/README.md`
- Naming pattern: `NNNN-title.md`
- Start with context, decision, and consequences.
- Do not rewrite accepted ADR history; supersede with a new ADR.

## Archival Policy

- Superseded strategy/checklist documents move to `docs/archive/YYYY-MM/`.
- Preserve history; avoid deleting context that explains prior decisions.

## Related Documents

- `docs/STANDARDS.md`
- `docs/INDEX.md`
- `docs/adr/0001-DOC-GOVERNANCE.md`
