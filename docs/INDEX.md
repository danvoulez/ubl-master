# UBL Documentation Index

This is the entry point for all project documentation.

**Status**: active
**Owner**: Repo Maintainer
**Last reviewed**: 2026-02-17

## Sources of Truth

| Topic | Canonical document | Owner | Status |
|---|---|---|---|
| System design and invariants | `ARCHITECTURE.md` | Core Runtime | Active |
| Execution plan and delivery status | `TASKLIST.md` | Core Runtime | Active |
| Bootstrap/rollout policy flow | `ROLLOUT_P0_TO_P1.md` | Ops + Security | Active |
| Certified Runtime conceptual addendum | `ADDENDUM_CERTIFIED_RUNTIME.md` | Core Runtime | Active (complementary) |
| Operational runbooks | `docs/ops/` | Ops | Active |
| Numeric canon | `UNC-1.md` + `schemas/unc-1.schema.json` + `kats/unc1/unc1_kats.v1.json` | Core Runtime | Active |
| API contract | `docs/reference/API.md` | Gate | Active |
| Environment/config flags | `docs/reference/CONFIG.md` | Runtime + Gate | Active |
| Error taxonomy | `docs/reference/ERRORS.md` | Runtime | Active |
| Crypto trust model | `docs/security/CRYPTO_TRUST_MODEL.md` | Security | Active |
| Release gates | `docs/lifecycle/RELEASE_READINESS.md` | Core Runtime + Ops | Active |
| Change history | `docs/changelog/CHANGELOG.md` | Repo Maintainer | Active |

## Governance

- Documentation standards: `docs/STANDARDS.md`
- ADR process: `docs/adr/README.md`
- Archived/superseded docs: `docs/archive/`

## High-Signal Reading Order

1. `README.md`
2. `ARCHITECTURE.md`
3. `TASKLIST.md`
4. `docs/reference/API.md`
5. `docs/reference/CONFIG.md`
6. `docs/security/CRYPTO_TRUST_MODEL.md`
7. `docs/ops/INCIDENT_RUNBOOK.md`
8. `docs/lifecycle/RELEASE_READINESS.md`
