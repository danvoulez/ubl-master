# Changelog

**Status**: active
**Owner**: Repo Maintainer
**Last reviewed**: 2026-02-17

## 2026-02-17

- Added formal documentation governance:
  - `docs/INDEX.md`
  - `docs/STANDARDS.md`
  - `docs/adr/*`
  - `docs/reference/API.md`
  - `docs/reference/CONFIG.md`
  - `docs/reference/ERRORS.md`
  - `docs/security/CRYPTO_TRUST_MODEL.md`
  - `docs/lifecycle/RELEASE_READINESS.md`
- Archived superseded strategy/checklist/tasklist docs into `docs/archive/2026-02/`.
- Updated canonical entry documents (`README.md`, `ARCHITECTURE.md`, `TASKLIST.md`).

## 2026-02-18

- Closed F4/H6 execution slice (property-testing expansion + typed parse boundary in pipeline critical paths).
- Hardened CI:
  - fixed `KNOCK` output contract handling in GitHub Actions
  - added UNC-1 strict smoke checks under CI (`REQUIRE_UNC1_NUMERIC=true`, `F64_IMPORT_MODE=reject`)
  - added optional `SIMKIT-STX` CI job (auto-skips when `simrunner/main.py` is absent)
- Security dependency upgrades:
  - `ring` -> `0.17.x`
  - `prometheus` -> `0.14.x` (moves protobuf chain to `3.7.2+`)
  - `reqwest` -> `0.12.x`
- `ubl_ledger` no longer exposes no-op public API:
  - default feature `ledger_mem`
  - opt-in feature `ledger_ndjson` append-only persistence backend
- Draft release notes added: `docs/changelog/V0_4_0_RC1.md`.
