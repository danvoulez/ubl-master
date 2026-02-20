# START-HERE (LLM + Human Operators)

If you change this repository, preserve canonical contracts first.

## Non-Negotiable Canonical Contracts

1. **Universal Envelope is mandatory**
- Required anchors: `@id`, `@type`, `@ver`, `@world`.
- Source: `ARCHITECTURE.md` (canon sections).

2. **Canonicalization (rho) must stay deterministic**
- NFC normalization, key-order determinism, null stripping in maps, duplicate-key rejection.
- Sources: `crates/rb_vm/src/canon.rs`, `kats/rho_vectors/`.

3. **NRF-1 bytes are canonical hash/sign input**
- Same canonical input => same bytes => same chip CID (`b3:`).
- Sources: `crates/ubl_ai_nrf1/src/nrf.rs`, `crates/ubl_ai_nrf1/src/chip_format.rs`.

4. **UNC-1 numeric canon only**
- No raw float in canonical payload path.
- Sources: `docs/canon/UNC-1.md`, `schemas/unc-1.schema.json`, `docs/vm/OPCODES_NUM.md`.

5. **Pipeline order is canonical**
- `KNOCK -> WA -> CHECK -> TR -> WF`; no side-path mutation.
- Sources: `ARCHITECTURE.md`, `crates/ubl_runtime/src/pipeline/`.

6. **Determinism boundary must not be blurred**
- Chip CID is content-deterministic.
- Receipt CID is event/context-specific (time/nonce/runtime context).
- Sources: `ARCHITECTURE.md` PF-01/PF-02 sections.

7. **Time handling discipline**
- Never inject wall-clock into chip canonical hash input.
- Runtime time belongs to execution proof (receipts), not chip content CID.

8. **Policy immutability and lock discipline**
- Policy context must remain explicit and versioned.
- Sources: `crates/ubl_runtime/src/policy_lock.rs`, `ROLLOUT_P0_TO_P1.md`.

9. **Crypto domains and verification are canonical**
- Domain-separated signatures and strict verification rules.
- Sources: `SECURITY.md`, `crates/ubl_receipt/src/unified.rs`, `crates/ubl_runtime/src/rich_url.rs`.

10. **Error taxonomy is contract, not prose**
- Source of truth: `crates/ubl_runtime/src/error_response.rs`.

## Where Full Canon Lives

- Exhaustive reference: `docs/canon/CANON-REFERENCE.md`
- Numeric canon: `docs/canon/UNC-1.md`
- Canon quickstart: `docs/canon/START-HERE-CANON.md`

## Final Rule

If in doubt, read `ARCHITECTURE.md`.
It is dense and imperfect in places, but it is still the best system map.
