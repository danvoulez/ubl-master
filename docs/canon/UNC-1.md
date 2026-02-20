# UNC-1 — UBL Numeric Canon v1

**Status**: Spec — ready for implementation
**Date**: February 16, 2026
**Spec**: [ARCHITECTURE.md](../../ARCHITECTURE.md) — engineering source of truth

---

## 1. Core Idea

Never hash or sign a binary `float`. Every number becomes a **canonical atom** with stable bytes and zero ambiguity:

| Kind | Tag | Fields | Example |
|---|---|---|---|
| **INT** | `int/1` | `v` (string bigint) | `{ "@num": "int/1", "v": "-42" }` |
| **DEC** | `dec/1` | `m` (mantissa string), `s` (scale u32) | `{ "@num": "dec/1", "m": "12345", "s": 3 }` → 12.345 |
| **RAT** | `rat/1` | `p` (numerator string), `q` (denominator string, >0) | `{ "@num": "rat/1", "p": "22", "q": "7" }` |
| **BND** | `bnd/1` | `lo` (Num), `hi` (Num) where `lo ≤ hi` | `{ "@num": "bnd/1", "lo": ..., "hi": ... }` |

- **Unit** (`u`): optional string field on any kind (e.g. `"USD"`, `"kg"`, `"m"`, `"s"`). Outside the value, but bound to the atom.
- **Rounding Mode** (`rm`): explicit at the **operation site** (never in the data). Default `HALF_EVEN`.

This separates **representation** from **rounding policy**. The data is pure; the policy belongs to the pipeline/VM.

---

## 2. JSON Form (readable) and NRF-1 Bytes (canonical)

```json
{ "@num": "dec/1", "m": "12345", "s": 3, "u": "USD" }
{ "@num": "int/1", "v": "-42" }
{ "@num": "rat/1", "p": "22", "q": "7" }
{ "@num": "bnd/1", "lo": { "@num": "dec/1", "m": "1", "s": 1 },
                   "hi": { "@num": "dec/1", "m": "2", "s": 1 } }
```

- Strings for `m`, `p`, `q`, `v` avoid precision loss (bigint).
- Key ordering and NRF-1 normalization guarantee **same CID on any machine**.
- `@num` signals the kind and schema version.
- NRF-1 encodes UNC-1 atoms as **MAP** — zero changes to the encoding layer.

---

## 3. IEEE-754 Frontier (safe import)

When a `float` arrives (from API/adapter/WASM), convert deterministically to UNC-1:

| Source | Conversion | Result |
|---|---|---|
| Decimal literal string (`"12.34"`) | Parse exact | **DEC** (`m=1234, s=2`) |
| Binary IEEE-754 (`f64`) | Derive exact interval of binary rounding | **BND** minimal `[lo, hi]` |
| `NaN`, `±Inf` | Reject | Error `NUMERIC_VALUE_INVALID` |

Every `f64` has a deterministic minimal decimal interval that contains it. The **imprecision becomes explicit** in BND; nothing "mysterious" enters the canon.

---

## 4. Deterministic Arithmetic (RB-VM / WASM host)

Operations defined by lifting over {INT, DEC, RAT, BND}:

| Operation | Rule |
|---|---|
| **INT ⊕ INT** | INT exact (bigint) |
| **DEC ⊕ DEC** (same unit) | DEC exact, aligning `scale` |
| **RAT ⊕ RAT** | RAT reduced (gcd) |
| **Mix** (e.g. DEC + RAT) | Promote to higher fidelity: `INT → DEC → RAT → BND` |
| **BND arithmetic** | Interval arithmetic with **directed rounding**: `lo` rounds DOWN, `hi` rounds UP |

**Rounding mode** only appears when **collapsing** a richer form to DEC:
`to_dec(value, scale, rm)` — always explicit.

---

## 5. Units and Coercion

- Field `"u"` is optional on INT/DEC/RAT/BND.
- Operations **require unit compatibility**:
  - `USD + USD` → ok
  - `USD + EUR` → error (or requires explicit rate as RAT)
  - `m/s × s` → coercion via dimensional analysis rules (future module)
- Policy can enforce `"u"` as mandatory in certain domains (finance, measurement).

---

## 6. Pipeline Integration

### KNOCK (validation)

Reject: raw `float`, `NaN/Inf`, malformed `@num` objects, conflicting units.

### CHECK (policy)

Policies can enforce:
- `max_scale` per field
- `max_denominator` for RAT
- `max_width` for BND (`hi - lo`)
- `require_unit` per domain

### TR (RB-VM opcodes)

New opcodes — 100% deterministic:

| Opcode | Signature | Description |
|---|---|---|
| `num.from_decimal_str` | `string → dec/1` | Parse decimal literal |
| `num.from_f64_bits` | `u64 → bnd/1` | Import IEEE-754 as minimal interval |
| `num.add` | `num, num → num` | Add with promotion |
| `num.sub` | `num, num → num` | Subtract with promotion |
| `num.mul` | `num, num → num` | Multiply with promotion |
| `num.div` | `num, num → num` | Divide with promotion |
| `num.to_dec` | `num, scale: u32, rm: u8 → dec/1` | Collapse to decimal |
| `num.to_rat` | `num, limit_den: u64 → rat/1` | Collapse to rational |
| `num.with_unit` | `num, string → num` | Attach unit (error if mismatch) |
| `num.assert_unit` | `num, string → num` | Verify unit (error if wrong/missing) |
| `num.compare` | `num, num → int/1 {-1,0,1}` | Deterministic comparison with promotion |
| `num.bound` | `num, width, rm → bnd/1` | Tighten interval per policy |

Rounding modes: `0=HALF_EVEN, 1=DOWN, 2=UP, 3=HALF_UP, 4=FLOOR, 5=CEIL`

### WF (receipts)

Receipts carry **kind** and **unit** in diffs for accounting traceability.

---

## 7. Developer Ergonomics

- **Sugar literals** (human-writable, still canonical):
  `"@num:12.345 USD"` → parser → `{ "@num":"dec/1", "m":"12345", "s":3, "u":"USD" }`
- Stable formatters (`HALF_EVEN` default) for rendering DEC/RAT/BND.
- SDK helpers (TS/Rust/Python): **never** expose `f64`; always `UNC-1`.

---

## 8. Migration Strategy

| Phase | Description | Flag |
|---|---|---|
| **Compat** | Accept JSON numbers; convert to DEC/BND; emit deprecation in receipt | `F64_IMPORT_MODE=bnd` |
| **Enforce** | Reject raw JSON numbers; only `@num` objects accepted | `REQUIRE_UNC1_NUMERIC=true` |
| **Cleanup** | TR task rewrites old payloads to `@num` (CIDs change — plan carefully) | — |

---

## 9. KATs (Known Answer Tests)

| Test | Input | Operation | Expected |
|---|---|---|---|
| Import f64 `0.1` | `0x3fb999999999999a` (bits) | `from_f64_bits` | `bnd/1` with exact decimal bounds |
| DEC addition | `0.1 DEC + 0.2 DEC` | `add` | `0.3 DEC` |
| RAT to DEC (DOWN) | `1/3 RAT` | `to_dec(scale=2, rm=DOWN)` | `0.33 DEC` |
| RAT to DEC (UP) | `1/3 RAT` | `to_dec(scale=2, rm=UP)` | `0.34 DEC` |
| BND addition | `[0.1,0.2] + [0.2,0.3]` | `add` | `[0.3, 0.5]` (directed rounding) |
| Unit mismatch | `10 USD + 5 EUR` | `add` | Error (no rate provided) |
| Mixed promotion | `2.5 DEC × 2 INT` | `mul` | `5.0 DEC` |

---

## 10. Why This Closes the Account

- **Strong determinism**: stable NRF-1 bytes, no IEEE-754 in canon.
- **Error transparency**: all imprecision becomes a visible **interval** (BND).
- **Exactness when possible**: DEC for finance, RAT for technical fractions, INT for counts.
- **Universal interop**: frontier with binary floats is **fully deterministic**.
- **Auditability**: receipts show kind/unit/rounding — nothing implicit.

---

## 11. Layer Integration

UNC-1 fits into the existing stack without modifying NRF-1 or the Envelope:

```
Layer 3 — Canon (NRF-1)     encodes UNC-1 atoms as MAP (no changes)
Layer 2 — Envelope           @type/@id/@ver/@world anchors (no changes)
Layer 1 — Numeric Canon      UNC-1 types live HERE — in the data payload
Layer 0 — Pipeline           KNOCK validates, CHECK enforces policy, TR computes
```

- **Envelope** (`envelope.rs`): unchanged — anchors are metadata, UNC-1 is payload data.
- **NRF-1** (`nrf.rs`): unchanged — UNC-1 atoms are JSON objects (maps), encoded deterministically.
- **chip_format.rs**: add `normalize_numbers_to_unc1(json)` step before `to_nrf1_bytes`.
- **Pipeline**: KNOCK rejects invalid `@num`; CHECK enforces numeric policy; TR uses `num.*` opcodes.

---

## 12. Schema

JSON Schema: [`schemas/unc-1.schema.json`](../../schemas/unc-1.schema.json)

Rust crate: [`crates/ubl_unc1/`](../../crates/ubl_unc1/) — `Num` enum with `int/1`, `dec/1`, `rat/1`, `bnd/1` variants.

---

## 13. Practical Limits (DoS prevention)

| Limit | Suggested Default | Configurable By |
|---|---|---|
| `max_decimal_digits` | 100 | Policy per tenant |
| `max_denominator` | 10^6 | Policy per tenant |
| `max_interval_width` | 10^6 (relative) | Policy per tenant |
| `max_scale` | 18 (finance) / 38 (scientific) | Policy per field |

---

*The pattern: UNC-1 numbers are just chips with `@num` instead of `@type`. Same canon, same CID, same pipeline. The leverage is already there.*
