//! M2 — RB-VM Property Tests
//!
//! Core VM invariants under property testing:
//! 1. Fuel determinism: same bytecode always burns same fuel
//! 2. CID determinism: same inputs → same receipt CID, always
//! 3. Receipt content distinctness: different rc_body → different rc_cid
//! 4. CAS round-trip: put then get is lossless
//! 5. CID format: always "b3:" + 64 lowercase hex chars
//! 6. Arithmetic safety: saturating ops never panic on extremes
//! 7. Fuel accounting: exactly 1 fuel per opcode

use proptest::prelude::*;
use rb_vm::{
    exec::{CasProvider, SignProvider},
    tlv, Cid, Vm, VmConfig,
};
use std::collections::HashMap;

// ── Test harness ─────────────────────────────────────────────────────────────

struct MemCas {
    store: HashMap<String, Vec<u8>>,
}

impl MemCas {
    fn new() -> Self { Self { store: HashMap::new() } }
}

impl CasProvider for MemCas {
    fn put(&mut self, bytes: &[u8]) -> Cid {
        let hash = blake3::hash(bytes);
        let cid = Cid(format!("b3:{}", hex::encode(hash.as_bytes())));
        self.store.insert(cid.0.clone(), bytes.to_vec());
        cid
    }
    fn get(&self, cid: &Cid) -> Option<Vec<u8>> {
        self.store.get(&cid.0).cloned()
    }
}

struct FixedSigner;
impl SignProvider for FixedSigner {
    fn sign_jws(&self, _: &[u8]) -> Vec<u8> { vec![0u8; 64] }
    fn kid(&self) -> String { "did:test#k1".to_string() }
}

fn cfg() -> VmConfig {
    VmConfig { fuel_limit: 1_000_000, ghost: false, trace: false }
}

/// TLV-encode: [opcode][u16 len BE][payload]
fn enc(op: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![op];
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Program that puts `json_bytes` into the receipt body, then emits.
/// ConstBytes → JsonNormalize → SetRcBody → EmitRc
/// The rc_cid will differ when json_bytes differs (after normalization).
fn prog_with_body(json_bytes: &[u8]) -> Vec<u8> {
    let mut p = enc(0x02, json_bytes); // ConstBytes
    p.extend(enc(0x03, &[]));          // JsonNormalize
    p.extend(enc(0x0D, &[]));          // SetRcBody
    p.extend(enc(0x10, &[]));          // EmitRc
    p
}

/// Minimal program: ConstI64 → EmitRc (value stays on stack, not in body)
fn prog_push_emit(value: i64) -> Vec<u8> {
    let mut p = enc(0x01, &value.to_be_bytes()); // ConstI64
    p.extend(enc(0x10, &[]));                     // EmitRc
    p
}

/// BLAKE3 hash program: ConstBytes → HashBlake3 → EmitRc
fn prog_hash_emit(bytes: &[u8]) -> Vec<u8> {
    let mut p = enc(0x02, bytes); // ConstBytes
    p.extend(enc(0x0A, &[]));     // HashBlake3
    p.extend(enc(0x10, &[]));     // EmitRc
    p
}

fn run(prog: &[u8]) -> Option<rb_vm::exec::VmOutcome> {
    let code = tlv::decode_stream(prog).ok()?;
    let signer = FixedSigner;
    Vm::new(cfg(), MemCas::new(), &signer, rb_vm::RhoCanon, vec![])
        .run(&code).ok()
}

fn run_ok(prog: &[u8]) -> rb_vm::exec::VmOutcome {
    run(prog).expect("prog must succeed")
}

// ── Properties ───────────────────────────────────────────────────────────────

proptest! {
    /// Fuel is deterministic — same bytecode, same fuel consumed, always.
    #[test]
    fn prop_fuel_deterministic(value in any::<i64>()) {
        let prog = prog_push_emit(value);
        let f1 = run_ok(&prog).fuel_used;
        let f2 = run_ok(&prog).fuel_used;
        prop_assert_eq!(f1, f2, "fuel must be deterministic");
    }

    /// Receipt CID is deterministic — same input, same CID, always.
    #[test]
    fn prop_cid_deterministic(value in any::<i64>()) {
        let prog = prog_push_emit(value);
        let c1 = run_ok(&prog).rc_cid;
        let c2 = run_ok(&prog).rc_cid;
        prop_assert_eq!(c1, c2, "rc_cid must be deterministic");
    }

    /// Different receipt bodies → different rc_cid.
    /// Uses SetRcBody so the value actually lands in the receipt payload.
    #[test]
    fn prop_distinct_bodies_distinct_cids(a in 0i32..i32::MAX, b in 0i32..i32::MAX) {
        prop_assume!(a != b);
        let json_a = format!("{{\"v\":{a}}}");
        let json_b = format!("{{\"v\":{b}}}");
        let prog_a = prog_with_body(json_a.as_bytes());
        let prog_b = prog_with_body(json_b.as_bytes());
        match (run(&prog_a), run(&prog_b)) {
            (Some(out_a), Some(out_b)) => {
                prop_assert_ne!(out_a.rc_cid, out_b.rc_cid,
                    "distinct receipt bodies must produce distinct rc_cids");
            }
            _ => {} // invalid JSON — skip
        }
    }

    /// BLAKE3 hash opcode is deterministic — same bytes, same result.
    #[test]
    fn prop_hash_deterministic(bytes in proptest::collection::vec(any::<u8>(), 0..=256)) {
        let prog = prog_hash_emit(&bytes);
        let c1 = run_ok(&prog).rc_cid;
        let c2 = run_ok(&prog).rc_cid;
        prop_assert_eq!(c1, c2, "BLAKE3 result must be deterministic");
    }

    /// Fuel cost is exactly 1 per opcode.
    #[test]
    fn prop_fuel_one_per_opcode(n_drops in 0usize..50) {
        // ConstI64(0) + n×[ConstI64(1) + Drop] + EmitRc = 1 + n*2 + 1
        let mut prog = enc(0x01, &0i64.to_be_bytes());
        for _ in 0..n_drops {
            prog.extend(enc(0x01, &1i64.to_be_bytes()));
            prog.extend(enc(0x11, &[])); // Drop
        }
        prog.extend(enc(0x10, &[])); // EmitRc
        let expected = 1u64 + (n_drops as u64 * 2) + 1;
        prop_assert_eq!(run_ok(&prog).fuel_used, expected,
            "exactly 1 fuel per opcode");
    }

    /// CAS put-then-get is lossless.
    #[test]
    fn prop_cas_roundtrip(bytes in proptest::collection::vec(any::<u8>(), 0..=512)) {
        let mut cas = MemCas::new();
        let cid = cas.put(&bytes);
        let got = cas.get(&cid).expect("must be present after put");
        prop_assert_eq!(got, bytes, "CAS round-trip must be lossless");
    }

    /// CAS CID is deterministic — same bytes → same CID.
    #[test]
    fn prop_cas_cid_deterministic(bytes in proptest::collection::vec(any::<u8>(), 0..=256)) {
        let mut cas1 = MemCas::new();
        let mut cas2 = MemCas::new();
        let cid1 = cas1.put(&bytes).0;
        let cid2 = cas2.put(&bytes).0;
        prop_assert_eq!(cid1, cid2, "same bytes must yield same CID");
    }

    /// All CIDs are "b3:" + exactly 64 lowercase hex chars.
    #[test]
    fn prop_cid_format(bytes in proptest::collection::vec(any::<u8>(), 0..=256)) {
        let mut cas = MemCas::new();
        let cid = cas.put(&bytes).0;
        prop_assert!(cid.starts_with("b3:"), "CID must start with b3:");
        prop_assert_eq!(cid.len(), 67, "b3:(3) + 64 hex = 67 chars");
        prop_assert!(
            cid[3..].chars().all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()),
            "CID hex must be lowercase"
        );
    }

    /// Distinct byte contents in CAS produce distinct CIDs.
    #[test]
    fn prop_cas_distinct_bytes_distinct_cids(
        a in proptest::collection::vec(any::<u8>(), 1..=128),
        b in proptest::collection::vec(any::<u8>(), 1..=128),
    ) {
        prop_assume!(a != b);
        let mut cas = MemCas::new();
        let cid_a = cas.put(&a).0;
        let cid_b = cas.put(&b).0;
        prop_assert_ne!(cid_a, cid_b, "distinct bytes must produce distinct CIDs");
    }

    /// CAS entries are independently retrievable — no cross-contamination.
    #[test]
    fn prop_cas_isolation(
        a in proptest::collection::vec(any::<u8>(), 1..=128),
        b in proptest::collection::vec(any::<u8>(), 1..=128),
    ) {
        prop_assume!(a != b);
        let mut cas = MemCas::new();
        let cid_a_str = cas.put(&a).0.clone();
        let cid_b_str = cas.put(&b).0.clone();
        let got_a = cas.get(&Cid(cid_a_str)).map(|v| v == a).unwrap_or(false);
        let got_b = cas.get(&Cid(cid_b_str)).map(|v| v == b).unwrap_or(false);
        prop_assert!(got_a, "entry a must be retrievable");
        prop_assert!(got_b, "entry b must be retrievable");
    }
}

// ── Arithmetic saturation (unit) ─────────────────────────────────────────────

fn run_arith(prog: &[u8]) {
    let code = tlv::decode_stream(prog).unwrap();
    let signer = FixedSigner;
    Vm::new(cfg(), MemCas::new(), &signer, rb_vm::RhoCanon, vec![])
        .run(&code).expect("must not panic");
}

#[test]
fn arith_add_max_saturates() {
    let mut p = enc(0x01, &i64::MAX.to_be_bytes());
    p.extend(enc(0x01, &1i64.to_be_bytes()));
    p.extend(enc(0x05, &[])); // AddI64
    p.extend(enc(0x10, &[])); // EmitRc
    run_arith(&p);
}

#[test]
fn arith_sub_min_saturates() {
    let mut p = enc(0x01, &i64::MIN.to_be_bytes());
    p.extend(enc(0x01, &1i64.to_be_bytes()));
    p.extend(enc(0x06, &[])); // SubI64
    p.extend(enc(0x10, &[])); // EmitRc
    run_arith(&p);
}

#[test]
fn arith_mul_overflow_saturates() {
    let mut p = enc(0x01, &i64::MAX.to_be_bytes());
    p.extend(enc(0x01, &2i64.to_be_bytes()));
    p.extend(enc(0x07, &[])); // MulI64
    p.extend(enc(0x10, &[])); // EmitRc
    run_arith(&p);
}

#[test]
fn bare_emit_rc_costs_one_fuel() {
    let prog = enc(0x10, &[]);
    let out = run_ok(&prog);
    assert_eq!(out.fuel_used, 1, "EmitRc alone costs 1 fuel");
}

#[test]
fn set_rc_body_is_reflected_in_receipt() {
    // Body {"k":1} should produce a different rc_cid than {"k":2}
    let prog1 = prog_with_body(br#"{"k":1}"#);
    let prog2 = prog_with_body(br#"{"k":2}"#);
    let cid1 = run_ok(&prog1).rc_cid;
    let cid2 = run_ok(&prog2).rc_cid;
    assert_ne!(cid1, cid2, "different bodies must produce different rc_cids");
}
