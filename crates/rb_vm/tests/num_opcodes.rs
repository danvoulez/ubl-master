use rb_vm::canon::NaiveCanon;
use rb_vm::exec::{CasProvider, SignProvider};
use rb_vm::tlv;
use rb_vm::{Cid, ExecError, Vm, VmConfig};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

struct SharedCas {
    store: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl SharedCas {
    fn new(store: Arc<Mutex<HashMap<String, Vec<u8>>>>) -> Self {
        Self { store }
    }
}

impl CasProvider for SharedCas {
    fn put(&mut self, bytes: &[u8]) -> Cid {
        let hash = blake3::hash(bytes);
        let cid = format!("b3:{}", hex::encode(hash.as_bytes()));
        self.store
            .lock()
            .unwrap()
            .insert(cid.clone(), bytes.to_vec());
        Cid(cid)
    }

    fn get(&self, cid: &Cid) -> Option<Vec<u8>> {
        self.store.lock().unwrap().get(&cid.0).cloned()
    }
}

struct FixedSigner;

impl SignProvider for FixedSigner {
    fn sign_jws(&self, _payload_nrf_bytes: &[u8]) -> Vec<u8> {
        vec![7u8; 64]
    }

    fn kid(&self) -> String {
        "did:test#k1".to_string()
    }
}

fn tlv_instr(op: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![op];
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn run(code: Vec<u8>) -> Result<(rb_vm::exec::VmOutcome, serde_json::Value), ExecError> {
    let instructions = tlv::decode_stream(&code).expect("valid tlv");
    let store = Arc::new(Mutex::new(HashMap::new()));
    let cas = SharedCas::new(store.clone());
    let signer = FixedSigner;
    let mut vm = Vm::new(
        VmConfig {
            fuel_limit: 100_000,
            ghost: false,
            trace: false,
        },
        cas,
        &signer,
        NaiveCanon,
        vec![],
    );

    let outcome = vm.run(&instructions)?;
    let rc_cid = outcome
        .rc_cid
        .as_ref()
        .expect("emit rc should return cid")
        .0
        .clone();
    let payload = store
        .lock()
        .unwrap()
        .get(&rc_cid)
        .cloned()
        .expect("payload stored in cas");
    let payload_json: serde_json::Value = serde_json::from_slice(&payload).expect("valid payload");
    Ok((outcome, payload_json))
}

#[test]
fn num_add_decimals_and_emit_body() {
    let mut code = Vec::new();
    code.extend(tlv_instr(0x02, b"0.1"));
    code.extend(tlv_instr(0x17, &[]));
    code.extend(tlv_instr(0x02, b"0.2"));
    code.extend(tlv_instr(0x17, &[]));
    code.extend(tlv_instr(0x19, &[]));
    code.extend(tlv_instr(0x0D, &[]));
    code.extend(tlv_instr(0x10, &[]));

    let (_outcome, payload) = run(code).expect("vm run");
    assert_eq!(payload["body"]["@num"], "dec/1");
    assert_eq!(payload["body"]["m"], "3");
    assert_eq!(payload["body"]["s"], 1);
}

#[test]
fn num_div_to_dec_round_down() {
    let mut code = Vec::new();
    let limit_den = 1000u64.to_be_bytes();
    code.extend(tlv_instr(0x02, b"1"));
    code.extend(tlv_instr(0x17, &[]));
    code.extend(tlv_instr(0x1E, &limit_den));
    code.extend(tlv_instr(0x02, b"3"));
    code.extend(tlv_instr(0x17, &[]));
    code.extend(tlv_instr(0x1E, &limit_den));
    code.extend(tlv_instr(0x1C, &[]));
    // scale=2, rounding=Down(1)
    code.extend(tlv_instr(0x1D, &[0, 0, 0, 2, 1]));
    code.extend(tlv_instr(0x0D, &[]));
    code.extend(tlv_instr(0x10, &[]));

    let (_outcome, payload) = run(code).expect("vm run");
    assert_eq!(payload["body"]["@num"], "dec/1");
    assert_eq!(payload["body"]["m"], "33");
    assert_eq!(payload["body"]["s"], 2);
}

#[test]
fn num_compare_with_units() {
    let mut code = Vec::new();
    code.extend(tlv_instr(0x02, b"10"));
    code.extend(tlv_instr(0x17, &[]));
    code.extend(tlv_instr(0x1F, b"USD"));
    code.extend(tlv_instr(0x02, b"20"));
    code.extend(tlv_instr(0x17, &[]));
    code.extend(tlv_instr(0x1F, b"USD"));
    code.extend(tlv_instr(0x21, &[]));
    code.extend(tlv_instr(0x0D, &[]));
    code.extend(tlv_instr(0x10, &[]));

    let (_outcome, payload) = run(code).expect("vm run");
    assert_eq!(payload["body"]["@num"], "int/1");
    assert_eq!(payload["body"]["v"], "-1");
}

#[test]
fn num_assert_unit_mismatch_denies() {
    let mut code = Vec::new();
    code.extend(tlv_instr(0x02, b"1"));
    code.extend(tlv_instr(0x17, &[]));
    code.extend(tlv_instr(0x1F, b"USD"));
    code.extend(tlv_instr(0x20, b"EUR"));
    code.extend(tlv_instr(0x10, &[]));

    let instructions = tlv::decode_stream(&code).expect("valid tlv");
    let store = Arc::new(Mutex::new(HashMap::new()));
    let cas = SharedCas::new(store);
    let signer = FixedSigner;
    let mut vm = Vm::new(
        VmConfig {
            fuel_limit: 10_000,
            ghost: false,
            trace: false,
        },
        cas,
        &signer,
        NaiveCanon,
        vec![],
    );

    let err = vm.run(&instructions).expect_err("unit mismatch must deny");
    match err {
        ExecError::Deny(msg) => assert!(msg.contains("num_assert_unit")),
        _ => panic!("expected deny, got {:?}", err),
    }
}
