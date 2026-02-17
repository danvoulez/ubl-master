use rb_vm::canon::NaiveCanon;
use rb_vm::exec::{CasProvider, SignProvider};
use rb_vm::tlv;
use rb_vm::{Cid, Vm, VmConfig};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

struct CaptureCas {
    store: HashMap<String, Vec<u8>>,
    last_put: Arc<Mutex<Option<Vec<u8>>>>,
}

impl CaptureCas {
    fn new(last_put: Arc<Mutex<Option<Vec<u8>>>>) -> Self {
        Self {
            store: HashMap::new(),
            last_put,
        }
    }
}

impl CasProvider for CaptureCas {
    fn put(&mut self, bytes: &[u8]) -> Cid {
        let hash = blake3::hash(bytes);
        let cid = format!("b3:{}", hex::encode(hash.as_bytes()));
        self.store.insert(cid.clone(), bytes.to_vec());
        *self.last_put.lock().unwrap() = Some(bytes.to_vec());
        Cid(cid)
    }

    fn get(&self, cid: &Cid) -> Option<Vec<u8>> {
        self.store.get(&cid.0).cloned()
    }
}

struct CaptureSigner {
    last_signed: Arc<Mutex<Option<Vec<u8>>>>,
}

impl SignProvider for CaptureSigner {
    fn sign_jws(&self, payload_nrf_bytes: &[u8]) -> Vec<u8> {
        *self.last_signed.lock().unwrap() = Some(payload_nrf_bytes.to_vec());
        vec![0u8; 64]
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

fn tlv_const_bytes(bytes: &[u8]) -> Vec<u8> {
    tlv_instr(0x02, bytes)
}

fn tlv_json_normalize() -> Vec<u8> {
    tlv_instr(0x03, &[])
}

fn tlv_set_rc_body() -> Vec<u8> {
    tlv_instr(0x0D, &[])
}

fn tlv_emit_rc() -> Vec<u8> {
    tlv_instr(0x10, &[])
}

#[test]
fn vm_emitrc_sig_persisted_and_linked() {
    let signed = Arc::new(Mutex::new(None));
    let stored = Arc::new(Mutex::new(None));

    let signer = CaptureSigner {
        last_signed: signed.clone(),
    };
    let cas = CaptureCas::new(stored.clone());

    let mut code = Vec::new();
    code.extend(tlv_const_bytes(br#"{"z":1,"a":{"y":2,"x":1}}"#));
    code.extend(tlv_json_normalize());
    code.extend(tlv_set_rc_body());
    code.extend(tlv_emit_rc());

    let instructions = tlv::decode_stream(&code).expect("valid TLV");
    let mut vm = Vm::new(
        VmConfig {
            fuel_limit: 1_000,
            ghost: false,
            trace: false,
        },
        cas,
        &signer,
        NaiveCanon,
        vec![],
    );

    let outcome = vm.run(&instructions).expect("vm run ok");
    let rc_cid = outcome.rc_cid.expect("EmitRc returns CID");
    let rc_sig = outcome.rc_sig.expect("EmitRc returns signature");
    let rc_payload_cid = outcome
        .rc_payload_cid
        .expect("EmitRc returns payload cid linkage");

    let signed_bytes = signed
        .lock()
        .unwrap()
        .clone()
        .expect("signer captured payload");
    let stored_bytes = stored
        .lock()
        .unwrap()
        .clone()
        .expect("cas captured payload");

    assert_eq!(
        signed_bytes, stored_bytes,
        "Sign and CID must use the exact same canonical payload bytes"
    );

    let payload: serde_json::Value =
        serde_json::from_slice(&signed_bytes).expect("payload is valid JSON");
    let root_keys: Vec<String> = payload
        .as_object()
        .expect("payload object")
        .keys()
        .cloned()
        .collect();
    let mut sorted_root_keys = root_keys.clone();
    sorted_root_keys.sort();
    assert_eq!(
        root_keys, sorted_root_keys,
        "EmitRc payload keys must be canonical-sorted"
    );

    let body_keys: Vec<String> = payload["body"]
        .as_object()
        .expect("body object")
        .keys()
        .cloned()
        .collect();
    assert_eq!(body_keys, vec!["a".to_string(), "z".to_string()]);

    let expected_cid = format!("b3:{}", hex::encode(blake3::hash(&signed_bytes).as_bytes()));
    assert_eq!(
        rc_cid.0, expected_cid,
        "CID must hash canonical payload bytes"
    );
    assert_eq!(rc_payload_cid.0, rc_cid.0);
    assert!(rc_sig.starts_with("ed25519:"));
}
