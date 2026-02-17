use crate::canon::CanonProvider;
use crate::{
    opcode::Opcode,
    tlv::Instr,
    types::{Cid, RcPayload, Value},
};
use base64::Engine;
use serde_json::json;
use ubl_unc1 as unc1;

pub type Fuel = u64;

#[derive(Debug, thiserror::Error)]
pub enum ExecError {
    #[error("fuel exhausted")]
    FuelExhausted,
    #[error("stack underflow for {0:?}")]
    StackUnderflow(Opcode),
    #[error("type mismatch for {0:?}")]
    TypeMismatch(Opcode),
    #[error("invalid payload for {0:?}")]
    InvalidPayload(Opcode),
    #[error("deny: {0}")]
    Deny(String),
}

pub trait CasProvider {
    fn put(&mut self, bytes: &[u8]) -> Cid;
    fn get(&self, cid: &Cid) -> Option<Vec<u8>>;
}

pub trait SignProvider {
    fn sign_jws(&self, payload_nrf_bytes: &[u8]) -> Vec<u8>;
    fn kid(&self) -> String;
}

#[derive(Clone)]
pub struct VmConfig {
    pub fuel_limit: Fuel,
    pub ghost: bool,
    pub trace: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TraceStep {
    pub step: u64,
    pub op: String,
    pub fuel_after: u64,
    pub stack_depth: usize,
    pub note: Option<String>,
}

pub struct Vm<'a, C: CasProvider, S: SignProvider, K: CanonProvider> {
    cfg: VmConfig,
    stack: Vec<Value>,
    steps: u64,
    fuel_used: Fuel,
    cas: C,
    signer: &'a S,
    inputs: Vec<Cid>,
    canon: K,
    rc_body: serde_json::Value,
    proofs: Vec<Cid>,
    trace: Vec<TraceStep>,
}

#[derive(Debug)]
pub struct VmOutcome {
    pub rc_cid: Option<Cid>,
    pub rc_sig: Option<String>,
    pub rc_payload_cid: Option<Cid>,
    pub steps: u64,
    pub fuel_used: Fuel,
    pub trace: Vec<TraceStep>,
}

impl<'a, C: CasProvider, S: SignProvider, K: CanonProvider> Vm<'a, C, S, K> {
    pub fn new(cfg: VmConfig, cas: C, signer: &'a S, canon: K, inputs: Vec<Cid>) -> Self {
        Self {
            cfg,
            stack: Vec::new(),
            steps: 0,
            fuel_used: 0,
            cas,
            signer,
            canon,
            inputs,
            rc_body: json!({}),
            proofs: Vec::new(),
            trace: Vec::new(),
        }
    }

    fn charge(&mut self, units: Fuel) -> Result<(), ExecError> {
        let next = self.fuel_used.saturating_add(units);
        if next > self.cfg.fuel_limit {
            return Err(ExecError::FuelExhausted);
        }
        self.fuel_used = next;
        Ok(())
    }

    fn pop(&mut self) -> Result<Value, ExecError> {
        self.stack
            .pop()
            .ok_or(ExecError::StackUnderflow(Opcode::Drop))
    }

    fn push(&mut self, v: Value) {
        self.stack.push(v);
    }

    fn pop_num_for(&mut self, op: Opcode) -> Result<unc1::Num, ExecError> {
        match self.pop()? {
            Value::Num(n) => Ok(n),
            Value::I64(v) => Ok(unc1::Num::Int {
                v: v.to_string(),
                u: None,
            }),
            Value::Json(v) => {
                serde_json::from_value::<unc1::Num>(v).map_err(|_| ExecError::TypeMismatch(op))
            }
            _ => Err(ExecError::TypeMismatch(op)),
        }
    }

    pub fn run(&mut self, code: &[Instr<'_>]) -> Result<VmOutcome, ExecError> {
        use Value::*;
        for ins in code {
            self.charge(1)?;
            self.steps += 1;
            let trace_op = format!("{:?}", ins.op);
            match ins.op {
                Opcode::ConstI64 => {
                    if ins.payload.len() != 8 {
                        return Err(ExecError::InvalidPayload(Opcode::ConstI64));
                    }
                    let v = i64::from_be_bytes(ins.payload.try_into().unwrap());
                    self.push(I64(v));
                }
                Opcode::ConstBytes => {
                    self.push(Bytes(ins.payload.to_vec()));
                }
                Opcode::Drop => {
                    self.pop()?;
                }
                Opcode::PushInput => {
                    if ins.payload.len() != 2 {
                        return Err(ExecError::InvalidPayload(Opcode::PushInput));
                    }
                    let idx = u16::from_be_bytes([ins.payload[0], ins.payload[1]]) as usize;
                    let cid = self
                        .inputs
                        .get(idx)
                        .cloned()
                        .ok_or(ExecError::InvalidPayload(Opcode::PushInput))?;
                    self.push(Value::Cid(cid));
                }
                Opcode::AddI64 | Opcode::SubI64 | Opcode::MulI64 => {
                    let b = match self.pop()? {
                        I64(v) => v,
                        _ => return Err(ExecError::TypeMismatch(ins.op)),
                    };
                    let a = match self.pop()? {
                        I64(v) => v,
                        _ => return Err(ExecError::TypeMismatch(ins.op)),
                    };
                    let r = match ins.op {
                        Opcode::AddI64 => a.saturating_add(b),
                        Opcode::SubI64 => a.saturating_sub(b),
                        _ => a.saturating_mul(b),
                    };
                    self.push(I64(r));
                }
                Opcode::CmpI64 => {
                    if ins.payload.len() != 1 {
                        return Err(ExecError::InvalidPayload(Opcode::CmpI64));
                    }
                    let b = match self.pop()? {
                        I64(v) => v,
                        _ => return Err(ExecError::TypeMismatch(Opcode::CmpI64)),
                    };
                    let a = match self.pop()? {
                        I64(v) => v,
                        _ => return Err(ExecError::TypeMismatch(Opcode::CmpI64)),
                    };
                    let op = ins.payload[0];
                    let ok = match op {
                        0 => a == b,
                        1 => a != b,
                        2 => a < b,
                        3 => a <= b,
                        4 => a > b,
                        5 => a >= b,
                        _ => return Err(ExecError::InvalidPayload(Opcode::CmpI64)),
                    };
                    self.push(Bool(ok));
                }
                Opcode::AssertTrue => {
                    let v = match self.pop()? {
                        Bool(v) => v,
                        _ => return Err(ExecError::TypeMismatch(Opcode::AssertTrue)),
                    };
                    if !v {
                        return Err(ExecError::Deny("assert_false".into()));
                    }
                }
                Opcode::CasGet => {
                    let cid = match self.pop()? {
                        Value::Cid(c) => c,
                        _ => return Err(ExecError::TypeMismatch(Opcode::CasGet)),
                    };
                    let bytes = self
                        .cas
                        .get(&cid)
                        .ok_or(ExecError::Deny("cas_get_not_found".into()))?;
                    self.push(Bytes(bytes));
                }
                Opcode::CasPut => {
                    let bytes = match self.pop()? {
                        Bytes(b) => b,
                        _ => return Err(ExecError::TypeMismatch(Opcode::CasPut)),
                    };
                    let cid = self.cas.put(&bytes);
                    self.push(Value::Cid(cid));
                }
                // Placeholders for JSON and sign/emit (to be wired to lower layer canon and JWS)
                Opcode::JsonNormalize => {
                    let bytes = match self.pop()? {
                        Bytes(b) => b,
                        _ => return Err(ExecError::TypeMismatch(Opcode::JsonNormalize)),
                    };
                    let v: serde_json::Value = serde_json::from_slice(&bytes)
                        .map_err(|_| ExecError::Deny("json_parse_error".into()))?;
                    // Canon real plugável; aqui usamos o provider
                    let v = self.canon.canon(v);
                    self.push(Value::Json(v));
                }
                Opcode::JsonValidate => {
                    let v = match self.pop()? {
                        Value::Json(v) => v,
                        _ => return Err(ExecError::TypeMismatch(Opcode::JsonValidate)),
                    };
                    // MVP: passthrough; replace with limits/scheme
                    self.push(Value::Json(v));
                }
                Opcode::JsonGetKey => {
                    let key = std::str::from_utf8(ins.payload)
                        .map_err(|_| ExecError::InvalidPayload(Opcode::JsonGetKey))?;
                    let v = match self.pop()? {
                        Value::Json(v) => v,
                        _ => return Err(ExecError::TypeMismatch(Opcode::JsonGetKey)),
                    };
                    let extracted = v
                        .get(key)
                        .ok_or(ExecError::Deny("json_key_missing_or_not_i64".into()))?;
                    if let Some(n) = extracted.as_i64() {
                        self.push(Value::I64(n));
                    } else if extracted.get("@num").is_some() {
                        let num = serde_json::from_value::<unc1::Num>(extracted.clone())
                            .map_err(|_| ExecError::Deny("json_key_missing_or_not_i64".into()))?;
                        self.push(Value::Num(num));
                    } else {
                        return Err(ExecError::Deny("json_key_missing_or_not_i64".into()));
                    }
                }
                Opcode::HashBlake3 => {
                    let bytes = match self.pop()? {
                        Value::Bytes(b) => b,
                        _ => return Err(ExecError::TypeMismatch(Opcode::HashBlake3)),
                    };
                    let hash = blake3::hash(&bytes);
                    self.push(Value::Bytes(hash.as_bytes().to_vec()));
                }
                Opcode::SetRcBody => {
                    let v = match self.pop()? {
                        Value::Json(v) => v,
                        Value::Num(n) => serde_json::to_value(n)
                            .map_err(|_| ExecError::Deny("num_serialize_error".into()))?,
                        _ => return Err(ExecError::TypeMismatch(Opcode::SetRcBody)),
                    };
                    self.rc_body = v;
                }
                Opcode::AttachProof => {
                    let cid = match self.pop()? {
                        Value::Cid(c) => c,
                        _ => return Err(ExecError::TypeMismatch(Opcode::AttachProof)),
                    };
                    self.proofs.push(cid);
                }
                Opcode::SignDefault => {
                    // no-op here; signing is done in EmitRc using provider
                }
                Opcode::Dup => {
                    let v = self.pop()?;
                    self.push(v.clone());
                    self.push(v);
                }
                Opcode::Swap => {
                    let b = self.pop()?;
                    let a = self.pop()?;
                    self.push(b);
                    self.push(a);
                }
                Opcode::VerifySig => {
                    // Stack: [msg_bytes, sig_bytes, pubkey_bytes] (top = pubkey)
                    let pubkey_bytes = match self.pop()? {
                        Value::Bytes(b) => b,
                        _ => return Err(ExecError::TypeMismatch(Opcode::VerifySig)),
                    };
                    let sig_bytes = match self.pop()? {
                        Value::Bytes(b) => b,
                        _ => return Err(ExecError::TypeMismatch(Opcode::VerifySig)),
                    };
                    let msg_bytes = match self.pop()? {
                        Value::Bytes(b) => b,
                        _ => return Err(ExecError::TypeMismatch(Opcode::VerifySig)),
                    };
                    // Ed25519 verification
                    let valid = if pubkey_bytes.len() == 32 && sig_bytes.len() == 64 {
                        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
                        match VerifyingKey::from_bytes(&pubkey_bytes.try_into().unwrap()) {
                            Ok(vk) => {
                                let sig = Signature::from_bytes(&sig_bytes.try_into().unwrap());
                                vk.verify(&msg_bytes, &sig).is_ok()
                            }
                            Err(_) => false,
                        }
                    } else {
                        false
                    };
                    self.push(Value::Bool(valid));
                }
                Opcode::NumFromDecimalStr => {
                    let raw = match self.pop()? {
                        Value::Bytes(b) => b,
                        _ => return Err(ExecError::TypeMismatch(Opcode::NumFromDecimalStr)),
                    };
                    let decimal = std::str::from_utf8(&raw)
                        .map_err(|_| ExecError::InvalidPayload(Opcode::NumFromDecimalStr))?;
                    let num = unc1::from_decimal_str(decimal)
                        .map_err(|e| ExecError::Deny(format!("num_from_decimal_str: {}", e)))?;
                    self.push(Value::Num(num));
                }
                Opcode::NumFromF64Bits => {
                    let bits_i64 = match self.pop()? {
                        Value::I64(v) => v,
                        _ => return Err(ExecError::TypeMismatch(Opcode::NumFromF64Bits)),
                    };
                    if bits_i64 < 0 {
                        return Err(ExecError::InvalidPayload(Opcode::NumFromF64Bits));
                    }
                    let num = unc1::from_f64_bits(bits_i64 as u64)
                        .map_err(|e| ExecError::Deny(format!("num_from_f64_bits: {}", e)))?;
                    self.push(Value::Num(num));
                }
                Opcode::NumAdd | Opcode::NumSub | Opcode::NumMul | Opcode::NumDiv => {
                    let b = self.pop_num_for(ins.op)?;
                    let a = self.pop_num_for(ins.op)?;
                    let result = match ins.op {
                        Opcode::NumAdd => unc1::add(&a, &b),
                        Opcode::NumSub => unc1::sub(&a, &b),
                        Opcode::NumMul => unc1::mul(&a, &b),
                        Opcode::NumDiv => unc1::div(&a, &b),
                        _ => unreachable!(),
                    }
                    .map_err(|e| ExecError::Deny(format!("num_op_error: {}", e)))?;
                    self.push(Value::Num(result));
                }
                Opcode::NumToDec => {
                    if ins.payload.len() != 5 {
                        return Err(ExecError::InvalidPayload(Opcode::NumToDec));
                    }
                    let scale = u32::from_be_bytes([
                        ins.payload[0],
                        ins.payload[1],
                        ins.payload[2],
                        ins.payload[3],
                    ]);
                    let rm = unc1::RoundingMode::from_u8(ins.payload[4])
                        .map_err(|_| ExecError::InvalidPayload(Opcode::NumToDec))?;
                    let a = self.pop_num_for(ins.op)?;
                    let result = unc1::to_dec(&a, scale, rm)
                        .map_err(|e| ExecError::Deny(format!("num_to_dec: {}", e)))?;
                    self.push(Value::Num(result));
                }
                Opcode::NumToRat => {
                    if ins.payload.len() != 8 {
                        return Err(ExecError::InvalidPayload(Opcode::NumToRat));
                    }
                    let limit_den = u64::from_be_bytes([
                        ins.payload[0],
                        ins.payload[1],
                        ins.payload[2],
                        ins.payload[3],
                        ins.payload[4],
                        ins.payload[5],
                        ins.payload[6],
                        ins.payload[7],
                    ]);
                    let a = self.pop_num_for(ins.op)?;
                    let result = unc1::to_rat(&a, limit_den)
                        .map_err(|e| ExecError::Deny(format!("num_to_rat: {}", e)))?;
                    self.push(Value::Num(result));
                }
                Opcode::NumWithUnit => {
                    let unit = std::str::from_utf8(ins.payload)
                        .map_err(|_| ExecError::InvalidPayload(Opcode::NumWithUnit))?;
                    let a = self.pop_num_for(ins.op)?;
                    let result = a
                        .with_unit(unit)
                        .map_err(|e| ExecError::Deny(format!("num_with_unit: {}", e)))?;
                    self.push(Value::Num(result));
                }
                Opcode::NumAssertUnit => {
                    let unit = std::str::from_utf8(ins.payload)
                        .map_err(|_| ExecError::InvalidPayload(Opcode::NumAssertUnit))?;
                    let a = self.pop_num_for(ins.op)?;
                    a.assert_unit(unit)
                        .map_err(|e| ExecError::Deny(format!("num_assert_unit: {}", e)))?;
                    self.push(Value::Num(a));
                }
                Opcode::NumCompare => {
                    let b = self.pop_num_for(ins.op)?;
                    let a = self.pop_num_for(ins.op)?;
                    let result = unc1::compare(&a, &b)
                        .map_err(|e| ExecError::Deny(format!("num_compare: {}", e)))?;
                    self.push(Value::Num(result));
                }
                Opcode::EmitRc => {
                    if self.cfg.trace {
                        self.trace.push(TraceStep {
                            step: self.steps,
                            op: trace_op,
                            fuel_after: self.fuel_used,
                            stack_depth: self.stack.len(),
                            note: Some("emit_rc".into()),
                        });
                    }
                    // Build minimal RC payload
                    let payload = RcPayload {
                        subject_cid: None,
                        engine: "rb-vm/0.1.0".into(),
                        ghost: self.cfg.ghost,
                        inputs: self.inputs.clone(),
                        proofs: self.proofs.clone(),
                        steps: self.steps,
                        fuel_used: self.fuel_used,
                        policy_id: "default:v1".into(),
                        decision: json!({"status":"ok"}),
                        body: self.rc_body.clone(),
                    };
                    // Canonicalize the full RC payload before signing/hashing so
                    // key order and equivalent JSON forms cannot change signatures/CIDs.
                    let payload_json = serde_json::to_value(&payload)
                        .map_err(|_| ExecError::Deny("rc_payload_serialize_error".into()))?;
                    let payload_json = self.canon.canon(payload_json);
                    let bytes = serde_json::to_vec(&payload_json)
                        .map_err(|_| ExecError::Deny("rc_payload_encode_error".into()))?;
                    let sig_bytes = self.signer.sign_jws(&bytes);
                    if sig_bytes.is_empty() {
                        return Err(ExecError::Deny("emit_rc_missing_signature".into()));
                    }
                    let sig = format!(
                        "ed25519:{}",
                        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig_bytes)
                    );
                    let cid = self.cas.put(&bytes);
                    return Ok(VmOutcome {
                        rc_cid: Some(cid.clone()),
                        rc_sig: Some(sig),
                        rc_payload_cid: Some(cid),
                        steps: self.steps,
                        fuel_used: self.fuel_used,
                        trace: std::mem::take(&mut self.trace),
                    });
                }
            }
            if self.cfg.trace {
                self.trace.push(TraceStep {
                    step: self.steps,
                    op: trace_op,
                    fuel_after: self.fuel_used,
                    stack_depth: self.stack.len(),
                    note: None,
                });
            }
        }
        Ok(VmOutcome {
            rc_cid: None,
            rc_sig: None,
            rc_payload_cid: None,
            steps: self.steps,
            fuel_used: self.fuel_used,
            trace: std::mem::take(&mut self.trace),
        })
    }
}
