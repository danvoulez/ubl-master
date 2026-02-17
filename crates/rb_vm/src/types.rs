use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    I64(i64),
    Bytes(Vec<u8>),
    Json(serde_json::Value),
    Num(ubl_unc1::Num),
    Cid(Cid),
    Bool(bool),
    Unit,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Cid(pub String); // MVP: textual `b3:...` or `cidv1:...`

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RcPayload {
    pub subject_cid: Option<Cid>,
    pub engine: String,
    pub ghost: bool,
    pub inputs: Vec<Cid>,
    pub proofs: Vec<Cid>,
    pub steps: u64,
    pub fuel_used: u64,
    pub policy_id: String,
    pub decision: serde_json::Value,
    pub body: serde_json::Value,
}
