use crate::opcode::Opcode;

#[derive(Debug)]
pub struct Instr<'a> {
    pub op: Opcode,
    pub payload: &'a [u8],
}

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("truncated")]
    Truncated,
    #[error("unknown opcode {0:#x}")]
    UnknownOpcode(u8),
}

pub fn decode_stream(buf: &[u8]) -> Result<Vec<Instr<'_>>, DecodeError> {
    let mut i = 0;
    let mut out = Vec::new();
    while i < buf.len() {
        if i + 3 > buf.len() {
            return Err(DecodeError::Truncated);
        }
        let op_u8 = buf[i];
        let len = u16::from_be_bytes([buf[i + 1], buf[i + 2]]) as usize;
        let start = i + 3;
        let end = start + len;
        if end > buf.len() {
            return Err(DecodeError::Truncated);
        }
        let op = Opcode::try_from(op_u8).map_err(|_| DecodeError::UnknownOpcode(op_u8))?;
        out.push(Instr {
            op,
            payload: &buf[start..end],
        });
        i = end;
    }
    Ok(out)
}
