#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Opcode {
    ConstI64 = 0x01,
    ConstBytes = 0x02,
    JsonNormalize = 0x03,
    JsonValidate = 0x04,
    AddI64 = 0x05,
    SubI64 = 0x06,
    MulI64 = 0x07,
    CmpI64 = 0x08, // payload: 1 byte operator (0 EQ,1 NE,2 LT,3 LE,4 GT,5 GE)
    AssertTrue = 0x09,
    HashBlake3 = 0x0A,
    CasPut = 0x0B,
    CasGet = 0x0C,
    SetRcBody = 0x0D,
    AttachProof = 0x0E,
    SignDefault = 0x0F,
    EmitRc = 0x10,
    Drop = 0x11,
    PushInput = 0x12,  // payload: u16 index
    JsonGetKey = 0x13, // payload: utf-8 key
    Dup = 0x14,        // duplicate top of stack
    Swap = 0x15,       // swap top two stack values
    VerifySig = 0x16,  // pop (pubkey_bytes, sig_bytes, msg_bytes) → push Bool
}

impl TryFrom<u8> for Opcode {
    type Error = ();
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        use Opcode::*;
        Ok(match v {
            0x01 => ConstI64,
            0x02 => ConstBytes,
            0x03 => JsonNormalize,
            0x04 => JsonValidate,
            0x05 => AddI64,
            0x06 => SubI64,
            0x07 => MulI64,
            0x08 => CmpI64,
            0x09 => AssertTrue,
            0x0A => HashBlake3,
            0x0B => CasPut,
            0x0C => CasGet,
            0x0D => SetRcBody,
            0x0E => AttachProof,
            0x0F => SignDefault,
            0x10 => EmitRc,
            0x11 => Drop,
            0x12 => PushInput,
            0x13 => JsonGetKey,
            0x14 => Dup,
            0x15 => Swap,
            0x16 => VerifySig,
            _ => return Err(()),
        })
    }
}
