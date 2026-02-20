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
    PushInput = 0x12,         // payload: u16 index
    JsonGetKey = 0x13,        // payload: utf-8 key
    Dup = 0x14,               // duplicate top of stack
    Swap = 0x15,              // swap top two stack values
    VerifySig = 0x16,         // pop (pubkey_bytes, sig_bytes, msg_bytes) → push Bool
    NumFromDecimalStr = 0x17, // pop string bytes -> push unc1 num
    NumFromF64Bits = 0x18,    // pop i64 bits -> push unc1 bnd
    NumAdd = 0x19,            // pop b,a (num) -> push num
    NumSub = 0x1A,            // pop b,a (num) -> push num
    NumMul = 0x1B,            // pop b,a (num) -> push num
    NumDiv = 0x1C,            // pop b,a (num) -> push num
    NumToDec = 0x1D,          // payload: u32 scale + u8 rounding mode; pop num -> push dec
    NumToRat = 0x1E,          // payload: u64 limit_den; pop num -> push rat
    NumWithUnit = 0x1F,       // payload: utf8 unit; pop num -> push num
    NumAssertUnit = 0x20,     // payload: utf8 unit; pop num -> push same num
    NumCompare = 0x21,        // pop b,a (num) -> push int/1 as num

    // ── Phase 2: string comparison + bool-stack composition ─────────────────
    JsonGetKeyBytes = 0x22, // payload: utf-8 key; pop Json -> push Bytes (string value)
    JsonHasKey = 0x23,      // payload: utf-8 key; pop Json -> push Bool (key exists)
    EqBytes = 0x24,         // pop b,a (Bytes) -> push Bool(a == b)
    PushBodySize = 0x25,    // push I64(vm.body_size)
    PushBool = 0x26,        // payload: 1 byte (0=false, 1=true); push Bool
    BoolNot = 0x27,         // pop Bool -> push !Bool
    BoolOr = 0x28,          // pop b,a (Bool) -> push Bool(a || b)
    BoolAnd = 0x29,         // pop b,a (Bool) -> push Bool(a && b)
    BoolToI64 = 0x2A,       // pop Bool -> push I64(1 or 0)

    // ── Phase 3: arithmetic + temporal ──────────────────────────────────────
    DivI64 = 0x2B, // pop b,a (I64) -> push I64(a / b), saturating (div-by-zero → 0)
    PushTimestamp = 0x2C, // push I64(unix_secs_now) — wall-clock seconds since epoch
    CmpTimestamp = 0x2D, // payload: 1-byte cmp-op (same as CmpI64); pop I64 ts, push Bool
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
            0x17 => NumFromDecimalStr,
            0x18 => NumFromF64Bits,
            0x19 => NumAdd,
            0x1A => NumSub,
            0x1B => NumMul,
            0x1C => NumDiv,
            0x1D => NumToDec,
            0x1E => NumToRat,
            0x1F => NumWithUnit,
            0x20 => NumAssertUnit,
            0x21 => NumCompare,
            0x22 => JsonGetKeyBytes,
            0x23 => JsonHasKey,
            0x24 => EqBytes,
            0x25 => PushBodySize,
            0x26 => PushBool,
            0x27 => BoolNot,
            0x28 => BoolOr,
            0x29 => BoolAnd,
            0x2A => BoolToI64,
            0x2B => DivI64,
            0x2C => PushTimestamp,
            0x2D => CmpTimestamp,
            _ => return Err(()),
        })
    }
}
