//! RB-VM disassembler — human-readable opcode listing from bytecode.

use crate::opcode::Opcode;
use crate::tlv::{decode_stream, DecodeError};

/// Disassemble bytecode into a human-readable string.
pub fn disassemble(bytecode: &[u8]) -> Result<String, DecodeError> {
    let instrs = decode_stream(bytecode)?;
    let mut out = String::new();
    let mut offset = 0usize;

    for ins in &instrs {
        let payload_len = ins.payload.len();
        let line = format_instr(offset, ins.op, ins.payload);
        out.push_str(&line);
        out.push('\n');
        offset += 3 + payload_len; // 1 opcode + 2 len + payload
    }

    if out.is_empty() {
        out.push_str("(empty program)\n");
    }

    Ok(out)
}

fn format_instr(offset: usize, op: Opcode, payload: &[u8]) -> String {
    let name = format!("{:?}", op);
    let detail = format_payload(op, payload);
    if detail.is_empty() {
        format!("{:04x}  {:02x}  {}", offset, op as u8, name)
    } else {
        format!("{:04x}  {:02x}  {} {}", offset, op as u8, name, detail)
    }
}

fn format_payload(op: Opcode, payload: &[u8]) -> String {
    match op {
        Opcode::ConstI64 if payload.len() == 8 => {
            let v = i64::from_be_bytes(payload.try_into().unwrap());
            format!("({})", v)
        }
        Opcode::ConstBytes => {
            if payload.len() <= 32 {
                format!("({} bytes: {})", payload.len(), hex_preview(payload))
            } else {
                format!(
                    "({} bytes: {}...)",
                    payload.len(),
                    hex_preview(&payload[..32])
                )
            }
        }
        Opcode::PushInput if payload.len() == 2 => {
            let idx = u16::from_be_bytes([payload[0], payload[1]]);
            format!("(idx={})", idx)
        }
        Opcode::CmpI64 if payload.len() == 1 => {
            let cmp = match payload[0] {
                0 => "EQ",
                1 => "NE",
                2 => "LT",
                3 => "LE",
                4 => "GT",
                5 => "GE",
                n => return format!("(cmp=0x{:02x}?)", n),
            };
            format!("({})", cmp)
        }
        Opcode::JsonGetKey => match std::str::from_utf8(payload) {
            Ok(s) => format!("(\"{}\")", s),
            Err(_) => format!("({} bytes, non-utf8)", payload.len()),
        },
        Opcode::NumToDec if payload.len() == 5 => {
            let scale = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
            format!("(scale={}, rm={})", scale, payload[4])
        }
        Opcode::NumToRat if payload.len() == 8 => {
            let limit = u64::from_be_bytes(payload.try_into().unwrap());
            format!("(limit_den={})", limit)
        }
        Opcode::NumWithUnit | Opcode::NumAssertUnit => match std::str::from_utf8(payload) {
            Ok(s) => format!("(\"{}\")", s),
            Err(_) => format!("({} bytes, non-utf8)", payload.len()),
        },
        Opcode::JsonGetKeyBytes | Opcode::JsonHasKey => match std::str::from_utf8(payload) {
            Ok(s) => format!("(\"{}\")", s),
            Err(_) => format!("({} bytes, non-utf8)", payload.len()),
        },
        Opcode::PushBool if payload.len() == 1 => {
            format!("({})", if payload[0] != 0 { "true" } else { "false" })
        }
        Opcode::CmpTimestamp if payload.len() == 1 => {
            let cmp = match payload[0] {
                0 => "EQ",
                1 => "NE",
                2 => "LT",
                3 => "LE",
                4 => "GT",
                5 => "GE",
                n => return format!("(cmp=0x{:02x}?)", n),
            };
            format!("({})", cmp)
        }
        _ if !payload.is_empty() => {
            format!("({} bytes)", payload.len())
        }
        _ => String::new(),
    }
}

fn hex_preview(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join("")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_instr(op: Opcode, payload: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(op as u8);
        buf.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        buf.extend_from_slice(payload);
        buf
    }

    #[test]
    fn disasm_empty() {
        let out = disassemble(&[]).unwrap();
        assert_eq!(out, "(empty program)\n");
    }

    #[test]
    fn disasm_const_i64() {
        let bc = encode_instr(Opcode::ConstI64, &42i64.to_be_bytes());
        let out = disassemble(&bc).unwrap();
        assert!(out.contains("ConstI64"));
        assert!(out.contains("(42)"));
    }

    #[test]
    fn disasm_push_input() {
        let bc = encode_instr(Opcode::PushInput, &0u16.to_be_bytes());
        let out = disassemble(&bc).unwrap();
        assert!(out.contains("PushInput"));
        assert!(out.contains("(idx=0)"));
    }

    #[test]
    fn disasm_cmp_operators() {
        for (byte, name) in [
            (0, "EQ"),
            (1, "NE"),
            (2, "LT"),
            (3, "LE"),
            (4, "GT"),
            (5, "GE"),
        ] {
            let bc = encode_instr(Opcode::CmpI64, &[byte]);
            let out = disassemble(&bc).unwrap();
            assert!(
                out.contains(name),
                "expected {} in output for byte {}",
                name,
                byte
            );
        }
    }

    #[test]
    fn disasm_json_get_key() {
        let bc = encode_instr(Opcode::JsonGetKey, b"@type");
        let out = disassemble(&bc).unwrap();
        assert!(out.contains("JsonGetKey"));
        assert!(out.contains("(\"@type\")"));
    }

    #[test]
    fn disasm_multi_instruction() {
        let mut bc = Vec::new();
        bc.extend(encode_instr(Opcode::PushInput, &0u16.to_be_bytes()));
        bc.extend(encode_instr(Opcode::JsonGetKey, b"amount"));
        bc.extend(encode_instr(Opcode::ConstI64, &100i64.to_be_bytes()));
        bc.extend(encode_instr(Opcode::CmpI64, &[3])); // LE
        bc.extend(encode_instr(Opcode::AssertTrue, &[]));
        bc.extend(encode_instr(Opcode::EmitRc, &[]));

        let out = disassemble(&bc).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 6);
        assert!(lines[0].contains("PushInput"));
        assert!(lines[1].contains("JsonGetKey"));
        assert!(lines[2].contains("ConstI64"));
        assert!(lines[3].contains("CmpI64"));
        assert!(lines[4].contains("AssertTrue"));
        assert!(lines[5].contains("EmitRc"));
    }

    #[test]
    fn disasm_offsets_correct() {
        let mut bc = Vec::new();
        bc.extend(encode_instr(Opcode::Drop, &[])); // offset 0, size 3
        bc.extend(encode_instr(Opcode::ConstI64, &1i64.to_be_bytes())); // offset 3, size 11

        let out = disassemble(&bc).unwrap();
        assert!(out.starts_with("0000"));
        assert!(out.contains("0003"));
    }

    #[test]
    fn disasm_bad_opcode() {
        let bc = vec![0xFF, 0x00, 0x00];
        let result = disassemble(&bc);
        assert!(result.is_err());
    }
}
