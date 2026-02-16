# RB-VM MVP (Fractal)

Este pacote contém:
- `spec/DECISIONS.md` e `spec/LAWS.md`
- Fixtures de Leis em `tests/laws/*`
- Exemplo `deny_age` com `chip.tlv`, `chip.asm`, `inputs.json`

## Formato TLV
- Opcode: u8
- Len: u16 (big-endian)
- Payload: [len] bytes

### Opcodes (MVP)
- 0x01 ConstI64
- 0x02 ConstBytes
- 0x03 JsonNormalize
- 0x04 JsonValidate
- 0x05 AddI64
- 0x06 SubI64
- 0x07 MulI64
- 0x08 CmpI64
- 0x09 AssertTrue
- 0x0A HashBlake3
- 0x0B CasPut
- 0x0C CasGet
- 0x0D SetRcBody
- 0x0E AttachProof
- 0x0F SignDefault
- 0x10 EmitRc
- 0x11 Drop
- 0x12 PushInput
- 0x13 JsonGetKey

## Próximos passos
- Implementar executor em `crates/rb_vm`
- Ligar `--engine=rb` no `ubl-runtime`
- Preencher goldens de `expected.rc.cid` após implementação
