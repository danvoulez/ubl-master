# RB-VM — Numeric Opcodes (UNC-1)

- `0x17 num.from_decimal_str(s: string) -> dec/1`
- `0x18 num.from_f64_bits(bits: u64) -> bnd/1`
- `0x19 num.add(a, b) -> num`
- `0x1A num.sub(a, b) -> num`
- `0x1B num.mul(a, b) -> num`
- `0x1C num.div(a, b) -> num`
- `0x1D num.to_dec(a, scale: u32, rm: u8) -> dec/1`
- `0x1E num.to_rat(a, limit_den: u64) -> rat/1`
- `0x1F num.with_unit(a, u: string) -> num`
- `0x20 num.assert_unit(a, u: string) -> num`
- `0x21 num.compare(a, b) -> int/1 {-1,0,1}`

- `num.from_decimal_str(s: string) -> dec/1`
- `num.from_f64_bits(bits: u64) -> bnd/1`
- `num.add(a, b) -> num`
- `num.sub(a, b) -> num`
- `num.mul(a, b) -> num`
- `num.div(a, b) -> num`
- `num.to_dec(a, scale: u32, rm: u8) -> dec/1`
- `num.to_rat(a, limit_den: u64) -> rat/1`
- `num.with_unit(a, u: string) -> num`
- `num.assert_unit(a, u: string) -> num`
- `num.compare(a, b) -> int/1 {-1,0,1}`

`rm`: 0=HALF_EVEN, 1=DOWN, 2=UP, 3=HALF_UP, 4=FLOOR, 5=CEIL.

Default TR wiring:
- `numeric_v1` profile is selected by default for `ubl/payment`, `ubl/invoice`, `ubl/settlement`, `ubl/quote`.
- `numeric_v1` bytecode canonicalizes `amount` (`NumToRat` + `NumToDec(scale=2)`), sets RC body, attaches input proof, and emits receipt.
