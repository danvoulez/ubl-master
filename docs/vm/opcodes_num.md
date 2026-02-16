# RB-VM — Numeric Opcodes (UNC-1)

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
