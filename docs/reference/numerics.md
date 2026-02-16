# UNC-1 — UBL Numeric Canon v1
_Gerado em 2026-02-16_

UNC-1 define números canônicos determinísticos `{
  "@num": "int/1|dec/1|rat/1|bnd/1", ... }` com **opcional unidade `u`**.

- **INT**: `"@num":"int/1","v":"-42"`
- **DEC**: `"@num":"dec/1","m":"12345","s":3` → 12.345
- **RAT**: `"@num":"rat/1","p":"22","q":"7"`
- **BND**: `"@num":"bnd/1","lo":<Num>,"hi":<Num>`

## Regras principais
- Sem IEEE-754 no canon; floats binários são **importados** como **BND**.
- Arredondamento (RM) só quando *reduzir*: `to_dec(scale, rm)`.
- Unidades: campo `"u"`; operações exigem compatibilidade.

## Fronteira com floats
- `f64` entra via `num.from_f64_bits(u64)` → `bnd/1` mínimo que contém o valor.
- `NaN/Inf` → erro `NUMERIC_VALUE_INVALID`.

## Aritmética (resumo)
- Promoção: `INT→DEC→RAT→BND`.
- `BND`: aritmética de intervalos; `lo` arredonda para **baixo**, `hi` para **cima**.
- Colapso: `to_dec(scale, rm)`; `to_rat(limit_den)`; `bound(width, rm)`.

## Limites sugeridos (política)
- `max_decimal_digits`, `max_denominator`, `max_interval_width`, `require_unit`.
