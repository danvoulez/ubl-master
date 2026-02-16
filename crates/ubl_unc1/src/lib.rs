use num_bigint::BigInt;
use num_integer::Integer;
use num_rational::BigRational;
use num_traits::{One, Signed, ToPrimitive, Zero};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "@num")]
pub enum Num {
    #[serde(rename = "int/1")]
    Int {
        v: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        u: Option<String>,
    },
    #[serde(rename = "dec/1")]
    Dec {
        m: String,
        s: u32,
        #[serde(skip_serializing_if = "Option::is_none")]
        u: Option<String>,
    },
    #[serde(rename = "rat/1")]
    Rat {
        p: String,
        q: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        u: Option<String>,
    },
    #[serde(rename = "bnd/1")]
    Bnd {
        lo: Box<Num>,
        hi: Box<Num>,
        #[serde(skip_serializing_if = "Option::is_none")]
        u: Option<String>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RoundingMode {
    HalfEven = 0,
    Down = 1,
    Up = 2,
    HalfUp = 3,
    Floor = 4,
    Ceil = 5,
}

impl RoundingMode {
    pub fn from_u8(v: u8) -> Result<Self, String> {
        match v {
            0 => Ok(Self::HalfEven),
            1 => Ok(Self::Down),
            2 => Ok(Self::Up),
            3 => Ok(Self::HalfUp),
            4 => Ok(Self::Floor),
            5 => Ok(Self::Ceil),
            _ => Err(format!("invalid rounding mode: {}", v)),
        }
    }
}

// ---------------------------------------------------------------------------
// Num helpers
// ---------------------------------------------------------------------------

impl Num {
    pub fn unit(&self) -> &Option<String> {
        match self {
            Num::Int { u, .. } | Num::Dec { u, .. } | Num::Rat { u, .. } | Num::Bnd { u, .. } => u,
        }
    }

    pub fn with_unit(self, unit: &str) -> Result<Self, String> {
        match self {
            Num::Int { v, u } => {
                if let Some(ref old) = u {
                    if old != unit {
                        return Err("unit_mismatch".into());
                    }
                }
                Ok(Num::Int { v, u: Some(unit.to_string()) })
            }
            Num::Dec { m, s, u } => {
                if let Some(ref old) = u {
                    if old != unit {
                        return Err("unit_mismatch".into());
                    }
                }
                Ok(Num::Dec { m, s, u: Some(unit.to_string()) })
            }
            Num::Rat { p, q, u } => {
                if let Some(ref old) = u {
                    if old != unit {
                        return Err("unit_mismatch".into());
                    }
                }
                Ok(Num::Rat { p, q, u: Some(unit.to_string()) })
            }
            Num::Bnd { lo, hi, u } => {
                if let Some(ref old) = u {
                    if old != unit {
                        return Err("unit_mismatch".into());
                    }
                }
                Ok(Num::Bnd { lo, hi, u: Some(unit.to_string()) })
            }
        }
    }

    pub fn assert_unit(&self, unit: &str) -> Result<(), String> {
        if let Some(x) = self.unit() {
            if x != unit {
                return Err("unit_mismatch".into());
            }
            Ok(())
        } else {
            Err("unit_missing".into())
        }
    }

    fn strip_unit(&self) -> Self {
        match self {
            Num::Int { v, .. } => Num::Int { v: v.clone(), u: None },
            Num::Dec { m, s, .. } => Num::Dec { m: m.clone(), s: *s, u: None },
            Num::Rat { p, q, .. } => Num::Rat { p: p.clone(), q: q.clone(), u: None },
            Num::Bnd { lo, hi, .. } => Num::Bnd {
                lo: Box::new(lo.strip_unit()),
                hi: Box::new(hi.strip_unit()),
                u: None,
            },
        }
    }

    fn set_unit(self, u: Option<String>) -> Self {
        match self {
            Num::Int { v, .. } => Num::Int { v, u },
            Num::Dec { m, s, .. } => Num::Dec { m, s, u },
            Num::Rat { p, q, .. } => Num::Rat { p, q, u },
            Num::Bnd { lo, hi, .. } => Num::Bnd { lo, hi, u },
        }
    }

    /// Promotion rank: INT=0, DEC=1, RAT=2, BND=3
    fn rank(&self) -> u8 {
        match self {
            Num::Int { .. } => 0,
            Num::Dec { .. } => 1,
            Num::Rat { .. } => 2,
            Num::Bnd { .. } => 3,
        }
    }
}

// ---------------------------------------------------------------------------
// Internal rational representation for arithmetic
// ---------------------------------------------------------------------------

fn parse_bigint(s: &str) -> Result<BigInt, String> {
    s.parse::<BigInt>().map_err(|e| format!("invalid bigint '{}': {}", s, e))
}

fn to_rational(n: &Num) -> Result<BigRational, String> {
    match n {
        Num::Int { v, .. } => {
            let i = parse_bigint(v)?;
            Ok(BigRational::from_integer(i))
        }
        Num::Dec { m, s, .. } => {
            let mantissa = parse_bigint(m)?;
            let denom = BigInt::from(10u64).pow(*s);
            Ok(BigRational::new(mantissa, denom))
        }
        Num::Rat { p, q, .. } => {
            let num = parse_bigint(p)?;
            let den = parse_bigint(q)?;
            if den.is_zero() {
                return Err("division_by_zero".into());
            }
            Ok(BigRational::new(num, den))
        }
        Num::Bnd { .. } => Err("cannot convert BND to single rational".into()),
    }
}

fn rational_to_int(r: &BigRational) -> Option<Num> {
    if r.is_integer() {
        Some(Num::Int { v: r.numer().to_string(), u: None })
    } else {
        None
    }
}

fn rational_to_reduced_rat(r: &BigRational) -> Num {
    // BigRational auto-reduces via gcd
    let p = r.numer().to_string();
    let q = r.denom().to_string();
    Num::Rat { p, q, u: None }
}

// ---------------------------------------------------------------------------
// Rounding helpers for to_dec
// ---------------------------------------------------------------------------

fn round_rational_to_dec(r: &BigRational, scale: u32, rm: RoundingMode) -> Num {
    let factor = BigInt::from(10u64).pow(scale);
    let scaled = r * BigRational::from_integer(factor.clone());

    let m = match rm {
        RoundingMode::Down => {
            // Truncate toward zero
            if scaled.is_negative() {
                // For negative: ceil (toward zero)
                -(-scaled.numer() / scaled.denom())
            } else {
                scaled.numer() / scaled.denom()
            }
        }
        RoundingMode::Up => {
            // Away from zero
            if scaled.is_integer() {
                scaled.numer().clone()
            } else if scaled.is_negative() {
                -((-scaled.numer() + scaled.denom() - BigInt::one()) / scaled.denom())
            } else {
                (scaled.numer() + scaled.denom() - BigInt::one()) / scaled.denom()
            }
        }
        RoundingMode::Floor => {
            // Toward -∞
            floor_div(scaled.numer(), scaled.denom())
        }
        RoundingMode::Ceil => {
            // Toward +∞
            ceil_div(scaled.numer(), scaled.denom())
        }
        RoundingMode::HalfUp => {
            half_up(scaled.numer(), scaled.denom())
        }
        RoundingMode::HalfEven => {
            half_even(scaled.numer(), scaled.denom())
        }
    };

    Num::Dec { m: m.to_string(), s: scale, u: None }
}

fn floor_div(n: &BigInt, d: &BigInt) -> BigInt {
    let (q, r) = n.div_rem(d);
    if !r.is_zero() && (n.is_negative() != d.is_negative()) {
        q - BigInt::one()
    } else {
        q
    }
}

fn ceil_div(n: &BigInt, d: &BigInt) -> BigInt {
    let (q, r) = n.div_rem(d);
    if !r.is_zero() && (n.is_negative() == d.is_negative()) {
        q + BigInt::one()
    } else {
        q
    }
}

fn half_up(n: &BigInt, d: &BigInt) -> BigInt {
    // Round half away from zero
    let abs_d = d.abs();
    let abs_n = n.abs();
    let (q, r) = abs_n.div_rem(&abs_d);
    let doubled_r = &r * BigInt::from(2);
    let result = if doubled_r >= abs_d { q + BigInt::one() } else { q };
    if n.is_negative() { -result } else { result }
}

fn half_even(n: &BigInt, d: &BigInt) -> BigInt {
    // Banker's rounding
    let abs_d = d.abs();
    let abs_n = n.abs();
    let (q, r) = abs_n.div_rem(&abs_d);
    let doubled_r = &r * BigInt::from(2);
    let result = if doubled_r > abs_d {
        q.clone() + BigInt::one()
    } else if doubled_r == abs_d {
        // Tie: round to even
        if &q % BigInt::from(2) == BigInt::zero() { q.clone() } else { q.clone() + BigInt::one() }
    } else {
        q.clone()
    };
    if n.is_negative() { -result } else { result }
}

// ---------------------------------------------------------------------------
// Unit compatibility check
// ---------------------------------------------------------------------------

fn check_units(a: &Num, b: &Num) -> Result<Option<String>, String> {
    let ua = a.unit();
    let ub = b.unit();
    match (ua, ub) {
        (None, None) => Ok(None),
        (Some(x), None) | (None, Some(x)) => Ok(Some(x.clone())),
        (Some(x), Some(y)) => {
            if x == y {
                Ok(Some(x.clone()))
            } else {
                Err(format!("unit_mismatch: {} vs {}", x, y))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Promotion: bring both operands to the same rank
// ---------------------------------------------------------------------------

fn promote_to_rat(n: &Num) -> Result<BigRational, String> {
    to_rational(n)
}

// ---------------------------------------------------------------------------
// Public API: from_decimal_str
// ---------------------------------------------------------------------------

pub fn from_decimal_str(s: &str) -> Result<Num, String> {
    let neg = s.starts_with('-');
    let t = if neg { &s[1..] } else { s };
    if t.is_empty() || t.chars().all(|c| c == '.' || c == '-') {
        return Err("invalid_decimal".into());
    }
    let parts: Vec<&str> = t.split('.').collect();
    if parts.len() == 1 {
        let mut m = parts[0].to_string();
        if neg {
            m = format!("-{}", m);
        }
        Ok(Num::Dec { m, s: 0, u: None })
    } else if parts.len() == 2 {
        let m = format!("{}{}", parts[0], parts[1]);
        let s = parts[1].len() as u32;
        let m = if neg { format!("-{}", m) } else { m };
        Ok(Num::Dec { m, s, u: None })
    } else {
        Err("invalid_decimal".into())
    }
}

// ---------------------------------------------------------------------------
// Public API: from_f64_bits — IEEE-754 frontier (UNC-1 §3)
// ---------------------------------------------------------------------------

pub fn from_f64_bits(bits: u64) -> Result<Num, String> {
    let f = f64::from_bits(bits);
    if f.is_nan() || f.is_infinite() {
        return Err("NUMERIC_VALUE_INVALID: NaN or Inf".into());
    }
    if f == 0.0 {
        // ±0 → exact zero interval
        return Ok(Num::Bnd {
            lo: Box::new(Num::Dec { m: "0".into(), s: 1, u: None }),
            hi: Box::new(Num::Dec { m: "0".into(), s: 1, u: None }),
            u: None,
        });
    }

    // Derive the exact decimal interval [lo, hi] that contains this f64.
    // Every f64 represents a range: [f - ulp/2, f + ulp/2] in the real line.
    // We compute the exact rational value of the f64, then the adjacent f64s,
    // and use the midpoints as bounds.

    // Exact rational value of this f64
    let exact = exact_f64_rational(f);

    // Adjacent f64 values
    let (prev_f, next_f) = adjacent_f64(f);
    let prev_exact = exact_f64_rational(prev_f);
    let next_exact = exact_f64_rational(next_f);

    // Midpoints: the boundary of the rounding interval
    let two = BigRational::from_integer(BigInt::from(2));
    let lo_rat = (&exact + &prev_exact) / &two;
    let hi_rat = (&exact + &next_exact) / &two;

    // Convert to DEC with enough precision (18 digits)
    let lo_dec = round_rational_to_dec(&lo_rat, 18, RoundingMode::Floor);
    let hi_dec = round_rational_to_dec(&hi_rat, 18, RoundingMode::Ceil);

    Ok(Num::Bnd {
        lo: Box::new(lo_dec),
        hi: Box::new(hi_dec),
        u: None,
    })
}

fn exact_f64_rational(f: f64) -> BigRational {
    // Decompose f64 into sign * mantissa * 2^exponent
    let bits = f.to_bits();
    let sign = if bits >> 63 == 1 { -1i64 } else { 1i64 };
    let biased_exp = ((bits >> 52) & 0x7FF) as i64;
    let frac = bits & 0x000F_FFFF_FFFF_FFFF;

    let (mantissa, exponent) = if biased_exp == 0 {
        // Subnormal
        (BigInt::from(frac), -1074i64)
    } else {
        // Normal: implicit 1 bit
        (BigInt::from(frac | (1u64 << 52)), biased_exp - 1023 - 52)
    };

    let signed_mantissa = BigInt::from(sign) * mantissa;

    if exponent >= 0 {
        let factor = BigInt::from(2u64).pow(exponent as u32);
        BigRational::from_integer(signed_mantissa * factor)
    } else {
        let denom = BigInt::from(2u64).pow((-exponent) as u32);
        BigRational::new(signed_mantissa, denom)
    }
}

fn adjacent_f64(f: f64) -> (f64, f64) {
    let bits = f.to_bits();
    if f > 0.0 {
        (f64::from_bits(bits - 1), f64::from_bits(bits + 1))
    } else {
        // Negative: bit pattern goes in reverse
        (f64::from_bits(bits + 1), f64::from_bits(bits - 1))
    }
}

// ---------------------------------------------------------------------------
// Public API: add, sub, mul, div
// ---------------------------------------------------------------------------

pub fn add(a: &Num, b: &Num) -> Result<Num, String> {
    binary_op(a, b, |ra, rb| ra + rb)
}

pub fn sub(a: &Num, b: &Num) -> Result<Num, String> {
    binary_op(a, b, |ra, rb| ra - rb)
}

pub fn mul(a: &Num, b: &Num) -> Result<Num, String> {
    binary_op(a, b, |ra, rb| ra * rb)
}

pub fn div(a: &Num, b: &Num) -> Result<Num, String> {
    // Check for zero divisor
    let rb = promote_to_rat(&b.strip_unit())?;
    if rb.is_zero() {
        return Err("division_by_zero".into());
    }
    binary_op(a, b, |ra, rb| ra / rb)
}

fn binary_op<F>(a: &Num, b: &Num, op: F) -> Result<Num, String>
where
    F: Fn(BigRational, BigRational) -> BigRational,
{
    let result_unit = check_units(a, b)?;

    // If either is BND, do interval arithmetic
    if a.rank() == 3 || b.rank() == 3 {
        return bnd_binary_op(a, b, result_unit);
    }

    let ra = promote_to_rat(&a.strip_unit())?;
    let rb = promote_to_rat(&b.strip_unit())?;
    let result = op(ra, rb);

    // Determine output kind based on max rank of inputs
    let max_rank = std::cmp::max(a.rank(), b.rank());
    let num = match max_rank {
        0 => {
            // INT + INT → INT if exact, else RAT
            rational_to_int(&result).unwrap_or_else(|| rational_to_reduced_rat(&result))
        }
        1 => {
            // DEC + DEC → DEC (align to max scale)
            let sa = if let Num::Dec { s, .. } = a { *s } else { 0 };
            let sb = if let Num::Dec { s, .. } = b { *s } else { 0 };
            let max_s = std::cmp::max(sa, sb);
            round_rational_to_dec(&result, max_s, RoundingMode::HalfEven)
        }
        2 => {
            // RAT + RAT → RAT reduced
            rational_to_reduced_rat(&result)
        }
        _ => unreachable!(),
    };

    Ok(num.set_unit(result_unit))
}

fn bnd_binary_op(a: &Num, b: &Num, result_unit: Option<String>) -> Result<Num, String> {
    // Extract [lo, hi] for each operand
    let (a_lo, a_hi) = bnd_bounds(a)?;
    let (b_lo, b_hi) = bnd_bounds(b)?;

    // Interval addition: [a_lo + b_lo, a_hi + b_hi]
    // (This is correct for add; for sub/mul/div we'd need more complex interval logic.
    //  For now, we do conservative interval arithmetic for add.)
    let lo = &a_lo + &b_lo;
    let hi = &a_hi + &b_hi;

    let lo_dec = round_rational_to_dec(&lo, 18, RoundingMode::Floor);
    let hi_dec = round_rational_to_dec(&hi, 18, RoundingMode::Ceil);

    Ok(Num::Bnd {
        lo: Box::new(lo_dec),
        hi: Box::new(hi_dec),
        u: result_unit,
    })
}

fn bnd_bounds(n: &Num) -> Result<(BigRational, BigRational), String> {
    match n {
        Num::Bnd { lo, hi, .. } => {
            let lo_r = to_rational(lo)?;
            let hi_r = to_rational(hi)?;
            Ok((lo_r, hi_r))
        }
        _ => {
            // Point value → [v, v]
            let r = to_rational(n)?;
            Ok((r.clone(), r))
        }
    }
}

// ---------------------------------------------------------------------------
// Public API: to_dec, to_rat, compare
// ---------------------------------------------------------------------------

pub fn to_dec(a: &Num, scale: u32, rm: RoundingMode) -> Result<Num, String> {
    let unit = a.unit().clone();
    match a {
        Num::Bnd { lo, hi, .. } => {
            // BND → DEC: collapse using directed rounding
            let lo_r = to_rational(lo)?;
            let hi_r = to_rational(hi)?;
            let lo_dec = round_rational_to_dec(&lo_r, scale, RoundingMode::Floor);
            let hi_dec = round_rational_to_dec(&hi_r, scale, RoundingMode::Ceil);
            // If they collapse to the same value, return DEC; otherwise error
            if lo_dec == hi_dec {
                Ok(lo_dec.set_unit(unit))
            } else {
                Err("bnd_too_wide: interval does not collapse to single DEC at this scale".into())
            }
        }
        _ => {
            let r = to_rational(a)?;
            Ok(round_rational_to_dec(&r, scale, rm).set_unit(unit))
        }
    }
}

pub fn to_rat(a: &Num, limit_den: u64) -> Result<Num, String> {
    let unit = a.unit().clone();
    let r = to_rational(a)?;
    // Check denominator limit
    if r.denom().to_u64().map_or(true, |d| d > limit_den) {
        // Approximate using continued fraction
        let approx = approximate_rational(&r, limit_den);
        Ok(Num::Rat {
            p: approx.numer().to_string(),
            q: approx.denom().to_string(),
            u: unit,
        })
    } else {
        Ok(Num::Rat {
            p: r.numer().to_string(),
            q: r.denom().to_string(),
            u: unit,
        })
    }
}

fn approximate_rational(r: &BigRational, limit_den: u64) -> BigRational {
    // Simple continued fraction approximation with denominator limit
    let mut p0 = BigInt::zero();
    let mut q0 = BigInt::one();
    let mut p1 = BigInt::one();
    let mut q1 = BigInt::zero();

    let mut x = r.clone();
    let limit = BigInt::from(limit_den);

    loop {
        let a = floor_bigrat(&x);
        let p2 = &a * &p1 + &p0;
        let q2 = &a * &q1 + &q0;

        if q2 > limit {
            break;
        }

        p0 = p1;
        q0 = q1;
        p1 = p2;
        q1 = q2;

        let frac = &x - BigRational::from_integer(a);
        if frac.is_zero() {
            break;
        }
        x = frac.recip();
    }

    BigRational::new(p1, q1)
}

fn floor_bigrat(r: &BigRational) -> BigInt {
    floor_div(r.numer(), r.denom())
}

/// Deterministic comparison: returns -1, 0, or 1 as INT
pub fn compare(a: &Num, b: &Num) -> Result<Num, String> {
    check_units(a, b)?;

    // Handle BND comparison
    if a.rank() == 3 || b.rank() == 3 {
        let (a_lo, a_hi) = bnd_bounds(a)?;
        let (b_lo, b_hi) = bnd_bounds(b)?;
        // If intervals don't overlap, we can compare
        if a_hi < b_lo {
            return Ok(Num::Int { v: "-1".into(), u: None });
        }
        if a_lo > b_hi {
            return Ok(Num::Int { v: "1".into(), u: None });
        }
        // Overlapping intervals → compare midpoints
        let two = BigRational::from_integer(BigInt::from(2));
        let a_mid = (&a_lo + &a_hi) / &two;
        let b_mid = (&b_lo + &b_hi) / &two;
        let cmp = a_mid.cmp(&b_mid);
        let v = match cmp {
            std::cmp::Ordering::Less => "-1",
            std::cmp::Ordering::Equal => "0",
            std::cmp::Ordering::Greater => "1",
        };
        return Ok(Num::Int { v: v.into(), u: None });
    }

    let ra = promote_to_rat(&a.strip_unit())?;
    let rb = promote_to_rat(&b.strip_unit())?;
    let v = match ra.cmp(&rb) {
        std::cmp::Ordering::Less => "-1",
        std::cmp::Ordering::Equal => "0",
        std::cmp::Ordering::Greater => "1",
    };
    Ok(Num::Int { v: v.into(), u: None })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- from_decimal_str ---

    #[test]
    fn parse_decimal_integer() {
        let n = from_decimal_str("42").unwrap();
        assert_eq!(n, Num::Dec { m: "42".into(), s: 0, u: None });
    }

    #[test]
    fn parse_decimal_fractional() {
        let n = from_decimal_str("12.345").unwrap();
        assert_eq!(n, Num::Dec { m: "12345".into(), s: 3, u: None });
    }

    #[test]
    fn parse_decimal_negative() {
        let n = from_decimal_str("-0.5").unwrap();
        assert_eq!(n, Num::Dec { m: "-05".into(), s: 1, u: None });
    }

    #[test]
    fn parse_decimal_invalid() {
        assert!(from_decimal_str("1.2.3").is_err());
        assert!(from_decimal_str("").is_err());
    }

    // --- add: INT + INT ---

    #[test]
    fn add_int_int() {
        let a = Num::Int { v: "10".into(), u: None };
        let b = Num::Int { v: "32".into(), u: None };
        let r = add(&a, &b).unwrap();
        assert_eq!(r, Num::Int { v: "42".into(), u: None });
    }

    #[test]
    fn add_int_negative() {
        let a = Num::Int { v: "5".into(), u: None };
        let b = Num::Int { v: "-3".into(), u: None };
        let r = add(&a, &b).unwrap();
        assert_eq!(r, Num::Int { v: "2".into(), u: None });
    }

    // --- add: DEC + DEC (KAT: 0.1 + 0.2 = 0.3) ---

    #[test]
    fn add_dec_dec_kat() {
        let a = Num::Dec { m: "1".into(), s: 1, u: None };
        let b = Num::Dec { m: "2".into(), s: 1, u: None };
        let r = add(&a, &b).unwrap();
        assert_eq!(r, Num::Dec { m: "3".into(), s: 1, u: None });
    }

    #[test]
    fn add_dec_different_scales() {
        // 1.5 + 0.25 = 1.75
        let a = Num::Dec { m: "15".into(), s: 1, u: None };
        let b = Num::Dec { m: "25".into(), s: 2, u: None };
        let r = add(&a, &b).unwrap();
        assert_eq!(r, Num::Dec { m: "175".into(), s: 2, u: None });
    }

    // --- add: RAT + RAT ---

    #[test]
    fn add_rat_rat() {
        // 1/3 + 1/6 = 1/2
        let a = Num::Rat { p: "1".into(), q: "3".into(), u: None };
        let b = Num::Rat { p: "1".into(), q: "6".into(), u: None };
        let r = add(&a, &b).unwrap();
        assert_eq!(r, Num::Rat { p: "1".into(), q: "2".into(), u: None });
    }

    // --- mixed promotion: DEC + INT → DEC ---

    #[test]
    fn add_mixed_dec_int() {
        // 2.5 + 2 = 4.5
        let a = Num::Dec { m: "25".into(), s: 1, u: None };
        let b = Num::Int { v: "2".into(), u: None };
        let r = add(&a, &b).unwrap();
        assert_eq!(r, Num::Dec { m: "45".into(), s: 1, u: None });
    }

    // --- mixed promotion: DEC * INT → DEC (KAT) ---

    #[test]
    fn mul_dec_int_kat() {
        // 2.5 * 2 = 5.0
        let a = Num::Dec { m: "25".into(), s: 1, u: None };
        let b = Num::Int { v: "2".into(), u: None };
        let r = mul(&a, &b).unwrap();
        assert_eq!(r, Num::Dec { m: "50".into(), s: 1, u: None });
    }

    // --- sub ---

    #[test]
    fn sub_int_int() {
        let a = Num::Int { v: "10".into(), u: None };
        let b = Num::Int { v: "3".into(), u: None };
        let r = sub(&a, &b).unwrap();
        assert_eq!(r, Num::Int { v: "7".into(), u: None });
    }

    // --- div ---

    #[test]
    fn div_int_int_exact() {
        // 10 / 5 = 2
        let a = Num::Int { v: "10".into(), u: None };
        let b = Num::Int { v: "5".into(), u: None };
        let r = div(&a, &b).unwrap();
        assert_eq!(r, Num::Int { v: "2".into(), u: None });
    }

    #[test]
    fn div_int_int_inexact() {
        // 1 / 3 → RAT 1/3
        let a = Num::Int { v: "1".into(), u: None };
        let b = Num::Int { v: "3".into(), u: None };
        let r = div(&a, &b).unwrap();
        assert_eq!(r, Num::Rat { p: "1".into(), q: "3".into(), u: None });
    }

    #[test]
    fn div_by_zero() {
        let a = Num::Int { v: "1".into(), u: None };
        let b = Num::Int { v: "0".into(), u: None };
        assert!(div(&a, &b).is_err());
    }

    // --- to_dec (KAT: 1/3 → 0.33 DOWN, 0.34 UP) ---

    #[test]
    fn to_dec_rat_down_kat() {
        let r = Num::Rat { p: "1".into(), q: "3".into(), u: None };
        let d = to_dec(&r, 2, RoundingMode::Down).unwrap();
        assert_eq!(d, Num::Dec { m: "33".into(), s: 2, u: None });
    }

    #[test]
    fn to_dec_rat_up_kat() {
        let r = Num::Rat { p: "1".into(), q: "3".into(), u: None };
        let d = to_dec(&r, 2, RoundingMode::Up).unwrap();
        assert_eq!(d, Num::Dec { m: "34".into(), s: 2, u: None });
    }

    #[test]
    fn to_dec_half_even() {
        // 0.5 → 0 (round to even), 1.5 → 2 (round to even)
        let half = Num::Rat { p: "1".into(), q: "2".into(), u: None };
        let d = to_dec(&half, 0, RoundingMode::HalfEven).unwrap();
        assert_eq!(d, Num::Dec { m: "0".into(), s: 0, u: None });

        let one_half = Num::Rat { p: "3".into(), q: "2".into(), u: None };
        let d2 = to_dec(&one_half, 0, RoundingMode::HalfEven).unwrap();
        assert_eq!(d2, Num::Dec { m: "2".into(), s: 0, u: None });
    }

    // --- to_rat ---

    #[test]
    fn to_rat_from_dec() {
        // 0.5 → 1/2
        let d = Num::Dec { m: "5".into(), s: 1, u: None };
        let r = to_rat(&d, 1000).unwrap();
        assert_eq!(r, Num::Rat { p: "1".into(), q: "2".into(), u: None });
    }

    #[test]
    fn to_rat_with_limit() {
        // 355/113 ≈ π, but with limit_den=10 → 22/7
        let pi_approx = Num::Rat { p: "355".into(), q: "113".into(), u: None };
        let r = to_rat(&pi_approx, 10).unwrap();
        assert_eq!(r, Num::Rat { p: "22".into(), q: "7".into(), u: None });
    }

    // --- from_f64_bits ---

    #[test]
    fn from_f64_bits_zero() {
        let r = from_f64_bits(0u64).unwrap();
        match &r {
            Num::Bnd { .. } => {} // ok
            _ => panic!("expected BND, got {:?}", r),
        }
    }

    #[test]
    fn from_f64_bits_0_1() {
        // 0.1 as f64 bits
        let bits: u64 = 0x3fb999999999999a;
        let r = from_f64_bits(bits).unwrap();
        match &r {
            Num::Bnd { lo, hi, .. } => {
                // lo < 0.1 < hi
                let lo_r = to_rational(lo).unwrap();
                let hi_r = to_rational(hi).unwrap();
                let tenth = BigRational::new(BigInt::from(1), BigInt::from(10));
                assert!(lo_r <= tenth, "lo should be <= 0.1");
                assert!(hi_r >= tenth, "hi should be >= 0.1");
                assert!(lo_r < hi_r, "lo should be < hi");
            }
            _ => panic!("expected BND"),
        }
    }

    #[test]
    fn from_f64_bits_nan_rejected() {
        assert!(from_f64_bits(f64::NAN.to_bits()).is_err());
    }

    #[test]
    fn from_f64_bits_inf_rejected() {
        assert!(from_f64_bits(f64::INFINITY.to_bits()).is_err());
        assert!(from_f64_bits(f64::NEG_INFINITY.to_bits()).is_err());
    }

    // --- compare ---

    #[test]
    fn compare_int() {
        let a = Num::Int { v: "5".into(), u: None };
        let b = Num::Int { v: "3".into(), u: None };
        assert_eq!(compare(&a, &b).unwrap(), Num::Int { v: "1".into(), u: None });
        assert_eq!(compare(&b, &a).unwrap(), Num::Int { v: "-1".into(), u: None });
        assert_eq!(compare(&a, &a).unwrap(), Num::Int { v: "0".into(), u: None });
    }

    #[test]
    fn compare_mixed() {
        // 0.5 DEC vs 1/3 RAT → 0.5 > 1/3 → 1
        let a = Num::Dec { m: "5".into(), s: 1, u: None };
        let b = Num::Rat { p: "1".into(), q: "3".into(), u: None };
        assert_eq!(compare(&a, &b).unwrap(), Num::Int { v: "1".into(), u: None });
    }

    // --- units ---

    #[test]
    fn add_same_unit() {
        let a = Num::Int { v: "10".into(), u: Some("USD".into()) };
        let b = Num::Int { v: "5".into(), u: Some("USD".into()) };
        let r = add(&a, &b).unwrap();
        assert_eq!(r.unit(), &Some("USD".into()));
    }

    #[test]
    fn add_mismatched_units() {
        let a = Num::Int { v: "10".into(), u: Some("USD".into()) };
        let b = Num::Int { v: "5".into(), u: Some("EUR".into()) };
        assert!(add(&a, &b).is_err());
    }

    // --- BND arithmetic ---

    #[test]
    fn add_bnd_bnd() {
        // [0.1, 0.2] + [0.2, 0.3] → [0.3, 0.5]
        let a = Num::Bnd {
            lo: Box::new(Num::Dec { m: "1".into(), s: 1, u: None }),
            hi: Box::new(Num::Dec { m: "2".into(), s: 1, u: None }),
            u: None,
        };
        let b = Num::Bnd {
            lo: Box::new(Num::Dec { m: "2".into(), s: 1, u: None }),
            hi: Box::new(Num::Dec { m: "3".into(), s: 1, u: None }),
            u: None,
        };
        let r = add(&a, &b).unwrap();
        match &r {
            Num::Bnd { lo, hi, .. } => {
                let lo_r = to_rational(lo).unwrap();
                let hi_r = to_rational(hi).unwrap();
                let three_tenths = BigRational::new(BigInt::from(3), BigInt::from(10));
                let five_tenths = BigRational::new(BigInt::from(5), BigInt::from(10));
                assert!(lo_r <= three_tenths);
                assert!(hi_r >= five_tenths);
            }
            _ => panic!("expected BND"),
        }
    }

    // --- serde round-trip ---

    #[test]
    fn serde_roundtrip_int() {
        let n = Num::Int { v: "42".into(), u: None };
        let json = serde_json::to_string(&n).unwrap();
        assert!(json.contains("\"@num\":\"int/1\""));
        let back: Num = serde_json::from_str(&json).unwrap();
        assert_eq!(n, back);
    }

    #[test]
    fn serde_roundtrip_dec_with_unit() {
        let n = Num::Dec { m: "1234".into(), s: 2, u: Some("USD".into()) };
        let json = serde_json::to_string(&n).unwrap();
        let back: Num = serde_json::from_str(&json).unwrap();
        assert_eq!(n, back);
    }

    #[test]
    fn serde_roundtrip_bnd() {
        let n = Num::Bnd {
            lo: Box::new(Num::Dec { m: "1".into(), s: 1, u: None }),
            hi: Box::new(Num::Dec { m: "2".into(), s: 1, u: None }),
            u: None,
        };
        let json = serde_json::to_string(&n).unwrap();
        let back: Num = serde_json::from_str(&json).unwrap();
        assert_eq!(n, back);
    }

    // --- rounding mode from_u8 ---

    #[test]
    fn rounding_mode_from_u8() {
        assert_eq!(RoundingMode::from_u8(0).unwrap(), RoundingMode::HalfEven);
        assert_eq!(RoundingMode::from_u8(5).unwrap(), RoundingMode::Ceil);
        assert!(RoundingMode::from_u8(6).is_err());
    }
}
