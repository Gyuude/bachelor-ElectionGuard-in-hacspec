//! # Seq Arithmetic
//! This library contains several handy functions to do basic arithmetic on byte sequences
//! 
//! There are several different ways of creating byte sequences, for example by converting from other numeric types.
//! 
//! If you wish to create a byte sequence directly, the easiest way we have found is to do the following:
//! 
//! ```text
//! bytes!(BSeq, 2);
//! 
//! let mySeq = BSeq(secret_bytes!([0x0fu8, 0x15u8])).to_be_bytes();
//! ```
//! 
//! Note that you have to specify the number of bytes you wish to input. 
//! When inputting multiple byte sequences of different length, you can avoid defining multiple types by defining a large sequence, padding with leading zeroes, and use be_seq_trim() to trim the zeroes away afterwards.
//! 
//! ```text
//! bytes!(BSeq, 6);
//! 
//! let myLongSeq = BSeq(secret_bytes!([
//!     0x0fu8, 0x15u8, 
//!     oxffu8, 0x0fu8, 
//!     0x15u8, oxffu8
//! ])).to_be_bytes();
//! 
//! let myShortSeq = be_seq_trim(&BSeq(secret_bytes!([
//!     0x00u8, 0x00u8, 
//!     ox00u8, 0x00u8, 
//!     0x15u8, oxffu8
//! ])).to_be_bytes());
//! ```


use hacspec_lib::*;

/// Adds two byte sequences of any length 
pub fn be_seq_add(a: &Seq<U8>, b: &Seq<U8>) -> Seq<U8> {
    let a_len = a.len();
    let b_len = b.len();

    let mut max_len = 0;
    if a_len >= b_len {
        max_len = a_len;
    } else {
        max_len = b_len;
    }


    let mut out = Seq::<U8>::new(max_len);

    let mut carry = U8::zero();

    for i in 0..max_len {

        let a_val = if i < a_len {a[a_len - 1 - i]} else {U8::zero()};
        let b_val = if i < b_len {b[b_len - 1 - i]} else {U8::zero()};

        let (o, c) = carry_add(a_val, b_val, carry);
        out[max_len - 1 - i] = o;
        carry = c
    }

    if !carry.equal(U8::zero())  {
        let mut temp = Seq::<U8>::new(1);
        temp[0] = carry;
        out = temp.concat_owned(out);
    }

    out
}

/// Subtracts two byte sequences of any length, returns result as well as bool stating if theres underflow or not
pub fn be_seq_sub(a: &Seq<U8>, b: &Seq<U8>) -> (Seq<U8>, bool) {
    let a_len = a.len();
    let b_len = b.len();

    let mut max_len = 0;
    if a_len >= b_len {
        max_len = a_len;
    } else {
        max_len = b_len;
    }

    let mut out = Seq::<U8>::new(max_len);

    let mut borrow = false;

    for i in 0..max_len {

        let a_val = if i < a_len {a[a_len - 1 - i]} else {U8::zero()};
        let b_val = if i < b_len {b[b_len - 1 - i]} else {U8::zero()};

        let (o, c) = borrow_sub(a_val, b_val, borrow);
        out[max_len - 1 - i] = o;
        borrow = c
    }
    
    (be_seq_trim(&out), borrow)
}

/// Mulitplies two byte sequences of any length and returns the product
pub fn be_seq_mul(a: &Seq<U8>, b: &Seq<U8>) -> Seq<U8> {
    let a_len = a.len();
    let b_len = b.len();

    let mut out = Seq::<U8>::new(1);
    out[0] = U8::zero();

    for i in 0..b_len {
        let b_val = b[b_len - 1 - i];

        let mut carry = U8::zero();
        let mut acc = Seq::<U8>::new(i);
        for n in 0..i {
            acc[n] = U8::zero();
        }

        for j in 0..a_len {
            let a_val = a[a_len - 1 - j];
            let (o, c) = carry_mul(a_val, b_val, carry);

            let mut temp = Seq::<U8>::new(1);
            temp[0] = o;
            acc = temp.concat_owned(acc);

            carry = c;
        }

        if !carry.equal(U8::zero()) {
            let mut temp = Seq::<U8>::new(1);
            temp[0] = carry;
            acc = temp.concat_owned(acc);
        }

        out = be_seq_add(&out, &acc);
    }
    out
}

/// Makes integer division on two byte sequences of any length and returns (quotient, remainder)
/// Returns 0 when trying to divide by 0
/// TODO: Give error when dividing by 0
pub fn be_seq_div(a: &Seq<U8>, b: &Seq<U8>) -> (Seq<U8>, Seq<U8>) {
    let mut res = (seq_zero(), seq_zero());
    if !seq_eq(b, &seq_zero()) {
        let mut quotient = Seq::<U8>::new(0);

        let a_len = a.len();

        let mut dividend = a.clone();
        let mut divisor = b.clone();

        let a_llen = a_len - 1;

        divisor = seq_shift_left(divisor, a_llen);

        for i in 0..(a_len) {
            let (count, remainder) = slow_div(&dividend, &divisor);

            let mut count_seq = Seq::<U8>::new(1);
            count_seq[0] = count;
            quotient = quotient.concat_owned(count_seq);
            dividend = remainder;

            let (t, d) = divisor.get_chunk(a_len - 1 - i, 0);
            divisor = d;
        }

        res = (quotient, dividend);
    }

    res
}

/// Calculates exponents NOTE: only supports exponents of max size usize
/// TODO: Add support of any size exponents, perhaps put loops in a seperate function that supports loops to a byteSeq max
pub fn be_seq_exp(a: &Seq<U8>, exp: &usize) -> Seq<U8> {
    
    let mut res = a.clone();

    if seq_eq(&res, &seq_zero()) {
        res = seq_one();
    } else {
        for i in 1..exp.clone() {
            let temp = res.clone();
            res = be_seq_mul(&temp, a);
        }
    }

    res
}

/// Performs modular exponentiation i. e. a^b mod n
/// Is designed to avoid extremely large intermediate values
/// Uses the square multiply algorithm
pub fn be_seq_mod_exp(a: &Seq<U8>, b: &Seq<U8>, c: &Seq<U8>) -> Seq<U8> {
    /// NOT IMPLEMENTED
    seq_one()
}

/// Trims a byte sequence by removing leading zeroes. Returns the trimmed byte sequence
pub fn be_seq_trim(a: &Seq<U8>) -> Seq<U8> {
    let mut out = a.clone();
    if a.len() >= 1 {
        let mut flag = true;
        for i in 0..(a.len() - 1) {
            if a[i].equal(U8::zero()) && flag {
                let (t, o) = out.clone().pop();
                out = o;
            } else {
                flag = false;
            }
        }
    }
    out
}

/// Adds n trailing bytes with value zero to a
pub fn seq_shift_left(a: Seq<U8>, n: usize) -> Seq<U8> {
    let mut zeroes = Seq::<U8>::new(n);
    
    for i in 0..n {
        zeroes[i] = U8::zero();
    }

    let shifted = a.concat_owned(zeroes);

    shifted
}

/// Adds n leading bytes with value zero to a
pub fn seq_shift_right(a: Seq<U8>, n: usize) -> Seq<U8> {
    let mut zeroes = Seq::<U8>::new(n);
    
    for i in 0..n {
        zeroes[i] = U8::zero();
    }

    let shifted = zeroes.concat_owned(a);

    shifted
}

/// returns byte sequence with value zero
pub fn seq_zero() -> Seq<U8> {
    let mut zero = Seq::<U8>::new(1);
    zero[0] = U8::zero();
    zero
}

/// returns byte sequence with value one
pub fn seq_one() -> Seq<U8> {
    let mut one = Seq::<U8>::new(1);
    one[0] = U8::one();
    one
}

/// Trims and compares two byte sequences, returns true if equal 
pub fn seq_eq(a: &Seq<U8>, b: &Seq<U8>) -> bool {
    let a_trim = be_seq_trim(&a.clone());
    let b_trim = be_seq_trim(&b.clone());

    let mut equal = true;

    if a_trim.len() != b_trim.len() {
        equal = false;
    } else {
        
        for i in 0..a_trim.len() {
            if !a_trim[i].equal(b_trim[i]) {
                equal = false;
            }
        }
    }
    equal
}

fn carry_add(a: U8, b: U8, carry: U8) -> (U8, U8) {
    let c = U16_from_U8(a) + U16_from_U8(b) + U16_from_U8(carry);
    (U8_from_U16(c), U8_from_U16(c >> 8))
}

fn carry_mul(a: U8, b: U8, carry: U8) -> (U8, U8) {
    let c = U16_from_U8(a) * U16_from_U8(b) + U16_from_U8(carry);
    (U8_from_U16(c), U8_from_U16(c >> 8))
}

fn borrow_sub(a: U8, b: U8, borrow: bool) -> (U8, bool) {
    let mut al = U16_from_U8(a);
    let bl = U16_from_U8(b);
    let mut bor = false;
    if borrow {
        if al.declassify() == u16::zero() {
            bor = true;
            al = U16::from_literal(256);
        }
        al = al - U16::one();
    }

    if bl.declassify() > al.declassify() {
        bor = true;
        al = al + U16::from_literal(256);
    }

    (U8_from_U16(al - bl), bor)
}

fn slow_div(a: &Seq<U8>, b: &Seq<U8>) -> (U8, Seq<U8>) {
    let (rest, u) = be_seq_sub(&a.clone(), &b.clone());
    let mut result = (U8::zero(), a.clone());
    if !u {
        let (n, out) = slow_div(&rest, b);
        result = (n + U8::one(), out);
    }

    result
}

/// Converts a byte sequence to a U128 
pub fn seq_to_U128(a: &Seq<U8>) -> U128 {
    let mut res = U128::ZERO();

    let mut max_len = 16;

    let base: usize = 256;

    if a.len() < max_len {
        max_len = a.len();
    }

    for i in 0..max_len {
        res = res + U128_from_U8(a[i]) * U128_from_usize(base.pow(i as u32));
    }

    res
}

/// Converts a byte sequence to usize
pub fn seq_to_usize(a: &Seq<U8>) -> usize {
    // UNIMPLEMENTED
    0
}

/// Converts a U32 to Seq<U8>
pub fn be_U32_to_seq(a: &U32) -> Seq<U8> {
    // UNIMPLEMENTED
    seq_one()
}

/// Returns true if a is less or equal to b
pub fn seq_leq(a: &Seq<U8>, b: &Seq<U8>) -> bool {
    // UNIMPLEMENTED
    false
}

// Modular operation. Finds the rest when dividing two numbers
pub fn be_seq_mod(a: &Seq<U8>, b: &Seq<U8>) -> Seq<U8> {
    let (q, m) = be_seq_div(&a, &b);

    m
}

pub fn be_seq_mul_mod(a: &Seq<U8>, b: &Seq<U8>, m: &Seq<U8>) -> Seq<U8> {
    let a_mod = be_seq_mod(&a, &m);
    let b_mod = be_seq_mod(&b, &m);

    let product = be_seq_mul(&a_mod, &b_mod);

    let res = be_seq_mod(&product, &m);

    res
}