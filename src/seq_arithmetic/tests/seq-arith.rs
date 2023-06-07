use hacspec_lib::*;
use seq_arithmetic::*;


#[test]
fn add_test() {
    let a = Seq::<U8>::from_hex("ABBA");
    let b = Seq::<U8>::from_hex("0A12BB");
    let out = be_seq_add(&a, &b);
    let res = Seq::<U8>::from_hex("0ABE75");
    assert_bytes_eq!(out, res);
}

#[test]
fn sub_test() {
    let a = Seq::<U8>::from_hex("A0CBA0");
    let b = Seq::<U8>::from_hex("83DA");
    let (out, borrow) = be_seq_sub(&a, &b);
    let res = Seq::<U8>::from_hex("A047C6");
    assert_bytes_eq!(out, res);
    assert!(!borrow);
}

#[test]
fn sub_underflow_test() {
    let a = Seq::<U8>::from_hex("83DA");
    let b = Seq::<U8>::from_hex("A0CBA0");
    let (_, borrow) = be_seq_sub(&a, &b);
    assert!(borrow);
}

#[test]
fn mul_test() {
    let a = Seq::<U8>::from_hex("ABBA");
    let b = Seq::<U8>::from_hex("0A12BB");
    let out = be_seq_mul(&a, &b);
    let res = Seq::<U8>::from_hex("06C1D484DE");
    assert_bytes_eq!(out, res);
}

#[test]
fn div_test() {
    let a = Seq::<U8>::from_hex("30B6C1");
    let b = Seq::<U8>::from_hex("0F");
    let (out, rd) = be_seq_div(&a, &b);
    let res = Seq::<U8>::from_hex("033F62");
    let rd_res = Seq::<U8>::from_hex("03");
    assert_bytes_eq!(out, res);
    assert_bytes_eq!(rd, rd_res);
}

#[test]
fn div_zero_test() {
    let a = Seq::<U8>::from_hex("08");
    let b = Seq::<U8>::from_hex("00");
    let (out, rd) = be_seq_div(&a, &b);
    let res = Seq::<U8>::from_hex("00");
    let rd_res = Seq::<U8>::from_hex("00");
    assert_bytes_eq!(out, res);
    assert_bytes_eq!(rd, rd_res);
}

#[test]
fn exp_test() {
    let a = Seq::<U8>::from_hex("03");
    let b: usize = 2;
    let out = be_seq_exp(&a, &b);
    let res = Seq::<U8>::from_hex("09");
    assert_bytes_eq!(out, res);
}