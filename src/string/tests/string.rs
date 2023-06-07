use hacspec_lib::*;
use string::*;

#[test]
fn test_utf_conv() {
    let x = Seq::<U8>::from_hex("0AAF02");
    let check = Seq::<U8>::from_public_slice(&[0x30u8, 0x41u8, 0x41u8, 0x46u8, 0x30u8, 0x32u8]);

    let res = string::from_be_bytes_to_utf8(x);

    assert_bytes_eq!(res,check);
}