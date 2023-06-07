//! # string
//! A library to handle string convertions needed for hashing.
//! This library doesn't support actual string types, but works exclusefly with byte sequences from hacspec-lib.

use hacspec_lib::*;

/// Converts a byte array into the utf-8 encoding of it's hex representation. With capitalized letters.
pub fn from_be_bytes_to_utf8(bytes: Seq<U8>) -> Seq<U8> {

    let UTCMap = ByteSeq::from_public_slice(&[
        0x30u8, 0x31u8, 0x32u8, 0x33u8, 0x34u8, 0x35u8, 0x36u8, 0x37u8, 
        0x38u8, 0x39u8, 0x41u8, 0x42u8, 0x43u8, 0x44u8, 0x45u8, 0x46u8
    ]);

    let bytlen = bytes.len();

    let mut out = Seq::<U8>::new(bytlen * 2);

    for i in 0..bytlen {
        let fh = U8::declassify(bytes[i]) >> 4;
        let sh = U8::declassify(bytes[i]) & 0x0fu8;
        
        out[i * 2] = UTCMap[fh];
        out[(i * 2) + 1] = UTCMap[sh];
    }

    out
}

pub fn concat_strings(strings: Seq<Seq<U8>>) -> Seq<U8> {
    let mut out = Seq::<U8>::new(0);
    let pipe = ByteSeq::from_public_slice(&[0x7Cu8]);
    out = out.concat(&pipe);
    for i in 0..strings.len() {
        out = out.concat(&strings[i]);
        out = out.concat(&pipe);
    }
    out
}