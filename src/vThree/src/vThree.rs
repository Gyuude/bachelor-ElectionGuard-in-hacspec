#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(warnings, unused)]

use hacspec_lib::*;
use hacspec_sha256::*;
use schema::*;
use vOne::*;
use seq_arithmetic::*;
use string::*;

/// ## Step 3. (Election public-key validation)
/// 
/// An election verifier must verify the correct computation of the joint election public key and extended base hash.
/// 
/// (3.A) $K = \Pi^n_{i=1} K_i \mod p$, <br>
/// (3.B) $\bar{Q} = H(Q,K)$. <br>
/// 
/// | variable  | description                  | in election_record |                           |
/// |-----------|------------------------------|--------------------|---------------------------|
/// | $n$       | number of guardians          | context->          | number_of_guardians       |
/// | $Q$       | base hash value              | context->          | crypto_base_hash          |
/// | $\bar{Q}$ | extended base hash           | context->          | crypto_extended_base_hash |
/// | $K$       | joint election public key    | context->          | elgamal_public_key        |
/// | $K_i$     | public key of guardian $T_i$ | guardians[i]->     | election_public_key       |
pub fn thirdCheck(context(n, x1, epk, x2, x3, cbh, cebh, x4, x5): schema::context, guards: schema::guardians) -> bool {
    let guardian_n = U32::declassify(n) as usize;

    let p = &PBARR.to_be_bytes();
    let q = &QBARR.to_be_bytes();

    let mut prod = seq_one();
    for i in 0..(guardian_n - 1) {
        let guardian(x6, x7, pk, x8, x9) = guards[i].clone();
        prod = be_seq_mul_mod(&prod, &pk, &p);
    }

    // K = product^n(K_i) mod p
    let check_a = seq_eq(&epk, &prod);


    let mut strings = Seq::<Seq::<U8>>::new(2);

    strings[0] = from_be_bytes_to_utf8(cbh);
    strings[1] = from_be_bytes_to_utf8(epk);

    let strconcat = concat_strings(strings);
            
    let hashed = hash(&strconcat).to_be_bytes();

    // Q = H(Q,K)
    let check_b = seq_eq(q, &hashed);

    check_a && check_b
}