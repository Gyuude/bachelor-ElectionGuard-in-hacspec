#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(warnings, unused)]

use hacspec_lib::*;
use hacspec_provider::*;
use hacspec_sha256::*;
use schema::*;
use vOne::*;
use seq_arithmetic::*;
use string::*;

/// ## Step 2. (Guardian public key validation) <br><br>
/// 
/// This step verifies for each guardian $T_i$, and for each $j \in \Z_k$ the following:<br>
/// (2.A) The challenge $c_{i,j}$ is correctly computed as $c_{i,j} = H(K_{i,j} , h_{i,j}) \mod q$.<br>
/// (2.B) The equation $g^{u_{i,j}} \mod p = h_{i,j}K^{c_{i,j}}_{i,j} \mod p$ is satisfied.
/// 
///| variable  | description                | in election_record                     |                         |
///|-----------|----------------------------|----------------------------------------|-------------------------|
///| $K_{i,j}$ | public form of each random | guardians[i]->                         | election commitments[j] |
///| $h_{i,j}$ | coefficient commitments    | guardians[i]<br>->election proofs[j]-> | commitment              |
///| $c_{i,j}$ | challenge value            | guardians[i]<br>->election proofs[j]-> | challenge               |
///| $u_{i,j}$ | response                   | guardians[i]<br>->election proofs[j]-> | response                |
pub fn secondCheck(guards: &guardians) -> bool {
    let mut check_a = true;
    let mut check_b = true;

    // Gets constants from 
    let p = &PBARR.to_be_bytes();
    let q = &QBARR.to_be_bytes();
    let g = &GBARR.to_be_bytes();

    for i in 0..(guards.len()) {

        let schema::guardian(x1, x2, x3, x4, proofs) = guards[i].clone();

        for j in 0..(proofs.len()) {

            let schema::schnorr_proof(pbk, comm, cha, res, x5) = proofs[j].clone();

            // Check a:

            let mut strings = Seq::<Seq::<U8>>::new(2);

            strings[0] = from_be_bytes_to_utf8(pbk.clone());
            strings[1] = from_be_bytes_to_utf8(comm.clone());

            let strconcat = concat_strings(strings);
            
            // Hash H(K_i,j , h_i,j)
            let hashed = hash(&strconcat).to_be_bytes();

            // H(K_i_j, h_i_j) mod q
            let h = be_seq_mod(&hashed.clone(), q);
            
            // C_i_j = H(K_i_j, h_i_j) mod q
            check_a = seq_eq(&cha, &h) && check_a;

            // Check b:

            // G^u_i_j mod p
            let left = be_seq_mod_exp(g, &res, p);

            // h_i_j K_i_j^c_i_j mod p
            let right = be_seq_mod_exp(&pbk, &cha, p);

            // G^u_i_j mod p = h_i_j K_i_j^c_i_j mod p
            check_b = seq_eq(&left, &right) && check_b;

        };
    };

    check_a && check_b
}