#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(warnings, unused)]

use hacspec_lib::*;
use hacspec_sha256::*;
use schema::*;
use vOne::*;
use seq_arithmetic::*;
use string::*;


/// ## Step 4. (Correctness of selection encryptions) <br><br>
/// 
/// This step confirms the following for each selection on each cast ballot:<br>
/// (4.A) The given values $\alpha$, $\beta$, $a_0$, $b_0$, $a_1$ and $b_1$ are all in the set $\Z^r_p$. <br>
/// &nbsp; (A value $x$ is in $\Z^r_p$ if and only if $x$ is an integer such that $0 \leq x \leq p$ and $x^q \mod p = 1$ is satisfied.)<br>
/// (4.B) The challenge $c$ is correctly computed as $c = H(\bar{Q}, \alpha, \beta, a_0, b_0, a_1, b_1)$.<br>
/// (4.C) The given values $c_0$, $c_1$, $v_0$ and $v_1$ are each in the set $\Z_q$. <br>
/// &nbsp; (A value $x$ is in $\Z_q$ if and only if $x$ is an integer such that $0 \leq x < q$.) <br>
/// (4.D) The equation $c = (c_0 + c_1) \mod q$ is satisfied. <br>
/// (4.E) The equation $g^{v_0} \mod p = a_0\alpha^{c_0} \mod p$ is satisfied. <br>
/// (4.F) The equation $g^{v_1} \mod p = a_1\alpha^{c_1} \mod p$ is satisfied. <br>
/// (4.G) The equation $K^{v_0} \mod p = b_0\beta^{c_0} \mod p$ is satisfied. <br>
/// (4.H) The equation $g^{c_1}K^{v_1} \mod p = b_1\beta^{c_1} \mod p$ is satisfied. <br>
/// 
/// | variable          | description                                          | in election_record                                       |            |                                      |
/// |-------------------|------------------------------------------------------|----------------------------------------------------------|------------|--------------------------------------|
/// | $(\alpha, \beta)$ | encryption of vote                                   | submitted ballots<br>->contests<br>->ballot selections-> | ciphertext |                                      |
/// | $(a_0, b_0)$      | commitment to vote<br>being an encryption of<br>zero | submitted ballots<br>->contests<br>->ballot selections-> | proof->    | (proof zero pad,<br>proof zero data) |
/// | $(a_1, b_1)$      | commitment to vote<br>being an encryption of<br>one  | submitted ballots<br>->contests<br>->ballot selections-> | proof->    | (proof one pad,<br>proof one data)   |
/// | $c$               | challenge                                            | submitted ballots<br>->contests<br>->ballot selections-> | proof->    | challenge                            |
/// | $c_0$             | derived challenge to<br>encryption of zero           | submitted ballots<br>->contests<br>->ballot selections-> | proof->    | proof zero challenge                 |
/// | $c_1$             | derived challenge to<br>encryption of one            | submitted ballots<br>->contests<br>->ballot selections-> | proof->    | proof one challenge                  |
/// | $v_0$             | response to zero challenge                           | submitted ballots<br>->contests<br>->ballot selections-> | proof->    | proof zero response                  |
/// | $v_1$             | response to one challenge                            | submitted ballots<br>->contests<br>->ballot selections-> | proof->    | proof one response                   |
pub fn fourthCheck(ballots: &Seq<submitted_ballot>, ctx: context) -> bool {
    
    // The differend checks
    let mut check_a = true;
    let mut check_b = true;
    let mut check_c = true;
    let mut check_d = true;
    let mut check_e = true;
    let mut check_f = true;
    let mut check_g = true;
    let mut check_h = true;

    // The setup
    let p = &PBARR.to_be_bytes();
    let q = &QBARR.to_be_bytes();
    let g = &GBARR.to_be_bytes();

    let context(x1, x2, elgamal_public_key, x4, x5, x6, extended_base_hash, x7, x8) = ctx;

    for i in 0..ballots.len() {
        let submitted_ballot(x1, x2, x3, x4, contests, x5, x6, x7, x8, x9) = ballots[i].clone();
    
        for j in 0..contests.len() {

            let contest(x10, x11, x12, ballot_selections, x13, x14, x15, x16, x17) = contests[i].clone();

            for k in 0..ballot_selections.len() {

                let ballot_selection(x18, x19, x20, ciphertxt, x21, x22, x23, ballot_proof) = ballot_selections[k].clone();

                let disjunctive_proof(a0, b0, a1, b1, c0, c1, c, v0, v1, usage) = ballot_proof;
            
                let ciphertext(pad, data) = ciphertxt;

                // Check A
                let pad_in_z = do_check_a(&pad, p, q);
                let data_in_z = do_check_a(&data, p, q);
                let a0_in_z = do_check_a(&a0, p, q);
                let b0_in_z = do_check_a(&b0, p, q);
                let a1_in_z = do_check_a(&a1, p, q);
                let b1_in_z = do_check_a(&b1, p, q);

                check_a = pad_in_z && data_in_z && a0_in_z && b0_in_z && a1_in_z && b1_in_z & check_a;

                // Check B
                
                let mut hash_strings = Seq::<Seq::<U8>>::new(7);

                hash_strings[0] = extended_base_hash.clone();
                hash_strings[1] = pad.clone();
                hash_strings[2] = data.clone();
                hash_strings[3] = a0.clone();
                hash_strings[4] = b0.clone();
                hash_strings[5] = a1.clone();
                hash_strings[6] = b1.clone();

                let hash_concat = concat_strings(hash_strings);

                let hashed = hash(&hash_concat).to_be_bytes();

                check_b = seq_eq(&hashed, &c) && check_b;


                // Check C

                check_c = do_check_c(&c0, q) && do_check_c(&c1, q) && do_check_c(&v0, q) && do_check_c(&v1, q) && check_c;


                // Check D

                // (c0 + c1) mod q
                let (x24, check_d_temp) = be_seq_div(&be_seq_add(&c1, &c0), q);
                check_d = seq_eq(&c, &check_d_temp) && check_d;


                // Check E

                check_e = do_check_efg(g, &v0, p, &a0, &pad, &c0) && check_e;

                // Check F

                check_f = do_check_efg(g, &v0, p, &a1, &pad, &c1) && check_f;

                // Check G

                check_g = do_check_efg(&elgamal_public_key, &v0, p, &b0, &data, &c0) && check_g;

                // Check H
                let check_h_left =be_seq_mul_mod(&be_seq_mod_exp(g, &c1, p), &be_seq_mod_exp(&elgamal_public_key, &v1, p), &p);
                let check_h_right = be_seq_mul_mod(&b1, &be_seq_mod_exp(&data, &c1, p), p);
                check_h = seq_eq(&check_h_left, &check_h_right) && check_h;

            }
        }
    }
    check_a



}

fn do_check_a(x: &Seq<U8>, p: &Seq<U8>, q: &Seq<U8>) -> bool {
    let xmod = &be_seq_mod_exp(&x, &q, &p);
    // Check x^q mod p = 1
    let x_temp = seq_eq(&seq_one(), &xmod);
    seq_leq(&seq_zero(), &x) && !seq_leq( &p ,&x) && x_temp
}

fn do_check_c(x: &Seq<U8>, q: &Seq<U8>) -> bool {
    seq_leq(&seq_zero(), &x) && !seq_leq( &q ,&x)
}

fn do_check_efg(g: &Seq<U8>, v: &Seq<U8>, p: &Seq<U8>, a: &Seq<U8>, pad: &Seq<U8>, c: &Seq<U8>) -> bool {
    let check_e_left = be_seq_mod_exp(g, &v, p);
    // a mod p
    let check_e_right1 = be_seq_mod(&a, p);
    // pad^c mod p
    let check_e_right2 = be_seq_mod_exp(&pad, &c, p);
    let check_e_right = be_seq_mul_mod(&check_e_right1, &check_e_right2, p);
    seq_eq(&check_e_left, &check_e_right)
}