use hacspec_lib::*;
use hacspec_provider::*;
use schema::*;
use string::*;
use vOne::*;
use seq_arithmetic::*;
use hacspec_sha256::*;

fn twelfthCheck(spoil_bs: Seq<spoiled_ballot>, context(x21, x22, x23, x24, x25, x26, cebh, x27, x28): context, guards: Seq<guardian>) -> bool {
    

    let mut check_a = true;
    let mut check_b = true;
    let mut check_c = true;
    let mut check_d = true;
    let mut check_e = true;

    let p = &vOne::PBARR.to_be_bytes();
    let q = &vOne::QBARR.to_be_bytes();
    let g = &vOne::GBARR.to_be_bytes();

    for sbs in 0..spoil_bs.len() {
        let spoiled_ballot(x2, contests) = spoil_bs[sbs].clone();

        for j in 0..contests.len() {
            let (x3, spoiled_ballot_decrypted_contest(x4, selections, x40)) = contests[j].clone();

            for k in 0..selections.len() {
                let (x9, spoiled_ballot_decrypted_selection(x10, x11, x12, ciphertext(est_pad, est_data), shares)) = selections[k].clone();

                for i in 0..shares.len() {
                    let selection_share(x17, guard_id, m, cp_proof(a, b, c, v, x20), x19) = shares[i].clone();

                    // Check that v_i in the set Z_q
                    check_a = seq_leq(&seq_zero(), &v) && !seq_leq(q , &v) && check_a;

                    // Check that a_i and b_i are both in the set Z^r_p, using the same check as in step 4
                    check_b = do_check_b(&a, p, q) && do_check_b(&b, p, q) && check_b;


                    let mut check_c_strings = Seq::<Seq::<U8>>::new(6);

                    check_c_strings[0] = cebh.clone();
                    check_c_strings[1] = est_pad.clone();
                    check_c_strings[2] = est_data.clone();
                    check_c_strings[3] = a.clone();
                    check_c_strings[4] = b.clone();
                    check_c_strings[5] = m.clone();

                    let check_c_concat = concat_strings(check_c_strings);
                    let check_c_hashed = hash(&check_c_concat).to_be_bytes();

                    // Check that c_i = H(Q-, A, B, a_i, b_i, M_i)
                    check_c = seq_eq(&check_c_hashed, &c) && check_c;


                    // find corresponding guardian public key (K_i)
                    let mut guard_pk = seq_zero();

                    for l in 0..guards.len() {
                        let guardian(g_id, x30, g_pk, x31, x32) = guards[i].clone();
                        if seq_eq(&guard_id, &g_id) {
                            guard_pk = g_pk;
                        }
                    }

                    if seq_eq(&guard_pk, &seq_zero()) {
                        check_d = false;
                    }

                    // g^(v_i) mod p
                    let check_d_left = be_seq_mod_exp(g, &v, p);

                    // a_i mod p
                    let (x29, check_d_right1) = be_seq_div(&a, p);
                    
                    // K_i^(c_i) mod p
                    let check_d_right2 = be_seq_mod_exp(&guard_pk, &c, p);

                    // (a_iK_i^(c_i)) mod p
                    let (x33, check_d_right) = be_seq_div(&be_seq_mul(&check_d_right1, &check_d_right2), p);

                    // Check that g^(v_i) mod p = (a_iK_i^(c_i)) mod p
                    check_d = seq_eq(&check_d_left, &check_d_right) && check_d;

                    // A^(v_i) mod p
                    let check_e_left = be_seq_mod_exp(&est_pad, &v, p);

                    // b_i mod p
                    let (x34, check_e_right1) = be_seq_div(&b, p);

                    // M_i^(c_i) mod p
                    let check_e_right2 = be_seq_mod_exp(&m, &c, p);
                    
                    // (b_iM_i^(c_i)) mod p
                    let (x35, check_e_right) = be_seq_div(&be_seq_mul(&check_e_right1, &check_e_right2), p);

                    // Check that A^(v_i) mod p = (b_iM_i^(c_i)) mod p
                    check_e = seq_eq(&check_e_left, &check_e_right) && check_e;
                }
            }
        }
    }

    check_a && check_b && check_c && check_d && check_e
}

fn do_check_b(x: &Seq<U8>, p: &Seq<U8>, q: &Seq<U8>) -> bool {
    let xmod = &be_seq_mod_exp(&x, &q, &p);
    // Check x^q mod p = 1
    let x_temp = seq_eq(&seq_one(), &xmod);
    seq_leq(&seq_zero(), &x) && !seq_leq( &p ,&x) && x_temp
}