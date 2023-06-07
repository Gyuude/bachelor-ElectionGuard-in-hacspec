use hacspec_lib::*;
use hacspec_provider::*;
use schema::*;
use string::*;
use vOne::*;
use seq_arithmetic::*;
use hacspec_sha256::*;

fn ninthcheck(encry_tally: encrypted_tally, tall: tally, context(x21, x22, x23, x24, x25, x26, cebh, x27, x28): context, guards: Seq<guardian>) -> bool {
    let tally(x2, contests) = tall;
    let encrypted_tally(x1, encrypted_contests) = encry_tally;

    let mut check_a = true;
    let mut check_b = true;
    let mut check_c = true;
    let mut check_d = true;
    let mut check_e = true;

    let p = &PBARR.to_be_bytes();
    let q = &QBARR.to_be_bytes();
    let g = &GBARR.to_be_bytes();

    for j in 0..contests.len() {
        let (x3, contest_tally(x4, selections)) = contests[j].clone();
        let (x5, encrypted_contest_tally(x6, x7, x8, encrypted_selections)) = encrypted_contests[j].clone();

        for k in 0..selections.len() {
            let (x9, selection_tally(x10, x11, x12, x13, shares)) = selections[k].clone();
            let (x14, encrypted_selection_tally(x36, x15, x16, ciphertext(est_pad, est_data))) = encrypted_selections[k].clone();

            for i in 0..shares.len() {
                let selection_share(x17, x19, x20, x36, recovered_parts) = shares[i].clone();

                for l in 0..recovered_parts.len() {

                    let (x40, recovered_part(x37, guard_id, m_guard_id, m, x38, cp_proof(a, b, c, v, x39))) = recovered_parts[l].clone();

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
                    let mut guard_ec = Seq::<Seq::<U8>>::new(0);

                    for l in 0..guards.len() {
                        let guardian(g_id, x30, x31, g_ec, x32) = guards[i].clone();
                        if seq_eq(&guard_id, &g_id) {
                            guard_ec = g_ec;
                        }
                    }

                    // g^(v_i) mod p
                    let check_d_left = be_seq_mod_exp(g, &v, p);

                    let mut check_d_right1 = seq_one();

                    // Product K_{i,j}^{l^{j}}
                    for m in 0..guard_ec.len() {
                        check_d_right1 = be_seq_exp(&guard_ec[m].clone(), &usize::pow(l, m as u32));
                    }

                    let check_d_right2 = be_seq_exp(&check_d_right1, &seq_to_usize(&c));

                    let check_d_right = be_seq_mul_mod(&a, &check_d_right2, p);

                    // Check that g^(v_{i, l}) mod p = (a_{i, l} (\Pi^{k-1}_{j=0} K_{i,j}^{l^{j}})^{c_{i, j}} ) mod p
                    check_d = seq_eq(&check_d_left, &check_d_right) && check_d;

                    // A^(v_{i, l}) mod p
                    let check_e_left = be_seq_mod_exp(&est_pad, &v, p);

                    // M_{i, l}^{c_{i, l}} mod p
                    let check_e_right1 = be_seq_mod_exp(&m, &c, p);

                    // (a_{i, l} mod p * M_{i, l}^{c_{i, l}} mod p) mod p
                    let check_e_right = be_seq_mul_mod(&be_seq_mod(&b, p), &check_e_right1, p);

                    // Check that A^(v_{i, l}) mod p = (a_{i, l} mod p * M_{i, l}^{c_{i, l}} mod p) mod p
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