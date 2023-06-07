use hacspec_lib::*;
use hacspec_provider::*;
use schema::*;
use string::*;
use vOne::*;
use seq_arithmetic::*;
use hacspec_sha256::*;
/// Verification 18: Correctness of substitute contest data for spoiled ballots
/// 
/// An election verifier must confirm for each contest on the spoiled ballot the following for each missing
/// guardian $T_i$ and for each surrogate guardian $T_{\lambda}$.

pub fn eighteenthcheck(sub_ballots: Seq<submitted_ballot>, sp_ballots: Seq<spoiled_ballot>, context(x21, x22, x23, x24, x25, x26, cebh, x27, x28): context, guards: Seq<guardian>) -> bool {

    let mut check_a = true;
    let mut check_b = true;
    let mut check_c = true;
    let mut check_d = true;
    let mut check_e = true;

    let p = &vOne::PBARR.to_be_bytes();
    let q = &vOne::QBARR.to_be_bytes();
    let g = &vOne::GBARR.to_be_bytes();

    // For every spoiled ballot
    for m in 0..sp_ballots.len() {
        let spoiled_ballot(sp_id, sp_contests) = sp_ballots[m].clone();

        // For every submitted ballot
        for n in 0..sub_ballots.len() {
            let submitted_ballot(sub_id, x36, x37, x38, sub_contests, x39, x40, x41, x42, x43) = sub_ballots[n].clone();

            // If spoiled ballot ID = submitted ballot ID
            if seq_eq(&sp_id, &sub_id) {
                // For every contest in the spoiled and submitted ballot. These should be the same length.
                for j in 0..sub_contests.len() {
                    let contest(x44, x45, x46, x47, x48, x49, x50, x51, sub_extended_data) = sub_contests[j].clone();
                    let (x5, spoiled_ballot_decrypted_contest(x6, x7, sp_con_data)) = sp_contests[j].clone();

                    let spoiled_ballot_contest_data(x52, x53, x54, sp_shares) = sp_con_data.clone();

                    // For every spoiled ballot share
                    for i in 0..sp_shares.len() {
                        let selection_share(x17, guard_id, m, cp_proof(x61, x64, x62, x63, x20), rec_parts) = sp_shares[i].clone();
        
                        // For every recovered part
                        for k in 0..rec_parts.len() {
                            let (x55, rec_part) = rec_parts[k].clone();

                            let recovered_part(x56, x57, x58, rec_share, x59, cp_proof(a, b, c, v, x60)) = rec_part;

                            // Check that v_i in the set Z_q
                            check_a = seq_leq(&seq_zero(), &v) && !seq_leq(q , &v) && check_a;
                                    
                            // Check that a_i and b_i are both in the set Z^r_p, using the same check as in step 4
                            check_b = do_check_b(&a, p, q) && do_check_b(&b, p, q) && check_b;

                            let extended_data(sub_pad, sub_data, sub_mac) = sub_extended_data.clone();


                            let mut check_c_strings = Seq::<Seq::<U8>>::new(7);

                            check_c_strings[0] = cebh.clone();
                            check_c_strings[1] = sub_pad.clone();
                            check_c_strings[2] = sub_data.clone();
                            check_c_strings[3] = sub_mac.clone();
                            check_c_strings[4] = a.clone();
                            check_c_strings[5] = b.clone();
                            check_c_strings[6] = m.clone();

                            let check_c_concat = concat_strings(check_c_strings);
                            let check_c_hashed = hash(&check_c_concat).to_be_bytes();

                            // Check that c_i = H(Q-, C_0, C_1, C_2, a_i, b_i, M_i)
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
                                check_d_right1 = be_seq_exp(&guard_ec[m].clone(), &usize::pow(k, m as u32));
                            }

                            let check_d_right2 = be_seq_exp(&check_d_right1, &seq_to_usize(&c));

                            let check_d_right3 = be_seq_mul(&a, &check_d_right2);

                            let check_d_right = be_seq_mod(&check_d_right3, p);

                            // Check that g^(v_{i, l}) mod p = (a_{i, l} (\Pi^{k-1}_{j=0} K_{i,j}^{l^{j}})^{c_{i, j}} ) mod p
                            check_d = seq_eq(&check_d_left, &check_d_right) && check_d;

                            // C_0^(v_{i, l}) mod p
                            let check_e_left = be_seq_mod_exp(&sub_pad, &v, p);

                            // M_{i, l}^{c_{i, l}} mod p
                            let check_e_right1 = be_seq_mod_exp(&m, &c, p);

                            // (a_{i, l} mod p * M_{i, l}^{c_{i, l}} mod p) mod p
                            let check_e_right = be_seq_mod(&be_seq_mul(&be_seq_mod(&b, p), &check_e_right1), p);

                            // Check that A^(v_{i, l}) mod p = (a_{i, l} mod p * M_{i, l}^{c_{i, l}} mod p) mod p
                            check_e = seq_eq(&check_e_left, &check_e_right) && check_e;
                        }
                    }
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