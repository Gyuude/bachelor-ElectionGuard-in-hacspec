use hacspec_lib::*;
use hacspec_provider::*;
use schema::*;
use string::*;
use vOne::*;
use seq_arithmetic::*;
use hacspec_sha256::*;

fn fourteenthCheck(spoiled_list: Seq<spoiled_ballot>) -> bool {
    let mut check_a = true;
    let mut check_b = true;

    let p = PBARR.to_be_bytes();
    let g = GBARR.to_be_bytes();

    for i in 0..spoiled_list.len() {
        let spoiled_ballot(x1, cons) = spoiled_list[i].clone();

        for j in 0..cons.len() {
            let (x2, spoiled_ballot_decrypted_contest(x11, sb_dc_selects, x3)) = cons[j].clone();

            for k in 0..sb_dc_selects.len() {
                let (x4, sel) = sb_dc_selects[k].clone();

                let spoiled_ballot_decrypted_selection(x5, v, m, msg, shares) = sel.clone();
                let ciphertext(x6, data) = msg.clone();

                let mut prod = seq_one();

                for l in 0..shares.len() {
                    let selection_share(x7, x8, share, x9, x10) = shares[l].clone();

                    prod = be_seq_mul_mod(&prod, &share, &p);
                }

                prod = be_seq_mul_mod(&prod, &m, &p);

                check_a = check_a && seq_eq(&data, &prod);

                let v_as_seq = be_U32_to_seq(&v);

                let b_right = be_seq_mod_exp(&g, &v_as_seq, &p);

                check_b = check_b && seq_eq(&m, &b_right);
            }
        }
    }

   check_a && check_b
}