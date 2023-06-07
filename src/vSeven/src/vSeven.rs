use hacspec_lib::*;
use hacspec_provider::*;
use schema::*;
use string::*;
use vOne::*;
use seq_arithmetic::*;
use hacspec_sha256::*;

fn seventhCheck(submitted_ballots: Seq<submitted_ballot>, encrypted_tally(et_id, tally_contests): encrypted_tally) -> bool {
    let submitted_ballot(x0, x1, x2, x3, first_contests, x4, x5, x6, x7, x8) = submitted_ballots[0 as usize].clone();

    let mut c_acc = Seq::<Seq::<ciphertext>>::new(first_contests.len());
    let mut contest_id_index = Seq::<Seq::<U8>>::new(first_contests.len());
    let mut selection_id_index = Seq::<Seq::<Seq::<U8>>>::new(first_contests.len());

    let p = PBARR.to_be_bytes();

    for i in 0..first_contests.len() {
        let contest(con_id, x10, x11, first_selections, x12, x13, x14, x15, x16) = first_contests[i].clone();

        contest_id_index[i] = con_id.clone();

        let mut ciphers = Seq::<ciphertext>::new(first_selections.len());

        for j in 0..first_selections.len() {
            let ballot_selection(sel_id, x18, x19, ct, x20, is_p, x22, x23) = first_selections[j].clone();

            selection_id_index[i][j] = sel_id.clone();

            if is_p {
                let empty_cipher = ciphertext(seq_one(), seq_one());
                ciphers[j] = empty_cipher;
            } else {
                let ciphertext(first_pad, first_data) = ct.clone();

                let first_pad_mod = be_seq_mod(&first_pad, &p);
                let first_data_mod = be_seq_mod(&first_data, &p);

                ciphers[j] = ciphertext(first_pad_mod, first_data_mod);
            }
        }

        c_acc[i] = ciphers;

    }

    for k in 1..submitted_ballots.len() {
        let submitted_ballot(x24, x25, x26, x27, bal_contests, x28, x29, x30, x31, x32) = submitted_ballots[k].clone();

        for l in 0..bal_contests.len() {
            let contest(x9, x10, x11, bal_selections, x12, x13, x14, x15, x16) = bal_contests[l].clone();

            for m in 0..bal_selections.len() {
                let ballot_selection(x17, x18, x19, ct, x20, is_p, x22, x23) = bal_selections[m].clone();

                if !is_p {
                    let ciphertext(new_pad, new_data) = ct.clone();

                    let new_pad_mod = be_seq_mod(&new_pad, &p);
                    let new_data_mod = be_seq_mod(&new_data, &p);

                    let ciphertext(c_pad, c_data) = c_acc[l][m].clone();

                    let pad_prod_mod = be_seq_mul_mod(&c_pad, &new_pad_mod, &p);
                    let data_prod_mod = be_seq_mul_mod(&c_data, &new_data_mod, &p);

                    c_acc[l][m] = ciphertext(pad_prod_mod, data_prod_mod);
                }

                
            }
        } 
    }

    let mut is_valid = true;

    for n in 0..tally_contests.len() {
        let (con_id, con_tally) = tally_contests[n].clone();

        let encrypted_contest_tally(x24, x25, x26, tally_selections) = con_tally.clone();

        for o in 0..tally_selections.len() {
            let (sel_id, sel_tally) = tally_selections[o].clone();
            let encrypted_selection_tally(x27, x28, x29, tally_cipher) = sel_tally;

            let mut con_index = 0 as usize;
            let mut sel_index = 0 as usize;

            for p in 0..contest_id_index.len() {
                if seq_eq(&con_id, &contest_id_index[p]) {
                    con_index = p;
                }
            }

            for q in 0..selection_id_index[con_index].len() {
                if seq_eq(&sel_id, &selection_id_index[con_index][q]) {
                    sel_index = q;
                }
            }

            let ciphertext(tally_pad, tally_data) = tally_cipher;

            let ciphertext(sub_pad, sub_data) = c_acc[con_index][sel_index].clone();

            let check_pad = seq_eq(&tally_pad, &sub_pad);
            let check_data = seq_eq(&tally_data, &sub_data);

            is_valid = is_valid && check_pad && check_data
        }
    }


    is_valid
}