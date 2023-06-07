use hacspec_lib::*;
use hacspec_provider::*;
use schema::*;
use string::*;
use vOne::*;
use seq_arithmetic::*;
use hacspec_sha256::*;

pub fn sixthCheck(sub_ballots: Seq<submitted_ballot>, cebh: crypto_extended_base_hash) -> bool {
    let mut check_a = true;
    let mut check_b = true;

    for i in 0..sub_ballots.len() {
        let submitted_ballot(x1, x2, x3, x4, sub_cons, h_i, x5, x6, x7, x8) = sub_ballots[i].clone();

        let mut str_for_hash = Seq::<Seq::<U8>>::new(1);

        str_for_hash[0] = from_be_bytes_to_utf8(cebh.clone());

        for j in 0..sub_cons.len() {
            let contest(x9, x10, x11, ballot_selects, x12, x13, x14, x15, x16) = sub_cons[j].clone();

            for k in 0..ballot_selects.len() {
                let ballot_selection(x17, x18, x19, ballot_ct, x20, x21, x22, x23) = ballot_selects[k].clone();

                let ciphertext(bal_pad, bal_data) = ballot_ct.clone();

                let mut ct_seq = Seq::<Seq::<U8>>::new(2);

                ct_seq[0] = from_be_bytes_to_utf8(bal_pad.clone());
                ct_seq[1] = from_be_bytes_to_utf8(bal_data.clone());

                str_for_hash = str_for_hash.concat(&ct_seq);
            }
        }

        // Concatenating them with pipe | characters between
        let strconcat = concat_strings(str_for_hash);

        // Hashing with SHA256
        let hashed_str = hash(&strconcat).to_be_bytes();

        check_a = check_a && seq_eq(&h_i, &hashed_str);

    }

    check_b = do_check_b(sub_ballots.clone());

    check_a && check_b
}

fn do_check_b(sub_ballots: Seq<submitted_ballot>) -> bool {
    let mut checked_codes = Seq::<sub_code>::new(sub_ballots.len());

    let mut check_b = true;

    for i in 0..sub_ballots.len() {
        let submitted_ballot(x1, x2, x3, x4, x5, current_h_i, x6, x7, x8, x9) = sub_ballots[i].clone();

        for j in 0..i {
            check_b = check_b && seq_eq(&checked_codes[j], &current_h_i);
        }

        checked_codes[i] = current_h_i.clone();
    }

    check_b
}