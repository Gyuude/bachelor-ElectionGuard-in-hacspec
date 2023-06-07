use hacspec_lib::*;
use hacspec_provider::*;
use schema::*;
use string::*;
use vOne::*;
use seq_arithmetic::*;
use hacspec_sha256::*;

fn eleventhcheck(encry_tally: encrypted_tally, tall: tally, mani: manifest, sub_ballots: Seq<submitted_ballot>) -> bool {
    let tally(x1, contests) = tall;
    let encrypted_tally(x2, encrypted_contests) = encry_tally;

    let mut check_a = true;
    let mut check_b = true;
    let mut check_c = true;
    let mut check_d = true;
    let mut check_e = true;
    let mut check_f = true;

    let p = &vOne::PBARR.to_be_bytes();
    let q = &vOne::QBARR.to_be_bytes();
    let g = &vOne::GBARR.to_be_bytes();

    // Get the contests fra election_manifest
    let manifest(x20, x21, x22, x23, x25, x26, x27, x28, man_contests, x29, x30, x31) = mani;



    for j in 0..contests.len() {
        let (x33, contest_tally(cont_id, selections)) = contests[j].clone();
        let (x5, encrypted_contest_tally(x4, x32, x6, encrypted_selections)) = encrypted_contests[j].clone();

        // Check c
        let mut found_cont = false;
        let mut mani_cont_selection = Seq::<manifest_ballot_selection>::new(1);

        for l in 0..man_contests.len() {
            if (!found_cont){    
                let manifest_contest(mc_id, x34, x35, x36, x37, x38, x39, mani_sel, x41, x42) = man_contests[l].clone();
                found_cont = seq_eq(&cont_id, &mc_id);
                if (found_cont) {
                    mani_cont_selection = mani_sel;
                }
            }; 
        }

        check_c = found_cont && check_c;



        // Check e

        for l in 0..mani_cont_selection.len() {
            let manifest_ballot_selection(mani_opt_id, x47, x48) = mani_cont_selection[l].clone();

            let mut found_sel_from_mani = false;

            for k in 0..selections.len() {
                if (!found_sel_from_mani) {
                    let (x45, selection_tally(sel_id, x46, x50, x51, x52)) = selections[k].clone();
                    found_sel_from_mani = seq_eq(&mani_opt_id, &sel_id);
                }
            }

            check_e = found_sel_from_mani && check_e;
        }

        // Checks for each selection (aka option)

        for k in 0..selections.len() {
            let (x8, selection_tally(sel_id, t, m, x9, shares)) = selections[k].clone();
            let (x10, encrypted_selection_tally(x11, x12, x13, ciphertext(x14, est_data))) = encrypted_selections[k].clone();

            // Check a

            let mut check_a_right1 = seq_one();

            // Product of all partial decryptions for each option
            for i in 0..shares.len() {
                let selection_share(x15, x16, share, x18, x19) = shares[i].clone();

                check_a_right1 = be_seq_mul(&check_a_right1, &share); 
            }

            // (M * (\Pi_{i = 1}^n M_i)) mod p
            let check_a_right = be_seq_mod(&be_seq_mul(&m, &be_seq_mod(&check_a_right1, p)), p);

            // B = (M * (\Pi_{i = 1}^n M_i)) mod p
            check_a = seq_eq(&est_data, &check_a_right) && check_a;

            // Check b

            // g^t mod p
            let check_b_right = be_seq_mod_exp(g, &be_U32_to_seq(&t), p);

            check_b = seq_eq(&m, &check_b_right) && check_b;


            // Check d

            let mut opt_exist = false;

            for l in 0..mani_cont_selection.len() {
                if (!opt_exist) {
                    let manifest_ballot_selection(mani_opt_id, x44, x43) = mani_cont_selection[l].clone();
                    opt_exist = seq_eq(&sel_id, &mani_opt_id);
                }
            }

            check_d = opt_exist && check_d;
        }
    }

    // Check f

    let mut conts_in_ballots = Seq::<Seq::<U8>>::new(0);

    for i in 0..sub_ballots.len() {
        let submitted_ballot(x53, x54, x55, x56, conts, x57, x58, x59, x60, x61) = sub_ballots[i].clone();
        
        for j in 0..conts.len() {
            let contest(cont_id, x62, x63, x64, x65, x66, x67, x68, x69) = conts[j].clone();
        
            let mut new_id = true;

            for k in 0..conts_in_ballots.len() {
                new_id = !seq_eq(&conts_in_ballots[k], &cont_id) && new_id;
            }

            if (new_id) {
                let mut next_id = Seq::<Seq::<U8>>::new(1);

                next_id[0] = cont_id.clone();
            
                conts_in_ballots = conts_in_ballots.concat(&next_id);

                let mut found_match = false;

                for l in 0..contests.len() {
                    let (x70, contest_tally(tal_cont_id, x71)) = contests[l].clone();

                    found_match = seq_eq(&cont_id, &tal_cont_id) || found_match;
                }

                check_f = found_match && check_f;
            }
        }
    }

    check_a && check_b && check_c && check_d && check_e && check_f
}
