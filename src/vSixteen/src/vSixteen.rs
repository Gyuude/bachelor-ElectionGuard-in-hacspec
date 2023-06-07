use hacspec_lib::*;
use hacspec_provider::*;
use schema::*;
use string::*;
use vOne::*;
use seq_arithmetic::*;
use hacspec_sha256::*;

fn sixteenthCheck(spoil_bs: Seq<spoiled_ballot>, mani: manifest) -> bool {
    let mut check_a = true;
    let mut check_b = true;
    
    let manifest(x9, x10, x11, x12, x13, x14, x15, x16, mani_contests, x17, x18, x19) = mani;

    for i in 0..spoil_bs.len() {
        let spoiled_ballot(x1, contests) = spoil_bs[i].clone();


        for j in 0..contests.len() {
            let (contest_key, spoiled_ballot_decrypted_contest(x2, selections, x3)) = contests[j].clone();

            let mut mani_contest_votes_allowed = U32::ZERO();

            for l in 0..mani_contests.len() {
                let manifest_contest(obid, x20, x21, x22, x23, votes_allowed, x25, x26, x27, x28) = mani_contests[l].clone();
                if (seq_eq(&obid, &contest_key)) {
                    mani_contest_votes_allowed = votes_allowed;
                }
            }



            let mut sel_sum = U32::ZERO();

            for k in 0..selections.len() {
                let (x4, spoiled_ballot_decrypted_selection(x5, tal, x6, x7, x8)) = selections[k].clone();

                let val_is_correct = tal.declassify() == 0 || tal.declassify() == 1;

                // Check A:
                check_a = val_is_correct && check_a;

                // sum of selections used in check B
                sel_sum = sel_sum + tal;
            }

            // Check B:
            check_b = (sel_sum.declassify() <= mani_contest_votes_allowed.declassify()) && check_b;
        }
    }

    check_a && check_b
}