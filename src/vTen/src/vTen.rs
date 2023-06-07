#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(warnings, unused)]

use hacspec_lib::*;
use hacspec_provider::*;
use schema::*;
use string::*;
use vOne::*;
use seq_arithmetic::*;
use hacspec_sha256::*;

fn tenthCheck(coefficients: l_coefficients, tally(x1, t_contests): tally, guards: guardians, missing_guards: guardians) -> bool {
    // 10.A
    // Set q
    let q = QBARR.to_be_bytes();

    // Prepare check a by defaulting to true
    let mut check_a = true;
    let mut check_b = true;

    // First loop: looking through each guardian T_l
    for l in 0..guards.len() {
        let guardian(current_id, current_ord, x1, x2, x3) = guards[l].clone();
        let seq_current_ord = be_U32_to_seq(&current_ord);
        let mut left_product = seq_one();
        let mut right_product = seq_one();

        // Second loop: 
        for j in 0..guards.len() {
            let guardian(other_id, other_ord, x4, x5, x6) = guards[j].clone();
            let seq_ord = be_U32_to_seq(&other_ord);

            if (!seq_eq(&seq_current_ord, &seq_ord)) {
                left_product = be_seq_mul_mod(&left_product, &seq_ord, &q);

                let mut lesser = seq_one();
                let mut greater = seq_one();
                if seq_leq(&seq_current_ord, &seq_ord) {
                    lesser = seq_current_ord.clone();
                    greater = seq_ord.clone();
                } else {
                    lesser = seq_ord.clone();
                    greater = seq_current_ord.clone();
                }
                let (ord_sub, x7) = be_seq_sub(&greater, &lesser);

                let right_product = be_seq_mul_mod(&right_product, &ord_sub, &q);
            }
        }

        let mut w_l = seq_zero();

        for i in 0..coefficients.len() {
            let (key, value) = coefficients[i].clone();
            if seq_eq(&key, &current_id) {
                w_l = value.clone();
            }
        }

        right_product = be_seq_mul_mod(&w_l, &right_product, &q);

        // 10.A check for guardian T_l
        if !seq_eq(&left_product, &right_product) {
            check_a = false;
        }


    }

    // 10.B

    for j in 0..missing_guards.len() {
        let guardian(missing_id, x23, x24, x25, x26) = missing_guards[j].clone();

        for k in 0..t_contests.len() {
            let (x8, c_tally) = t_contests[k].clone();
            let contest_tally(x9, selects) = c_tally;
            for m in 0..selects.len() {
                let (x10, select_tally) = selects[m].clone();
                let selection_tally(x11, x12, x13, x14, shares) = select_tally;
    
                for i in 0..shares.len() {
                    let selection_share(x15, s_guard_id, share, x17, rec_parts) = shares[i].clone();

                    if seq_eq(&s_guard_id, &missing_id) {

                        // Accumulator for product of (M,i,l)^(w_l) mod p
                        let mut b_acc = seq_one();

                        for n in 0..rec_parts.len() {
                            let (key, value) = rec_parts[n].clone();
                            
                            let recovered_part(x18, x19, x20, rec_share, x21, x22) = value.clone();

                            b_acc = be_seq_mul(&b_acc, &rec_share);
                        }

                        let res = seq_eq(&share, &b_acc);

                        check_b = check_b && res;
                    }

                    
                }
            }
        }
    
    }
    

    check_a && check_b
}