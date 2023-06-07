use hacspec_lib::*;
use hacspec_provider::*;
use schema::*;
use string::*;
use vOne::*;
use seq_arithmetic::*;
use hacspec_sha256::*;

fn fifthCheck(manifest_contests: m_contests, sub_ballots: Seq<submitted_ballot>, ctx: context) -> bool {
    let mut check_five = true;
    
    for i in 0..sub_ballots.len() {
        let submitted_ballot(x1, px2, x3, x4, sub_cons, x5, x6, x7, x8, x9) = sub_ballots[i].clone();

        for j in 0..sub_cons.len() {
            let contest(x10, sub_con_seq, x11, x12, x13, x14, x15, x16, x17) = sub_cons[j].clone();

            for k in 0..manifest_contests.len() {
                let manifest_contest(x18,  m_con_seq, x19, x20, x21, x22, x23, x24, x25, x26) = manifest_contests[k].clone();
                
                if sub_con_seq.declassify() == m_con_seq.declassify() {
                    check_five = check_five && check_contest(m_con_seq, sub_cons[j].clone(), ctx.clone());
                }
            }
        }
    }

    check_five
}

fn check_contest(l: U32, contest(x10, x11, x12, bal, c_acc, x13, x14, pr, x15): contest,
context(x16, x17, el_pk, x19, x20, x21, cebh, x22, x23): context) -> bool {
    // Declare constants p, q, g from schema
    let p = vOne::PBARR.to_be_bytes();
    let q = vOne::QBARR.to_be_bytes();
    let g = vOne::GBARR.to_be_bytes();
    
    let mut n_of_placeholders = 0;
    let mut c_pad_prod = seq_one();
    let mut c_data_prod = seq_one();
    for i in 0..(bal.len()) {
        let ballot_selection(x24, x25, x26, ciph, x27, is_place, x28, x29) = bal[i].clone();
        if is_place {
            n_of_placeholders = n_of_placeholders + 1;
        }
        // Product of alpha_i and product of beta_i
        let ciphertext(c_pad, c_data) = ciph;
        c_pad_prod = be_seq_mul_mod(&c_pad_prod, &c_pad, &p);
        c_data_prod = be_seq_mul_mod(&c_data_prod, &c_data, &p);

    }

    // Step 5.A: Check if number of placeholder positions matches the contest's selection limit
    let check_a = n_of_placeholders == U32::declassify(l);

    let ciphertext(c_acc_pad, c_acc_data) = c_acc;

    // Check c_acc_pad equals product of alpha_i mod p and c_acc_data equals product of beta_i mod p
    let check_b = seq_eq(&c_acc_pad, &c_pad_prod) && seq_eq(&c_acc_data, &c_data_prod);

    let constant_proof(con_pad, con_data, c, v, x24, x25) = pr;

    // Check that value V is less than q
    let check_c = !seq_leq(&q, &v);

    // a^q mod p and b^q mod p
    let con_pad_mod = be_seq_mod_exp(&con_pad, &q, &p);
    let con_data_mod = be_seq_mod_exp(&con_data, &q, &p);

    // Checks a < p, b < p, a^q mod p = 1, b^q mod p = 1
    let check_d = !seq_leq(&p, &con_pad) && !seq_leq(&p, &con_data) && seq_eq(&con_pad_mod, &seq_one()) && seq_eq(&con_data_mod, &seq_one());

    // Creating list of strings for hashing
    let mut str_for_hash = Seq::<Seq::<U8>>::new(5);

    str_for_hash[0] = from_be_bytes_to_utf8(cebh);
    str_for_hash[1] = from_be_bytes_to_utf8(c_acc_pad.clone());
    str_for_hash[2] = from_be_bytes_to_utf8(c_acc_data.clone());
    str_for_hash[3] = from_be_bytes_to_utf8(con_pad.clone());
    str_for_hash[4] = from_be_bytes_to_utf8(con_data.clone());

    // Concatenating them with pipe | characters between
    let strconcat = concat_strings(str_for_hash);

    // Hashing with SHA256
    let hashed_str = hash(&strconcat).to_be_bytes();

    // Checking if C is correctly computed according to 5.E
    let check_e = seq_eq(&c, &hashed_str);

    // a mod p
    let a_mod_p = be_seq_mod(&con_pad, &p);

    // acc_pad^C mod p
    let acc_c_mod_p = be_seq_mod_exp(&c_acc_pad, &c, &p);

    // Mod product of a mod p and acc_pad^C mod p
    let f_right = be_seq_mul_mod(&a_mod_p, &acc_c_mod_p, &p);
    
    // g^V mod p
    let f_left = be_seq_mod_exp(&g, &v, &p);

    // Check if g^V mod p equals (a * acc_pad^C) mod p
    let check_f = seq_eq(&f_left, &f_right);

    // Making l into Seq<U8> to be able to multiply
    let l_as_seq = be_U32_to_seq(&l);

    // Product of L and C
    let l_c_prod = be_seq_mul(&l_as_seq, &c);

    // g^(LC) mod p
    let g_l_c_mod = be_seq_mod_exp(&g, &l_c_prod, &p);

    // K^V mod p
    let k_v_mod = be_seq_mod_exp(&el_pk, &v, &p);

    // Product of g^(LC) mod p and K^V mod p
    let g_left = be_seq_mul_mod(&g_l_c_mod, &k_v_mod, &p);

    // b mod p
    let b_mod = be_seq_mod(&con_data, &p);

    // acc_data^C mod p
    let data_c_mod = be_seq_mod_exp(&c_acc_data, &c, &p);

    // Product of b mod p and acc_data^C mod p
    let g_right = be_seq_mul_mod(&b_mod, &data_c_mod, &p);

    // Check 5.G
    let check_g = seq_eq(&g_left, &g_right);

    check_a && check_b && check_c && check_d && check_e && check_f && check_g
}