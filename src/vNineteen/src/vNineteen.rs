use hacspec_lib::*;
use hacspec_provider::*;
use schema::*;
use string::*;
use vOne::*;
use seq_arithmetic::*;
use hacspec_sha256::*;
/// Verification 19: Correctness of contest replacement decryptions for spoiled ballots
/// 
/// Confirm the correct missing contest data share for each contest on the spoiled ballot for each missing guardian $T_i$
/// where $m_i$ is the product of $(m_{i,\lambda})^{w_{\lambda}} mod p$
pub fn nineteenthCheck(sp_ballots: Seq<spoiled_ballot>, missing_guards: Seq<guardian>, surr_guards: Seq<guardian>, coeffs: l_coefficients) -> bool {

    let mut check_a = true;

    let p = PBARR.to_be_bytes();

    // For every $T_i$
    for i in 0..missing_guards.len() {
        let guardian(missing_id, x1, x2, x3, x4) = missing_guards[i].clone();

        // For every spoiled ballot
        for j in 0..sp_ballots.len() {
            let spoiled_ballot(x5, sp_cons) = sp_ballots[j].clone();

            // For every contest
            for k in 0..sp_cons.len() {
                let (x6, spoiled_ballot_decrypted_contest(x7, x8, sp_con_data)) = sp_cons[k].clone();

                let spoiled_ballot_contest_data(x9, x10, x11, sp_shares) = sp_con_data.clone();

                // For every share
                for l in 0..sp_shares.len() {
                    let selection_share(x12, share_guard_id, sp_share, x13, sp_rec_parts) = sp_shares[l].clone();

                    // If share matches $T_i$
                    if seq_eq(&share_guard_id, &missing_id) {
                        let partial_dec = sp_share.clone();

                        let mut prod = seq_one();

                        // For every $T_{\lambda}$
                        for m in 0..surr_guards.len() {
                            let mut surr_coeff = seq_one();

                            let guardian(surr_id, x14, x15, x16, x17) = surr_guards[m].clone();

                            // For every coefficient
                            for n in 0..coeffs.len() {
                                let (coeff_key, coeff_value) = coeffs[n].clone();

                                // If coefficient matches $T_{\lambda}$
                                if seq_eq(&surr_id, &coeff_key) {
                                    surr_coeff = coeff_value.clone();
                                }
                            }

                            // For every recovered part in share $i$
                            for o in 0..sp_rec_parts.len() {
                                let (rec_id, sp_rec_part) = sp_rec_parts[o].clone();

                                // If recovered part matches $T_{\lambda}$
                                if seq_eq(&rec_id, &surr_id) {
                                    let recovered_part(x18, x19, x20, sp_rec_share, x21, x22) = sp_rec_part.clone();

                                    // $m_{i,\lambda}^{w_{\lambda}}$ mod $p$
                                    let mod_exp = be_seq_mod_exp(&sp_rec_share, &surr_coeff, &p);

                                    // product times $m_{i,\lambda}^{w_{\lambda}}$ mod $p$
                                    prod = be_seq_mul_mod(&prod, &mod_exp, &p);
                                }
                            }
                        }

                        // step A for $T_i$
                        let missing_eq = seq_eq(&partial_dec, &prod);

                        check_a = check_a && missing_eq;

                    }

                }
            }
        }

        
    }

    check_a
    
}