use hacspec_lib::*;


// Types to handle big integers
unsigned_public_integer!(BINT, 4096);

// Parameter types
pub type threshold = BINT;
pub type prime = BINT;
pub type generator = BINT;

pub type key = Seq<U8>;
pub type value = Seq<U8>;

#[derive(Default, Clone)]
pub struct key_value_pair(key, value);
pub type finite_map = Seq<key_value_pair>;

// manifest
pub type text_value = Seq<U8>;
pub type text_language = Seq<U8>;

#[derive(Default, Clone)]
pub struct text(text_value, text_language);

pub type gpu_object_id = Seq<U8>;
pub type gpu_name = Seq<U8>;
pub type gpu_type = Seq<U8>;
pub type gpu_contact_information = Seq<U8>;

#[derive(Default, Clone)]
pub struct geopolitical_unit(pub gpu_object_id, pub gpu_name, pub gpu_type, pub gpu_contact_information);

// political parties

pub type pp_object_id = Seq<U8>;
pub type pp_name = finite_map;
pub type abreviation = Seq<U8>;
pub type color = Seq<U8>;
pub type logo_uri = Seq<U8>;

#[derive(Default, Clone)]
pub struct party(pub pp_object_id, pub pp_name, pub abreviation, pub color, pub logo_uri);

// Candidate

pub type can_object_id = Seq<U8>;
pub type can_name = finite_map;
pub type party_id = Seq<U8>;
pub type image_uri = Seq<U8>;
pub type is_write_in = bool;

#[derive(Default, Clone)]
pub struct candidate(pub can_object_id, pub can_name, pub party_id, pub image_uri, pub is_write_in);

// manifest Ballot selection

pub type mbs_object_id = Seq<U8>;
pub type mbs_sequence_order = U32;
pub type candidate_id = Seq<U8>;
#[derive(Default, Clone)]
pub struct manifest_ballot_selection(pub mbs_object_id, pub mbs_sequence_order, pub candidate_id);

// manifest_contest

pub type mc_object_id = Seq<U8>;
pub type mc_sequence_order = U32;
pub type mc_electoral_district_id = Seq<U8>;
pub type mc_vote_variation = Seq<U8>;
pub type mc_number_elected = U32;
pub type mc_votes_allowed = U32;
pub type mc_name = Seq<U8>;
pub type mc_ballot_selections = Seq<manifest_ballot_selection>;
pub type mc_ballot_title = Seq<U8>;
pub type mc_ballot_subtitle = Seq<U8>;

#[derive(Default, Clone)]
pub struct manifest_contest(pub mc_object_id, pub mc_sequence_order, pub mc_electoral_district_id, pub mc_vote_variation, pub mc_number_elected,
    pub mc_votes_allowed, pub mc_name, pub mc_ballot_selections, pub mc_ballot_title, pub mc_ballot_subtitle);

// ballot style

pub type bstyle_object_id = Seq<U8>;
pub type bstyle_geopolitical_unit_ids = Seq<Seq<U8>>;
pub type bstyle_party_ids = Seq<Seq<U8>>;
pub type bstyle_image_uri = Seq<U8>;

#[derive(Default, Clone)]
pub struct ballot_style(pub bstyle_object_id, pub bstyle_geopolitical_unit_ids, pub bstyle_party_ids, pub bstyle_image_uri);

// manifest contact information

pub type mci_adress_line = Seq<Seq<U8>>;
pub type mci_email = Seq<U8>;
pub type mci_phone = Seq<U8>;
pub type mci_name = Seq<U8>;

pub struct manifest_contact(pub mci_adress_line, pub mci_email, pub mci_phone, pub mci_name);

// manifest

pub type m_election_scope_id = Seq<U8>;
pub type m_spec_version = Seq<U8>;
pub type m_type = Seq<U8>;
pub type m_start_date = Seq<U8>;
pub type m_end_date = Seq<U8>;
pub type m_geopolitical_units = Seq<geopolitical_unit>;
pub type m_parties = Seq<party>;
pub type m_candidates = Seq<candidate>;
pub type m_contests = Seq<manifest_contest>;
pub type m_ballot_styles = Seq<ballot_style>;
pub type m_name = finite_map;
pub type m_contact_information = manifest_contact;

pub struct manifest(pub m_election_scope_id, pub m_spec_version, pub m_type, pub m_start_date, pub m_end_date, pub m_geopolitical_units, pub m_parties,
    pub m_candidates, pub m_contests, pub m_ballot_styles, pub m_name, pub m_contact_information);

// schnorr proofs
pub type schnorr_public_key = Seq<U8>;
pub type schnorr_commitment = Seq<U8>;
pub type schnorr_challenge = Seq<U8>;
pub type schnorr_response = Seq<U8>;
pub type schnorr_usage = Seq<U8>;

#[derive(Default, Clone)]
pub struct schnorr_proof(pub schnorr_public_key, pub schnorr_commitment, pub schnorr_challenge, pub schnorr_response, pub schnorr_usage);

// Guardians
pub type guardian_id = Seq<U8>;
pub type sequence_order = U32;
pub type election_public_key = Seq<U8>;
pub type election_commitments = Seq<Seq<U8>>;
pub type election_proofs = Seq<schnorr_proof>;

#[derive(Default, Clone)]
pub struct guardian(pub guardian_id, pub sequence_order, pub election_public_key, pub election_commitments, pub election_proofs);

// Commitment types
pub type election_commitment_public_key = Seq<U8>;
pub type election_proof_commitment = Seq<U8>;
pub type eleciton_proof_challenge = Seq<U8>;
pub type election_proof_response = Seq<U8>;

// Context types
pub type number_of_guardians = U32;
pub type quorum = U32;
pub type elgamal_public_key = Seq<U8>;
pub type commitment_hash = Seq<U8>;
pub type manifest_hash = Seq<U8>;
pub type crypto_base_hash = Seq<U8>;
pub type crypto_extended_base_hash = Seq<U8>;
pub type ctx_extended_data = finite_map;
pub type configuration = finite_map;

#[derive(Default, Clone)]
pub struct context(pub number_of_guardians, pub quorum, pub elgamal_public_key, pub commitment_hash, pub manifest_hash, pub crypto_base_hash,
    pub crypto_extended_base_hash, pub ctx_extended_data, pub configuration);

pub type guardians = Seq<guardian>;

// Submitted ballots

// cipher text

pub type ct_pad = Seq<U8>;
pub type ct_data = Seq<U8>;

#[derive(Default, Clone)]
pub struct ciphertext(pub ct_pad, pub ct_data);

// ballots extended data

pub type ed_pad = Seq<U8>;
pub type ed_data = Seq<U8>;
pub type mac = Seq<U8>;

#[derive(Default, Clone)]
pub struct extended_data(pub ed_pad, pub ed_data, pub mac);

// disjunctive_proof

pub type proof_zero_pad = Seq<U8>;
pub type proof_zero_data = Seq<U8>;
pub type proof_one_pad = Seq<U8>;
pub type proof_one_data = Seq<U8>;
pub type proof_zero_challenge = Seq<U8>;
pub type proof_one_challenge = Seq<U8>;
pub type proof_challenge = Seq<U8>;
pub type proof_zero_response = Seq<U8>;
pub type proof_one_response = Seq<U8>;
pub type proof_usage = Seq<U8>;

#[derive(Default, Clone)]
pub struct disjunctive_proof(pub proof_zero_pad, pub proof_zero_data, pub proof_one_pad, pub proof_one_data, pub proof_zero_challenge, pub proof_one_challenge,
    pub proof_challenge, pub proof_zero_response, pub proof_one_response, pub proof_usage);

// ballot selection

pub type object_id = Seq<U8>;
pub type ballot_sequence_order = U32;
pub type description_hash = Seq<U8>;
pub type ballot_cipher_text = ciphertext;
pub type crypto_hash = Seq<U8>;
pub type is_placeholder_selection = bool;
pub type nonce = ();
pub type ballot_proof = disjunctive_proof;

#[derive(Default, Clone)]
pub struct ballot_selection(pub object_id, pub ballot_sequence_order, pub description_hash, pub ballot_cipher_text, pub crypto_hash, pub is_placeholder_selection,
    pub nonce, pub ballot_proof);

// constant proof

pub type constant_pad = Seq<U8>;
pub type constant_data = Seq<U8>;
pub type constant_challenge = Seq<U8>;
pub type constant_response = Seq<U8>;
pub type constant = U32;
pub type constant_usage = Seq<U8>;

#[derive(Default, Clone)]
pub struct constant_proof(pub constant_pad, pub constant_data, pub constant_challenge, pub constant_response, pub constant, pub constant_usage);
// contest

pub type contest_object_id = Seq<U8>;
pub type contest_sequence_order = U32;
pub type contest_description_hash = Seq<U8>;
pub type ballot_selections = Seq<ballot_selection>;
pub type ciphertext_accumulation = ciphertext;
pub type contest_crypto_hash = Seq<U8>;
pub type contest_nonce = ();
pub type contest_proof = constant_proof;
pub type contest_extended_data = extended_data;

#[derive(Default, Clone)]
pub struct contest(pub contest_object_id, pub contest_sequence_order, pub contest_description_hash, pub ballot_selections, pub ciphertext_accumulation,
    pub contest_crypto_hash, pub contest_nonce, pub contest_proof, pub contest_extended_data);

// submitted ballot

pub type sub_object_id = Seq<U8>;
pub type style_id = Seq<U8>;
pub type sub_manifest_hash = Seq<U8>;
pub type code_seed = Seq<U8>;
pub type contests = Seq<contest>;
pub type sub_code = Seq<U8>;
pub type sub_timestamp = U32;
pub type sub_crypto_hash = Seq<U8>;
pub type sub_nonce = ();
pub type sub_state = U32;

#[derive(Default, Clone)]
pub struct submitted_ballot(pub sub_object_id, pub style_id, pub sub_manifest_hash, pub code_seed, pub contests, pub sub_code, pub sub_timestamp,
    pub sub_crypto_hash, pub sub_nonce, pub sub_state);

// Encrypted tally

pub type est_object_id = Seq<U8>;
pub type est_sequence_order = U32;
pub type est_description_hash = Seq<U8>;
pub type est_ciphertext = ciphertext;

#[derive(Default, Clone)]
pub struct encrypted_selection_tally(pub est_object_id, pub est_sequence_order, pub est_description_hash, pub est_ciphertext);

// Encrypted contest tallies

pub type ect_object_id = Seq<U8>;
pub type ect_sequence_order = U32;
pub type ect_description_hash = Seq<U8>;
pub type ect_selections = Seq<(Seq<U8>, encrypted_selection_tally)>;

#[derive(Default, Clone)]
pub struct encrypted_contest_tally(pub ect_object_id, pub ect_sequence_order, pub ect_description_hash, pub ect_selections);

pub type et_object_id = Seq<U8>;
pub type et_contests = Seq<(Seq<U8>, encrypted_contest_tally)>;

#[derive(Default, Clone)]
pub struct encrypted_tally(pub et_object_id, pub et_contests);

// tally

// cp_proof

pub type cp_pad = Seq<U8>;
pub type cp_data = Seq<U8>;
pub type cp_challenge = Seq<U8>;
pub type cp_response = Seq<U8>;
pub type cp_usage = Seq<U8>;

#[derive(Default, Clone)]
pub struct cp_proof(pub cp_pad, pub cp_data, pub cp_challenge, pub cp_response, pub cp_usage);

// recovered part

pub type rp_object_id = Seq<U8>;
pub type rp_guardian_id = Seq<U8>;
pub type rp_missing_guardian_id = Seq<U8>;
pub type rp_share = Seq<U8>;
pub type rp_recovery_key = Seq<U8>;
pub type rp_proof = cp_proof;

#[derive(Default, Clone)]
pub struct recovered_part(pub rp_object_id, pub rp_guardian_id, pub rp_missing_guardian_id, pub rp_share, pub rp_recovery_key, pub rp_proof);

// selection_share

pub type ss_object_id = Seq<U8>;
pub type ss_guardian_id = Seq<U8>;
pub type ss_share = Seq<U8>;
pub type ss_proof = cp_proof;
pub type ss_recovered_parts = Seq<(Seq<U8>, recovered_part)>;

#[derive(Default, Clone)]
pub struct selection_share(pub ss_object_id, pub ss_guardian_id, pub ss_share, pub ss_proof, pub ss_recovered_parts);

// selection_tally

pub type st_object_id = Seq<U8>;
pub type st_tally = U32;
pub type st_value = Seq<U8>;
pub type st_message = ciphertext;
pub type st_shares = Seq<selection_share>;

#[derive(Default, Clone)]
pub struct selection_tally(pub st_object_id, pub st_tally, pub st_value, pub st_message, pub st_shares);

// contest_tally

pub type ct_object_id = Seq<U8>;
pub type ct_selections = Seq<(Seq<U8>, selection_tally)>;

#[derive(Default, Clone)]
pub struct contest_tally(pub ct_object_id, pub ct_selections);

// tally

pub type tally_object_id = Seq<U8>;
pub type tally_contests = Seq<(Seq<U8>, contest_tally)>;

#[derive(Default, Clone)]
pub struct tally(pub tally_object_id, pub tally_contests);

// Lagrange coefficients
pub type l_coefficient = (Seq<U8>, Seq<U8>);
pub type l_coefficients = Seq<l_coefficient>;

// Spoiled ballots

pub type sb_ds_object_id = Seq<U8>;
pub type sb_ds_tally = U32;
pub type sb_ds_value = Seq<U8>;
pub type sb_ds_message = ciphertext;
pub type sb_ds_shares = Seq<selection_share>;

#[derive(Default, Clone)]
pub struct spoiled_ballot_decrypted_selection(pub sb_ds_object_id, pub sb_ds_tally, pub sb_ds_value, pub sb_ds_message, pub sb_ds_shares);

// sb contest data

pub type sb_cd_object_id = Seq<U8>;
pub type sb_cd_data = Seq<U8>;
pub type sb_cd_ciphertext_extended_data = extended_data;
pub type sb_cd_shares = Seq<selection_share>;

#[derive(Default, Clone)]
pub struct spoiled_ballot_contest_data(pub sb_cd_object_id, pub sb_cd_data, pub sb_cd_ciphertext_extended_data, pub sb_cd_shares);

// sb decrypted contest

pub type sb_dc_object_id = Seq<U8>;
pub type sb_dc_selections = Seq<(Seq<U8>, spoiled_ballot_decrypted_selection)>;
pub type sb_dc_contest_data = spoiled_ballot_contest_data;

#[derive(Default, Clone)]
pub struct spoiled_ballot_decrypted_contest(pub sb_dc_object_id, pub sb_dc_selections, pub sb_dc_contest_data);

// spoiled ballot

pub type sb_object_id = Seq<U8>;
pub type sb_contests = Seq<(Seq<U8>, spoiled_ballot_decrypted_contest)>;

#[derive(Default, Clone)]
pub struct spoiled_ballot(pub sb_object_id, pub sb_contests);

// Election type
pub struct election_record(guardians);