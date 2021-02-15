use franklin_crypto::{alt_babyjubjub::AltJubjubBn256, rescue::bn256::Bn256RescueParams};

// Thread local storage of the precomputed parameters.
thread_local! {
    pub static JUBJUB_PARAMS: AltJubjubBn256 = AltJubjubBn256::new();
    pub static RESCUE_PARAMS: Bn256RescueParams = Bn256RescueParams::new_checked_2_into_1();
}
