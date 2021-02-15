use crate::decoder::{Decoder, STANDARD_ENCODING_LENGTH};
use crate::errors::MusigABIError;
use crate::local::JUBJUB_PARAMS;
use musig::aggregated_pubkey::AggregatedPublicKey;

pub fn compute(encoded_pubkeys: &[u8]) -> Result<Vec<u8>, MusigABIError> {
    let pubkeys = Decoder::decode_pubkey_list(encoded_pubkeys)?;

    let (agg_pubkey, _) = JUBJUB_PARAMS
        .with(|params| AggregatedPublicKey::compute_for_each_party(&pubkeys, &params))
        .map_err(MusigABIError::MuSigError)?;

    let mut encoded_agg_pubkey = vec![0u8; STANDARD_ENCODING_LENGTH];

    agg_pubkey
        .write(&mut encoded_agg_pubkey[..])
        .map_err(|_| MusigABIError::EncodingError)?;

    Ok(encoded_agg_pubkey)
}
