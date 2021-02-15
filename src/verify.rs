use crate::decoder::{Decoder, STANDARD_ENCODING_LENGTH};
use crate::errors::MusigABIError;
use bellman::{PrimeField, PrimeFieldRepr};
use franklin_crypto::alt_babyjubjub::{fs::Fs, fs::FsRepr, AltJubjubBn256};
use franklin_crypto::eddsa::Signature;
use franklin_crypto::jubjub::edwards::Point;
use franklin_crypto::jubjub::FixedGenerators;
use musig::verifier::MuSigVerifier;

pub fn verify(
    message: &[u8],
    encoded_pubkeys: &[u8],
    encoded_signature: &[u8],
) -> Result<bool, MusigABIError> {
    let jubjub_params = AltJubjubBn256::new();
    let generator = FixedGenerators::SpendingKeyGenerator;
    let rescue_params = franklin_crypto::rescue::bn256::Bn256RescueParams::new_checked_2_into_1();

    let pubkeys = Decoder::decode_pubkey_list(encoded_pubkeys)?;

    let sig_r = Point::read(
        &encoded_signature[..STANDARD_ENCODING_LENGTH],
        &jubjub_params,
    )
    .map_err(|_| MusigABIError::EncodingError)?;

    let mut repr = FsRepr::default();
    repr.read_le(&encoded_signature[STANDARD_ENCODING_LENGTH..])
        .map_err(|_| MusigABIError::EncodingError)?;
    let sig_s = Fs::from_repr(repr).unwrap();

    let signature = Signature { r: sig_r, s: sig_s };

    let is_valid = MuSigVerifier::verify(
        message,
        &pubkeys,
        &signature,
        &jubjub_params,
        generator,
        &rescue_params,
    )
    .map_err(MusigABIError::MuSigError)?;

    Ok(is_valid)
}
