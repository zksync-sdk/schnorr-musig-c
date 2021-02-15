use crate::decoder::Decoder;
use crate::errors::MusigABIError;
use bellman::pairing::bn256::Bn256;
use bellman::{PrimeField, PrimeFieldRepr};
use franklin_crypto::alt_babyjubjub::AltJubjubBn256;
use franklin_crypto::jubjub::FixedGenerators;
use musig::signer::MuSigSigner;
use rand::SeedableRng;

pub struct MusigBN256Signer {
    musig_signer: MuSigSigner<Bn256>,
}

impl MusigBN256Signer {
    pub fn new(
        input: &[u8], // concatenation of all pubkeys
        position: usize,
    ) -> Result<Self, MusigABIError> {
        let pubkeys = Decoder::decode_pubkey_list(input)?;

        let jubjub_params = AltJubjubBn256::new();
        let generator = FixedGenerators::SpendingKeyGenerator;

        let signer = MuSigSigner::new(&pubkeys[..], position, jubjub_params, generator)
            .map_err(MusigABIError::MuSigError)?;

        Ok(MusigBN256Signer {
            musig_signer: signer,
        })
    }

    pub fn compute_precommitment(&mut self, seed: &[u32]) -> Result<Vec<u8>, MusigABIError> {
        if seed.len() < 4 {
            return Err(MusigABIError::InvalidInputData);
        }
        let mut rng = rand::ChaChaRng::from_seed(seed);

        let pre_commitment = self
            .musig_signer
            .compute_precommitment(&mut rng)
            .map_err(MusigABIError::MuSigError)?;

        Ok(pre_commitment)
    }

    pub fn receive_precommitments(&mut self, input: &[u8]) -> Result<Vec<u8>, MusigABIError> {
        let pre_commitments = Decoder::decode_pre_commitments(input)?;

        let nonce_commitment = self
            .musig_signer
            .receive_precommitments(&pre_commitments)
            .map_err(MusigABIError::MuSigError)?;

        let mut encoded_nonce_commitment = vec![0u8; crate::decoder::STANDARD_ENCODING_LENGTH];

        nonce_commitment
            .write(&mut encoded_nonce_commitment[..])
            .map_err(|_| MusigABIError::EncodingError)?;

        Ok(encoded_nonce_commitment)
    }

    pub fn receive_commitments(&mut self, input: &[u8]) -> Result<Vec<u8>, MusigABIError> {
        let commitments = Decoder::decode_commitments(input)?;

        let aggregated_commitment = self
            .musig_signer
            .receive_commitments(&commitments)
            .map_err(MusigABIError::MuSigError)?;

        let mut encoded_agg_commitment = vec![0u8; crate::decoder::STANDARD_ENCODING_LENGTH];

        aggregated_commitment
            .write(&mut encoded_agg_commitment[..])
            .map_err(|_| MusigABIError::EncodingError)?;

        Ok(encoded_agg_commitment)
    }

    pub fn sign(
        &mut self,
        private_key_bytes: &[u8],
        message: &[u8],
    ) -> Result<Vec<u8>, MusigABIError> {
        let rescue_params =
            franklin_crypto::rescue::bn256::Bn256RescueParams::new_checked_2_into_1();

        let private_key = Decoder::decode_private_key(private_key_bytes)?;

        let signature_share = self
            .musig_signer
            .sign(&private_key, message, &rescue_params)
            .map_err(MusigABIError::MuSigError)?;

        let mut encoded_sig_share = vec![0u8; crate::decoder::STANDARD_ENCODING_LENGTH];

        signature_share
            .into_repr()
            .write_be(&mut encoded_sig_share[..])
            .map_err(|_| MusigABIError::EncodingError)?;

        Ok(encoded_sig_share)
    }

    pub fn receive_signature_shares(&self, input: &[u8]) -> Result<Vec<u8>, MusigABIError> {
        let signature_shares = Decoder::decode_signature_shares(input)?;

        let signature = self
            .musig_signer
            .receive_signatures(&signature_shares)
            .map_err(MusigABIError::MuSigError)?;

        // (R, s)
        let mut encoded_sig = vec![0u8; 2 * crate::decoder::STANDARD_ENCODING_LENGTH];
        signature
            .r
            .write(&mut encoded_sig[..crate::decoder::STANDARD_ENCODING_LENGTH])
            .map_err(|_| MusigABIError::EncodingError)?;

        signature
            .s
            .into_repr()
            .write_le(&mut encoded_sig[crate::decoder::STANDARD_ENCODING_LENGTH..])
            .map_err(|_| MusigABIError::EncodingError)?;

        Ok(encoded_sig)
    }
}
