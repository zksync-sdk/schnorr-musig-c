use crate::errors::MusigABIError;
use bellman::pairing::bn256::Bn256;
use bellman::{Field, PrimeField, PrimeFieldRepr};
use franklin_crypto::alt_babyjubjub::{fs::Fs, fs::FsRepr, AltJubjubBn256};
use franklin_crypto::eddsa::{PrivateKey, PublicKey};
use franklin_crypto::jubjub::edwards::Point;
use franklin_crypto::jubjub::Unknown;

// each encoded elements(point, scalar, pubkey) needs to have 32byte size
pub const STANDARD_ENCODING_LENGTH: usize = 32;
pub const AGG_SIG_ENCODING_LENGTH: usize = 64;

pub struct Decoder;

/// ABI Decoder for input data
impl Decoder {
    pub fn decode_private_key(input: &[u8]) -> Result<PrivateKey<Bn256>, MusigABIError> {
        let privkey_len = STANDARD_ENCODING_LENGTH;
        if input.is_empty() || input.len() % privkey_len != 0 {
            return Err(MusigABIError::InvalidInputData);
        }
        let mut privkey_repr = FsRepr::default();
        privkey_repr.read_be(input).unwrap();
        let priv_scalar = Fs::from_repr(privkey_repr).unwrap();

        Ok(PrivateKey::<Bn256>(priv_scalar))
    }

    pub fn decode_pubkey_list(input: &[u8]) -> Result<Vec<PublicKey<Bn256>>, MusigABIError> {
        let point_len = STANDARD_ENCODING_LENGTH;
        if input.is_empty() || input.len() % point_len != 0 {
            return Err(MusigABIError::InvalidInputData);
        }
        let number_of_pubkeys = input.len() / point_len;
        let params = AltJubjubBn256::new();

        let mut pubkeys = vec![PublicKey::<Bn256>(Point::zero()); number_of_pubkeys];
        for (i, pubkey) in pubkeys.iter_mut().enumerate() {
            let offset = i * point_len;
            let buf = input[offset..offset + point_len].to_vec();
            *pubkey = PublicKey::read(&buf[..], &params).unwrap();
        }

        Ok(pubkeys)
    }

    pub fn decode_commitments(input: &[u8]) -> Result<Vec<Point<Bn256, Unknown>>, MusigABIError> {
        let commitment_len = STANDARD_ENCODING_LENGTH;
        if input.is_empty() || input.len() % commitment_len != 0 {
            return Err(MusigABIError::InvalidInputData);
        }
        let number_of_pubkeys = input.len() / commitment_len;
        let params = AltJubjubBn256::new();

        let mut commitments = vec![Point::zero(); number_of_pubkeys];
        for (i, commitment) in commitments.iter_mut().enumerate() {
            let offset = i * commitment_len;
            let buf = input[offset..(offset + commitment_len)].to_vec();
            *commitment = Point::read(&buf[..], &params).unwrap();
        }

        Ok(commitments)
    }

    pub fn decode_pre_commitments(input: &[u8]) -> Result<Vec<Vec<u8>>, MusigABIError> {
        let pre_commitment_len = STANDARD_ENCODING_LENGTH;
        if input.is_empty() || input.len() % pre_commitment_len != 0 {
            return Err(MusigABIError::InvalidInputData);
        }
        let number_of_commitments = input.len() / pre_commitment_len;

        let mut pre_commitments = vec![vec![0u8; pre_commitment_len]; number_of_commitments];
        for (i, pre_commitment) in pre_commitments.iter_mut().enumerate() {
            let offset = i * pre_commitment_len;
            let buf = input[offset..(offset + pre_commitment_len)].to_vec();
            *pre_commitment = buf.to_vec();
        }

        Ok(pre_commitments)
    }

    pub fn decode_signature_shares(input: &[u8]) -> Result<Vec<Fs>, MusigABIError> {
        let share_len = STANDARD_ENCODING_LENGTH;
        if input.is_empty() || input.len() % share_len != 0 {
            return Err(MusigABIError::InvalidInputData);
        }
        let number_of_pubkeys = input.len() / share_len;

        let mut signature_shares = vec![Fs::zero(); number_of_pubkeys];

        for (i, share) in signature_shares.iter_mut().enumerate() {
            let offset = i * share_len;
            let buf = input[offset..(offset + share_len)].to_vec();

            let mut repr = FsRepr::default();
            repr.read_be(&buf[..]).unwrap();
            *share = Fs::from_repr(repr).unwrap();
        }

        Ok(signature_shares)
    }
}
