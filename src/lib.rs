use std::slice;

use errors::MusigABIError;
use musig::errors::MusigError;
use signer::MusigBN256Signer;

mod decoder;
mod errors;
mod local;

mod aggregate_pubkey;
mod signer;
mod verify;

#[repr(C)]
pub struct MusigSigner {
    inner: Box<MusigBN256Signer>,
}

#[repr(C)]
pub struct AggregatedPublicKey {
    data: [u8; decoder::STANDARD_ENCODING_LENGTH],
}

#[repr(C)]
pub struct Precommitment {
    data: [u8; decoder::STANDARD_ENCODING_LENGTH],
}

#[repr(C)]
pub struct Commitment {
    data: [u8; decoder::STANDARD_ENCODING_LENGTH],
}

#[repr(C)]
pub struct AggregatedCommitment {
    data: [u8; decoder::STANDARD_ENCODING_LENGTH],
}

#[repr(C)]
pub struct Signature {
    data: [u8; decoder::STANDARD_ENCODING_LENGTH],
}

#[repr(C)]
pub struct AggregatedSignature {
    data: [u8; decoder::AGG_SIG_ENCODING_LENGTH],
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub enum MusigRes {
    OK = 0,
    INVALID_INPUT_DATA,
    ENCODING_ERROR,
    SIGNATURE_VERIFICATION_FAILED,

    // Core Musig library error codes
    INVALID_PUBKEY_LENGTH = 100,
    NONCE_COMMITMENT_NOT_GENERATED,
    NONCE_PRECOMMITMENTS_NOT_RECEIVED,
    NONCE_PRECOMMITMENTS_AND_PARTICIPANTS_NOT_MATCH,
    NONCE_COMMITMENTS_NOT_RECEIVED,
    NONCE_COMMITMENTS_AND_PARTICIPANTS_NOT_MATCH,
    SIGNATURE_SHARE_AND_PARTICIPANTS_NOT_MATCH,
    COMMITMENT_IS_NOT_IN_CORRECT_SUBGROUP,
    INVALID_COMMITMENT,
    INVALID_PUBLIC_KEY,
    INVALID_PARTICIPANT_POSITION,
    AGGREGATED_NONCE_COMMITMENT_NOT_COMPUTED,
    CHALLENGE_NOT_GENERATED,
    INVALID_SIGNATURE_SHARE,
    INVALID_SEED,
}

impl From<MusigABIError> for MusigRes {
    fn from(e: MusigABIError) -> Self {
        match e {
            MusigABIError::InvalidInputData => MusigRes::INVALID_INPUT_DATA,
            MusigABIError::EncodingError => MusigRes::ENCODING_ERROR,
            MusigABIError::VerificationFailed => MusigRes::SIGNATURE_VERIFICATION_FAILED,
            MusigABIError::MuSigError(e) => e.into(),
        }
    }
}

impl From<MusigError> for MusigRes {
    fn from(e: MusigError) -> Self {
        match e {
            MusigError::InvalidPubkeyLength => MusigRes::INVALID_PUBKEY_LENGTH,
            MusigError::NonceCommitmentNotGenerated => MusigRes::NONCE_COMMITMENT_NOT_GENERATED,
            MusigError::NoncePreCommitmentsNotReceived => {
                MusigRes::NONCE_PRECOMMITMENTS_NOT_RECEIVED
            }
            MusigError::NoncePreCommitmentsAndParticipantsNotMatch => {
                MusigRes::NONCE_PRECOMMITMENTS_AND_PARTICIPANTS_NOT_MATCH
            }
            MusigError::NonceCommitmentsNotReceived => MusigRes::NONCE_COMMITMENTS_NOT_RECEIVED,
            MusigError::NonceCommitmentsAndParticipantsNotMatch => {
                MusigRes::NONCE_COMMITMENTS_AND_PARTICIPANTS_NOT_MATCH
            }
            MusigError::SignatureShareAndParticipantsNotMatch => {
                MusigRes::SIGNATURE_SHARE_AND_PARTICIPANTS_NOT_MATCH
            }
            MusigError::CommitmentIsNotInCorrectSubgroup => {
                MusigRes::COMMITMENT_IS_NOT_IN_CORRECT_SUBGROUP
            }
            MusigError::InvalidCommitment => MusigRes::INVALID_COMMITMENT,
            MusigError::InvalidPublicKey => MusigRes::INVALID_PUBLIC_KEY,
            MusigError::InvalidParticipantPosition => MusigRes::INVALID_PARTICIPANT_POSITION,
            MusigError::AggregatedNonceCommitmentNotComputed => {
                MusigRes::AGGREGATED_NONCE_COMMITMENT_NOT_COMPUTED
            }
            MusigError::ChallengeNotGenerated => MusigRes::CHALLENGE_NOT_GENERATED,
            MusigError::InvalidSignatureShare => MusigRes::INVALID_SIGNATURE_SHARE,
            MusigError::InvalidSeed => MusigRes::INVALID_SEED,
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn schnorr_musig_new_signer(
    encoded_pubkeys: *const u8,
    encoded_pubkeys_len: libc::size_t,
    position: libc::size_t,
) -> Box<MusigSigner> {
    let encoded_pubkeys = slice::from_raw_parts(encoded_pubkeys, encoded_pubkeys_len);
    let musig = MusigBN256Signer::new(encoded_pubkeys, position).unwrap();

    Box::new(MusigSigner {
        inner: Box::new(musig),
    })
}

#[no_mangle]
pub extern "C" fn schnorr_musig_delete_signer(_: Option<Box<MusigSigner>>) {}

#[no_mangle]
pub unsafe extern "C" fn schnorr_musig_compute_precommitment(
    signer: &mut MusigSigner,
    seed: *const u32,
    seed_len: libc::size_t,
    precommitment: *mut Precommitment,
) -> MusigRes {
    let seed = slice::from_raw_parts(seed, seed_len);
    match signer.inner.compute_precommitment(seed) {
        Ok(result) => {
            (*precommitment).data.copy_from_slice(result.as_slice());
            MusigRes::OK
        }
        Err(e) => e.into(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn schnorr_musig_receive_precommitments(
    signer: &mut MusigSigner,
    input: *const u8,
    input_len: libc::size_t,
    commitment: *mut Commitment,
) -> MusigRes {
    let input = slice::from_raw_parts(input, input_len);
    match signer.inner.receive_precommitments(input) {
        Ok(result) => {
            (*commitment).data.copy_from_slice(result.as_slice());
            MusigRes::OK
        }
        Err(e) => e.into(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn schnorr_musig_receive_commitments(
    signer: &mut MusigSigner,
    input: *const u8,
    input_len: libc::size_t,
    agg_commitment: *mut AggregatedCommitment,
) -> MusigRes {
    let input = slice::from_raw_parts(input, input_len);
    match signer.inner.receive_commitments(input) {
        Ok(result) => {
            (*agg_commitment).data.copy_from_slice(result.as_slice());
            MusigRes::OK
        }
        Err(e) => e.into(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn schnorr_musig_sign(
    signer: &mut MusigSigner,
    private_key: *const u8,
    private_key_len: libc::size_t,
    message: *const u8,
    message_len: libc::size_t,
    signature: *mut Signature,
) -> MusigRes {
    let private_key = slice::from_raw_parts(private_key, private_key_len);
    let message = slice::from_raw_parts(message, message_len);
    match signer.inner.sign(private_key, message) {
        Ok(result) => {
            (*signature).data.copy_from_slice(result.as_slice());
            MusigRes::OK
        }
        Err(e) => e.into(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn schnorr_musig_signature_shares(
    signer: &mut MusigSigner,
    input: *const u8,
    input_len: libc::size_t,
    signature_shares: *mut AggregatedSignature,
) -> MusigRes {
    let input = slice::from_raw_parts(input, input_len);
    match signer.inner.receive_signature_shares(input) {
        Ok(result) => {
            (*signature_shares).data.copy_from_slice(result.as_slice());
            MusigRes::OK
        }
        Err(e) => e.into(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn schnorr_musig_aggregate_pubkeys(
    encoded_pubkeys: *const u8,
    encoded_pubkeys_len: libc::size_t,
    aggregate_pubkeys: *mut AggregatedPublicKey,
) -> MusigRes {
    let encoded_pubkeys = slice::from_raw_parts(encoded_pubkeys, encoded_pubkeys_len);

    match aggregate_pubkey::compute(encoded_pubkeys) {
        Ok(pubkey) => {
            (*aggregate_pubkeys).data.copy_from_slice(pubkey.as_slice());
            MusigRes::OK
        }
        Err(e) => e.into(),
    }
}

#[no_mangle]
pub unsafe extern "C" fn schnorr_musig_verify(
    message: *const u8,
    message_len: libc::size_t,
    encoded_pubkeys: *const u8,
    encoded_pubkeys_len: libc::size_t,
    encoded_signature: *const u8,
    encoded_signature_len: libc::size_t,
) -> MusigRes {
    let message = slice::from_raw_parts(message, message_len);
    let encoded_pubkeys = slice::from_raw_parts(encoded_pubkeys, encoded_pubkeys_len);
    let encoded_signature = slice::from_raw_parts(encoded_signature, encoded_signature_len);

    match verify::verify(message, encoded_pubkeys, encoded_signature) {
        Ok(verified) => {
            if verified {
                MusigRes::OK
            } else {
                MusigRes::SIGNATURE_VERIFICATION_FAILED
            }
        }
        Err(e) => e.into(),
    }
}
