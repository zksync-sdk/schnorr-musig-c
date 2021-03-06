#ifndef SCHNORR_MUSIG_H
#define SCHNORR_MUSIG_H

/* Generated with cbindgen:0.17.0 */

/* Warning, this file is autogenerated by cbindgen. Don't modify this manually. */

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>


#define STANDARD_ENCODING_LENGTH 32

#define AGG_SIG_ENCODING_LENGTH 64

typedef enum MusigRes {
  OK = 0,
  INVALID_INPUT_DATA,
  ENCODING_ERROR,
  SIGNATURE_VERIFICATION_FAILED,
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
} MusigRes;

typedef struct MusigBN256Signer MusigBN256Signer;

typedef struct AggregatedPublicKey {
  uint8_t data[STANDARD_ENCODING_LENGTH];
} AggregatedPublicKey;

typedef struct MusigSigner {
  struct MusigBN256Signer *inner;
} MusigSigner;

typedef struct Precommitment {
  uint8_t data[STANDARD_ENCODING_LENGTH];
} Precommitment;

typedef struct AggregatedCommitment {
  uint8_t data[STANDARD_ENCODING_LENGTH];
} AggregatedCommitment;

typedef struct Commitment {
  uint8_t data[STANDARD_ENCODING_LENGTH];
} Commitment;

typedef struct Signature {
  uint8_t data[STANDARD_ENCODING_LENGTH];
} Signature;

typedef struct AggregatedSignature {
  uint8_t data[AGG_SIG_ENCODING_LENGTH];
} AggregatedSignature;

enum MusigRes schnorr_musig_aggregate_pubkeys(const uint8_t *encoded_pubkeys,
                                              size_t encoded_pubkeys_len,
                                              struct AggregatedPublicKey *aggregate_pubkeys);

enum MusigRes schnorr_musig_compute_precommitment(struct MusigSigner *signer,
                                                  const uint32_t *seed,
                                                  size_t seed_len,
                                                  struct Precommitment *precommitment);

void schnorr_musig_delete_signer(struct MusigSigner*);

struct MusigSigner *schnorr_musig_new_signer(const uint8_t *encoded_pubkeys,
                                             size_t encoded_pubkeys_len,
                                             size_t position);

enum MusigRes schnorr_musig_receive_commitments(struct MusigSigner *signer,
                                                const uint8_t *input,
                                                size_t input_len,
                                                struct AggregatedCommitment *agg_commitment);

enum MusigRes schnorr_musig_receive_precommitments(struct MusigSigner *signer,
                                                   const uint8_t *input,
                                                   size_t input_len,
                                                   struct Commitment *commitment);

enum MusigRes schnorr_musig_receive_signature_shares(struct MusigSigner *signer,
                                                     const uint8_t *input,
                                                     size_t input_len,
                                                     struct AggregatedSignature *signature_shares);

enum MusigRes schnorr_musig_sign(struct MusigSigner *signer,
                                 const uint8_t *private_key,
                                 size_t private_key_len,
                                 const uint8_t *message,
                                 size_t message_len,
                                 struct Signature *signature);

enum MusigRes schnorr_musig_verify(const uint8_t *message,
                                   size_t message_len,
                                   const uint8_t *encoded_pubkeys,
                                   size_t encoded_pubkeys_len,
                                   const uint8_t *encoded_signature,
                                   size_t encoded_signature_len);

#endif /* SCHNORR_MUSIG_H */
