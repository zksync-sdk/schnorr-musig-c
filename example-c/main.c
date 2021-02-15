#include "../schnorr_musig.h"
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>

void print_bytes(uint8_t * arr, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (arr[i] <= 0xF) {
            printf("0%" PRIx8, arr[i]);
        } else {
            printf("%" PRIx8, arr[i]);
        }
    }
    printf("\n");
}

int test_single();
int test_multiple();
int verify(uint8_t *, size_t, size_t);

int main() {
    int result = 0;

    result += test_single();
    result += test_multiple();

    return result;
}

int test_single() {
    uint32_t seed[] = { rand(), rand(), rand(), rand() };
    uint8_t private_key[32] = {1, 31, 91, 153, 8, 76, 92, 46, 45, 94, 99, 72, 142, 15, 113, 104, 213, 153, 165, 192, 31, 233, 254, 196, 201, 150, 5, 116, 61, 165, 232, 92};
    uint8_t public_key[32] = { 23, 156, 58, 89, 20, 125, 48, 49, 108, 136, 102, 40, 133, 35, 72, 201, 180, 42, 24, 184, 33, 8, 74, 201, 239, 121, 189, 115, 233, 185, 78, 141 };
    uint8_t message[] = { 'h', 'e', 'l', 'l', 'o' };

    struct MusigSigner * signer = schnorr_musig_new_signer(public_key, 32, 0);

    struct Precommitment * precommitment = malloc(sizeof(struct Precommitment));

    int result = schnorr_musig_compute_precommitment(signer, seed, 4, precommitment);
    print_bytes(precommitment->data, 32);

    struct Commitment * commitment = malloc(sizeof(struct Commitment));
    result += schnorr_musig_receive_precommitments(signer, precommitment->data, 32, commitment);
    print_bytes(commitment->data, 32);

    struct AggregatedCommitment * aggregated_commitment = malloc(sizeof(struct AggregatedCommitment));
    result += schnorr_musig_receive_commitments(signer, commitment->data, 32, aggregated_commitment);
    print_bytes(aggregated_commitment->data, 32);

    struct Signature * signature = malloc(sizeof(struct Signature));
    result += schnorr_musig_sign(signer, private_key, 32, message, 5, signature);
    print_bytes(signature->data, 32);

    struct AggregatedSignature * aggregated_signature = malloc(sizeof(struct AggregatedSignature));
    result += schnorr_musig_signature_shares(signer, signature->data, 32, aggregated_signature);
    print_bytes(aggregated_signature->data, 64);

    struct AggregatedPublicKey * aggregated_pubkey = malloc(sizeof(struct AggregatedPublicKey));
    result += schnorr_musig_aggregate_pubkeys(public_key, 32, aggregated_pubkey);
    print_bytes(aggregated_pubkey->data, 32);

    result += schnorr_musig_verify(message, 5, aggregated_pubkey->data, 32, aggregated_signature->data, 64);
    
    free(signer);
    free(precommitment);
    free(commitment);
    free(aggregated_commitment);
    free(signature);
    free(aggregated_signature);
    free(aggregated_pubkey);

    return result;
}

int test_multiple() {
    const size_t KEY_SIZE = 32;
    const size_t PARTICIPIANTS = 5;
    const size_t AGG_SIZE = KEY_SIZE * PARTICIPIANTS;
    const size_t TOTAL_SIZE = AGG_SIZE * sizeof(uint8_t);
    const size_t AGG_SIG_SIZE = AGG_SIG_ENCODING_LENGTH;
    const size_t AGG_SIG_TOTAL = AGG_SIG_SIZE * PARTICIPIANTS;

    uint32_t seed[] = { rand(), rand(), rand(), rand() };

    uint8_t private_keys[PARTICIPIANTS][KEY_SIZE] = {
        {1, 31, 91, 153, 8, 76, 92, 46, 45, 94, 99, 72, 142, 15, 113, 104, 213, 153, 165, 192, 31, 233, 254, 196, 201, 150, 5, 116, 61, 165, 232, 92},
        {5, 190, 250, 29, 197, 190, 184, 170, 116, 195, 72, 150, 111, 82, 84, 112, 43, 192, 169, 97, 62, 81, 158, 179, 239, 47, 232, 196, 68, 244, 13, 51},
        {3, 205, 137, 71, 169, 15, 115, 168, 117, 98, 53, 116, 248, 224, 227, 211, 198, 171, 216, 249, 54, 123, 165, 68, 51, 237, 2, 183, 166, 37, 51, 217},
        {2, 85, 108, 35, 44, 251, 108, 130, 116, 172, 126, 46, 85, 254, 31, 135, 182, 222, 225, 25, 191, 98, 163, 199, 132, 16, 45, 230, 194, 92, 37, 18},
        {1, 121, 16, 137, 181, 59, 238, 104, 33, 71, 236, 188, 94, 38, 50, 83, 41, 162, 28, 137, 74, 98, 5, 135, 108, 88, 121, 141, 28, 38, 138, 228}
    };

    uint8_t public_keys[PARTICIPIANTS][KEY_SIZE] = {
        {23, 156, 58, 89, 20, 125, 48, 49, 108, 136, 102, 40, 133, 35, 72, 201, 180, 42, 24, 184, 33, 8, 74, 201, 239, 121, 189, 115, 233, 185, 78, 141},
        {10, 244, 185, 164, 233, 226, 181, 164, 212, 208, 166, 210, 235, 154, 241, 154, 189, 157, 140, 95, 0, 155, 80, 243, 209, 95, 170, 126, 112, 100, 246, 159},
        {206, 175, 216, 203, 21, 161, 0, 231, 173, 13, 227, 215, 63, 125, 204, 232, 185, 227, 36, 60, 183, 219, 214, 78, 59, 11, 10, 121, 154, 147, 179, 136},
        {63, 6, 62, 235, 40, 185, 18, 160, 89, 252, 138, 140, 100, 33, 236, 89, 205, 45, 143, 42, 25, 64, 43, 9, 125, 120, 223, 138, 56, 100, 247, 15},
        {40, 107, 64, 71, 20, 219, 134, 117, 29, 146, 92, 118, 207, 119, 7, 9, 151, 228, 136, 101, 156, 74, 191, 116, 204, 114, 154, 55, 17, 188, 27, 164}
    };

    uint8_t message[] = { 'h', 'e', 'l', 'l', 'o' };

    uint8_t * all_pub_keys = malloc(TOTAL_SIZE);
    for (size_t i = 0; i < PARTICIPIANTS; ++i) {
        memcpy(all_pub_keys + i * KEY_SIZE, public_keys[i], KEY_SIZE * sizeof(uint8_t));
    }

    struct MusigSigner * signers[PARTICIPIANTS];
    for (size_t i = 0; i < PARTICIPIANTS; ++i) {
        signers[i] = schnorr_musig_new_signer(all_pub_keys, TOTAL_SIZE, i);
    }

    int result = 0;

    uint8_t * all_precommitments = malloc(TOTAL_SIZE);
    for (size_t i = 0; i < PARTICIPIANTS; ++i) {
        struct Precommitment * precommitment = malloc(sizeof(struct Precommitment));

        result += schnorr_musig_compute_precommitment(signers[i], seed, 4, precommitment);
        memcpy(all_precommitments + i * KEY_SIZE, precommitment->data, KEY_SIZE * sizeof(uint8_t));
        free(precommitment);
    }

    uint8_t * all_commitments = malloc(TOTAL_SIZE);
    for (size_t i = 0; i < PARTICIPIANTS; ++i) {
        struct Commitment * commitment = malloc(sizeof(struct Commitment));

        result += schnorr_musig_receive_precommitments(signers[i], all_precommitments, TOTAL_SIZE, commitment);
        memcpy(all_commitments + i * KEY_SIZE, commitment->data, KEY_SIZE * sizeof(uint8_t));
        free(commitment);
    }
    result += verify(all_commitments, TOTAL_SIZE, KEY_SIZE);

    uint8_t * aggregated_commitments = malloc(TOTAL_SIZE);
    for (size_t i = 0; i < PARTICIPIANTS; ++i) {
        struct AggregatedCommitment * aggregated_commitment = malloc(sizeof(struct AggregatedCommitment));
        
        result += schnorr_musig_receive_commitments(signers[i], all_commitments, TOTAL_SIZE, aggregated_commitment);
        memcpy(aggregated_commitments + i * KEY_SIZE, aggregated_commitment->data, KEY_SIZE * sizeof(uint8_t));
        free(aggregated_commitment);
    }
    result += verify(aggregated_commitments, TOTAL_SIZE, KEY_SIZE);

    uint8_t * signatures = malloc(TOTAL_SIZE);
    for (size_t i = 0; i < PARTICIPIANTS; ++i) {
        struct Signature * signature = malloc(sizeof(struct Signature));

        result += schnorr_musig_sign(signers[i], private_keys[i], KEY_SIZE, message, 5, signature);
        memcpy(signatures + i * KEY_SIZE, signature->data, KEY_SIZE * sizeof(uint8_t));
        free(signature);
    }

    uint8_t * agg_signatures = malloc(AGG_SIG_TOTAL);
    for (size_t i = 0; i < PARTICIPIANTS; ++i) {
        struct AggregatedSignature * aggregated_signature = malloc(sizeof(struct AggregatedSignature));
        
        result += schnorr_musig_signature_shares(signers[i], signatures, TOTAL_SIZE, aggregated_signature);
        memcpy(agg_signatures + i * AGG_SIG_SIZE, aggregated_signature->data, AGG_SIG_SIZE * sizeof(uint8_t));
        free(aggregated_signature);
    }
    result += verify(agg_signatures, AGG_SIG_TOTAL, AGG_SIG_SIZE);

    for (size_t i = 0; i < PARTICIPIANTS; ++i) {
        result += schnorr_musig_verify(message, 5, all_pub_keys, TOTAL_SIZE, agg_signatures, AGG_SIG_SIZE);
    }

    free(all_precommitments);
    free(all_commitments);
    free(aggregated_commitments);
    free(signatures);
    free(all_pub_keys);
    free(agg_signatures);

    for (size_t i = 0; i < PARTICIPIANTS; ++i) {
        free(signers[i]);
    }

    return result;
}

int verify(uint8_t * data, size_t size, size_t frame) {
    bool result = true;

    for (size_t i = 0; i < size / frame; ++i) {
        for (size_t j = 0; j < frame; ++j) {
            result = result && (data[j] == data[j + i]);
        }
    }

    return result;
}
