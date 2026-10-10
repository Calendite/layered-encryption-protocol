/*
 * C declarations of the CryptoKit wrappers in lep/native/swift/LepCryptoKit.swift, for cinterop.
 *
 * Every function returns LEP_CK_OK on success, LEP_CK_AUTH_FAILED when an AEAD tag does not
 * verify, and LEP_CK_FAILED for anything else CryptoKit refuses. Sealed outputs are
 * ciphertext || 16-byte tag. Pointers may be NULL when their length is 0.
 */
#ifndef LEP_CRYPTOKIT_H
#define LEP_CRYPTOKIT_H

#include <stddef.h>
#include <stdint.h>

#define LEP_CK_OK 0
#define LEP_CK_FAILED 1
#define LEP_CK_AUTH_FAILED 2

int32_t lep_ck_aes_gcm_seal(const uint8_t *key, long keyLength, const uint8_t *nonce, long nonceLength,
                            const uint8_t *plaintext, long plaintextLength, const uint8_t *aad, long aadLength,
                            uint8_t *out);
int32_t lep_ck_aes_gcm_open(const uint8_t *key, long keyLength, const uint8_t *nonce, long nonceLength,
                            const uint8_t *sealed, long sealedLength, const uint8_t *aad, long aadLength,
                            uint8_t *out);
int32_t lep_ck_chachapoly_seal(const uint8_t *key, long keyLength, const uint8_t *nonce, long nonceLength,
                               const uint8_t *plaintext, long plaintextLength, const uint8_t *aad, long aadLength,
                               uint8_t *out);
int32_t lep_ck_chachapoly_open(const uint8_t *key, long keyLength, const uint8_t *nonce, long nonceLength,
                               const uint8_t *sealed, long sealedLength, const uint8_t *aad, long aadLength,
                               uint8_t *out);
int32_t lep_ck_x25519_public_key(const uint8_t privateKey[32], uint8_t out[32]);
int32_t lep_ck_x25519(const uint8_t privateKey[32], const uint8_t peerPublicKey[32], uint8_t out[32]);

#endif /* LEP_CRYPTOKIT_H */
