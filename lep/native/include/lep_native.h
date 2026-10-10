/*
 * The C surface the Kotlin/Native CryptoProvider binds to (macosMain, AppleCryptoProvider).
 *
 * Every function here is a thin wrapper over vendored, unmodified upstream code (see
 * lep/native/README.md); no cryptography is written in this directory. The wrappers exist so
 * the Kotlin side sees one small, uniform, fixed-size API instead of three libraries' worth of
 * configuration macros, and so the libraries' own symbols stay private to their compilation units.
 *
 * Conventions: every function returns 0 on success and non-zero on failure, and never reads
 * randomness of its own. Anything random is drawn by the Kotlin caller and passed in, in the
 * same order and amount Bouncy Castle draws it, which is what lets a seeded run reproduce the
 * JVM provider byte for byte.
 */
#ifndef LEP_NATIVE_H
#define LEP_NATIVE_H

#include <stddef.h>
#include <stdint.h>

#define LEP_MLKEM768_PUBLICKEYBYTES 1184
#define LEP_MLKEM768_SECRETKEYBYTES 2400
#define LEP_MLKEM768_CIPHERTEXTBYTES 1088
#define LEP_MLDSA65_PUBLICKEYBYTES 1952
#define LEP_MLDSA65_SECRETKEYBYTES 4032
#define LEP_MLDSA65_BYTES 3309

/* ── FIPS 202 (mlkem-native's Keccak) ─────────────────────────────────────────────────────── */

int lep_sha3_256(uint8_t out[32], const uint8_t *in, size_t inlen);
int lep_shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);

/* ── ML-KEM-768, FIPS 203 (mlkem-native) ──────────────────────────────────────────────────── */

/* KeyGen_internal(d, z): coins = d || z. */
int lep_mlkem768_keypair_derand(uint8_t pk[LEP_MLKEM768_PUBLICKEYBYTES],
                                uint8_t sk[LEP_MLKEM768_SECRETKEYBYTES],
                                const uint8_t coins[64]);
/* FIPS 203 §7.2 modulus check: 0 if ek is a valid encapsulation key. */
int lep_mlkem768_check_pk(const uint8_t pk[LEP_MLKEM768_PUBLICKEYBYTES]);
/* Encaps_internal(ek, m): coins = m. Fails if ek fails the FIPS 203 §7.2 modulus check. */
int lep_mlkem768_enc_derand(uint8_t ct[LEP_MLKEM768_CIPHERTEXTBYTES], uint8_t ss[32],
                            const uint8_t pk[LEP_MLKEM768_PUBLICKEYBYTES],
                            const uint8_t coins[32]);
/* Decaps with implicit rejection. Fails if dk fails the FIPS 203 §7.3 hash check. */
int lep_mlkem768_dec(uint8_t ss[32], const uint8_t ct[LEP_MLKEM768_CIPHERTEXTBYTES],
                     const uint8_t sk[LEP_MLKEM768_SECRETKEYBYTES]);

/* ── ML-DSA-65, FIPS 204 (mldsa-native) ───────────────────────────────────────────────────── */

/* KeyGen_internal(xi). */
int lep_mldsa65_keypair_derand(uint8_t pk[LEP_MLDSA65_PUBLICKEYBYTES],
                               uint8_t sk[LEP_MLDSA65_SECRETKEYBYTES],
                               const uint8_t seed[32]);
/* Pure ML-DSA.Sign with an empty context, randomness rnd (all zero = the deterministic variant). */
int lep_mldsa65_sign_derand(uint8_t sig[LEP_MLDSA65_BYTES], const uint8_t *m, size_t mlen,
                            const uint8_t rnd[32],
                            const uint8_t sk[LEP_MLDSA65_SECRETKEYBYTES]);
/* Pure ML-DSA.Verify with an empty context. 0 = valid. */
int lep_mldsa65_verify(const uint8_t sig[LEP_MLDSA65_BYTES], const uint8_t *m, size_t mlen,
                       const uint8_t pk[LEP_MLDSA65_PUBLICKEYBYTES]);

/* ── Ed25519, RFC 8032 (Monocypher's SHA-512 variant) ─────────────────────────────────────── */

/* The private key is the 32-byte RFC 8032 seed, as Bouncy Castle encodes it. */
int lep_ed25519_public_key(uint8_t pk[32], const uint8_t seed[32]);
int lep_ed25519_sign(uint8_t sig[64], const uint8_t seed[32], const uint8_t *m, size_t mlen);
/* 0 = valid. */
int lep_ed25519_verify(const uint8_t sig[64], const uint8_t pk[32], const uint8_t *m, size_t mlen);
/*
 * 0 if pk is a public key Bouncy Castle accepts (Ed25519.validatePublicKeyPartial): y canonical
 * and not 0, 1, p - 1 or an order-8 y, and the point on the curve. Bouncy Castle refuses to build
 * any other key, so verification against one throws rather than returning false.
 */
int lep_ed25519_public_key_is_valid(const uint8_t pk[32]);

#endif /* LEP_NATIVE_H */
