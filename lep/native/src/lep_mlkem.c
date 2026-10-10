/*
 * ML-KEM-768 and FIPS 202 for the Kotlin/Native provider: mlkem-native built as a single
 * compilation unit, deterministic API only (randomness is the caller's), every upstream symbol
 * static so only the lep_ wrappers below leave this file.
 */
#define MLK_CONFIG_PARAMETER_SET 768
#define MLK_CONFIG_NAMESPACE_PREFIX lep_mlkem
#define MLK_CONFIG_NO_RANDOMIZED_API
#define MLK_CONFIG_INTERNAL_API_QUALIFIER static
#define MLK_CONFIG_EXTERNAL_API_QUALIFIER static

#include "mlkem_native.c"

#include "lep_native.h"

int lep_sha3_256(uint8_t out[32], const uint8_t *in, size_t inlen)
{
  lep_mlkem_sha3_256(out, in, inlen);
  return 0;
}

int lep_shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen)
{
  lep_mlkem_shake256(out, outlen, in, inlen);
  return 0;
}

int lep_mlkem768_keypair_derand(uint8_t pk[LEP_MLKEM768_PUBLICKEYBYTES],
                                uint8_t sk[LEP_MLKEM768_SECRETKEYBYTES],
                                const uint8_t coins[64])
{
  return lep_mlkem_keypair_derand(pk, sk, coins);
}

int lep_mlkem768_check_pk(const uint8_t pk[LEP_MLKEM768_PUBLICKEYBYTES])
{
  return lep_mlkem_check_pk(pk);
}

int lep_mlkem768_enc_derand(uint8_t ct[LEP_MLKEM768_CIPHERTEXTBYTES], uint8_t ss[32],
                            const uint8_t pk[LEP_MLKEM768_PUBLICKEYBYTES],
                            const uint8_t coins[32])
{
  return lep_mlkem_enc_derand(ct, ss, pk, coins);
}

int lep_mlkem768_dec(uint8_t ss[32], const uint8_t ct[LEP_MLKEM768_CIPHERTEXTBYTES],
                     const uint8_t sk[LEP_MLKEM768_SECRETKEYBYTES])
{
  return lep_mlkem_dec(ss, ct, sk);
}
