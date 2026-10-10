/*
 * ML-DSA-65 for the Kotlin/Native provider: mldsa-native built as a single compilation unit,
 * deterministic API only (randomness is the caller's), every upstream symbol static so only the
 * lep_ wrappers below leave this file.
 */
#define MLD_CONFIG_PARAMETER_SET 65
#define MLD_CONFIG_NAMESPACE_PREFIX lep_mldsa
#define MLD_CONFIG_NO_RANDOMIZED_API
#define MLD_CONFIG_INTERNAL_API_QUALIFIER static
#define MLD_CONFIG_EXTERNAL_API_QUALIFIER static

#include "mldsa_native.c"

#include "lep_native.h"

/*
 * Pure (non-pre-hash) ML-DSA with an empty context: FIPS 204 Algorithm 2 prefixes the message
 * with 0x00 (pure) and the context length (0), which is what signature_internal takes as `pre`.
 */
static const uint8_t lep_mldsa_pure_empty_context[2] = {0x00, 0x00};

int lep_mldsa65_keypair_derand(uint8_t pk[LEP_MLDSA65_PUBLICKEYBYTES],
                               uint8_t sk[LEP_MLDSA65_SECRETKEYBYTES],
                               const uint8_t seed[32])
{
  return lep_mldsa_keypair_internal(pk, sk, seed);
}

int lep_mldsa65_sign_derand(uint8_t sig[LEP_MLDSA65_BYTES], const uint8_t *m, size_t mlen,
                            const uint8_t rnd[32],
                            const uint8_t sk[LEP_MLDSA65_SECRETKEYBYTES])
{
  return lep_mldsa_signature_internal(sig, m, mlen, lep_mldsa_pure_empty_context,
                                      sizeof lep_mldsa_pure_empty_context, rnd, sk, 0);
}

int lep_mldsa65_verify(const uint8_t sig[LEP_MLDSA65_BYTES], const uint8_t *m, size_t mlen,
                       const uint8_t pk[LEP_MLDSA65_PUBLICKEYBYTES])
{
  return lep_mldsa_verify(sig, m, mlen, NULL, 0, pk);
}
