/*
 * Ed25519 (RFC 8032, SHA-512) for the Kotlin/Native provider, from Monocypher's optional
 * monocypher-ed25519. CryptoKit is not used here because its Ed25519 signatures are randomised,
 * and the protocol relies on deterministic RFC 8032 signatures matching Bouncy Castle's.
 */
#include "monocypher.h"
#include "optional/monocypher-ed25519.h"

#include "lep_native.h"

/* Monocypher's secret key is seed || public key, and key_pair wipes the seed it is given. */
static void lep_ed25519_expand(uint8_t secret[64], uint8_t pk[32], const uint8_t seed[32])
{
  uint8_t copy[32];
  for (int i = 0; i < 32; i++) {
    copy[i] = seed[i];
  }
  crypto_ed25519_key_pair(secret, pk, copy);
}

int lep_ed25519_public_key(uint8_t pk[32], const uint8_t seed[32])
{
  uint8_t secret[64];
  lep_ed25519_expand(secret, pk, seed);
  crypto_wipe(secret, sizeof secret);
  return 0;
}

int lep_ed25519_sign(uint8_t sig[64], const uint8_t seed[32], const uint8_t *m, size_t mlen)
{
  uint8_t secret[64];
  uint8_t pk[32];
  lep_ed25519_expand(secret, pk, seed);
  crypto_ed25519_sign(sig, secret, m, mlen);
  crypto_wipe(secret, sizeof secret);
  return 0;
}

int lep_ed25519_verify(const uint8_t sig[64], const uint8_t pk[32], const uint8_t *m, size_t mlen)
{
  return crypto_ed25519_check(sig, pk, m, mlen);
}
