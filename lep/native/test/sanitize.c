/*
 * Drives every lep_ C function under AddressSanitizer and UndefinedBehaviorSanitizer
 * (lep/native/test/sanitize.sh). Correctness is the parity test's job; this one only looks for
 * memory errors and undefined behaviour, over every input shape the Kotlin side can send:
 * zero-length messages, every length up to a few blocks, random and corrupted keys,
 * ciphertexts and signatures.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lep_native.h"

static void fill(uint8_t *p, size_t n) { arc4random_buf(p, n); }

/* Heap copies sized exactly, so ASan sees any read one byte past the end. */
static uint8_t *exact(size_t n)
{
  uint8_t *p = malloc(n ? n : 1);
  fill(p, n);
  return p;
}

int main(void)
{
  uint8_t out[3000];
  for (size_t n = 0; n <= 1100; n += (n < 300 ? 1 : 97)) {
    uint8_t *m = exact(n);
    lep_sha3_256(out, m, n);
    lep_shake256(out, n % 3000, m, n);
    free(m);
  }

  for (int round = 0; round < 40; round++) {
    uint8_t coins[64], m32[32];
    fill(coins, 64);
    fill(m32, 32);
    uint8_t *pk = exact(LEP_MLKEM768_PUBLICKEYBYTES), *sk = exact(LEP_MLKEM768_SECRETKEYBYTES);
    uint8_t *ct = exact(LEP_MLKEM768_CIPHERTEXTBYTES), ss[32], ss2[32];
    if (lep_mlkem768_keypair_derand(pk, sk, coins) != 0) return 1;
    if (lep_mlkem768_check_pk(pk) != 0) return 2;
    if (lep_mlkem768_enc_derand(ct, ss, pk, m32) != 0) return 3;
    if (lep_mlkem768_dec(ss2, ct, sk) != 0 || memcmp(ss, ss2, 32) != 0) return 4;
    ct[round % LEP_MLKEM768_CIPHERTEXTBYTES] ^= 1;
    (void)lep_mlkem768_dec(ss2, ct, sk);
    sk[(round * 61) % LEP_MLKEM768_SECRETKEYBYTES] ^= 0x80;
    (void)lep_mlkem768_dec(ss2, ct, sk);
    fill(pk, LEP_MLKEM768_PUBLICKEYBYTES);
    (void)lep_mlkem768_check_pk(pk);
    (void)lep_mlkem768_enc_derand(ct, ss, pk, m32);
    free(pk); free(sk); free(ct);
  }

  for (int round = 0; round < 12; round++) {
    uint8_t seed[32], rnd[32] = {0};
    fill(seed, 32);
    uint8_t *pk = exact(LEP_MLDSA65_PUBLICKEYBYTES), *sk = exact(LEP_MLDSA65_SECRETKEYBYTES);
    uint8_t *sig = exact(LEP_MLDSA65_BYTES);
    if (lep_mldsa65_keypair_derand(pk, sk, seed) != 0) return 5;
    size_t n = (size_t)round * 37;
    uint8_t *m = exact(n);
    if (lep_mldsa65_sign_derand(sig, m, n, rnd, sk) != 0) return 6;
    if (lep_mldsa65_verify(sig, m, n, pk) != 0) return 7;
    sig[(round * 271) % LEP_MLDSA65_BYTES] ^= 1;
    if (lep_mldsa65_verify(sig, m, n, pk) == 0) return 8;
    fill(sig, LEP_MLDSA65_BYTES);
    (void)lep_mldsa65_verify(sig, m, n, pk);
    sk[(round * 331) % LEP_MLDSA65_SECRETKEYBYTES] ^= 0xff;
    (void)lep_mldsa65_sign_derand(sig, m, n, rnd, sk);
    free(pk); free(sk); free(sig); free(m);
  }

  for (size_t n = 0; n <= 300; n++) {
    uint8_t seed[32], pk[32], sig[64];
    fill(seed, 32);
    uint8_t *m = exact(n);
    lep_ed25519_public_key(pk, seed);
    lep_ed25519_sign(sig, seed, m, n);
    if (lep_ed25519_public_key_is_valid(pk) != 0) return 9;
    if (lep_ed25519_verify(sig, pk, m, n) != 0) return 10;
    sig[n % 64] ^= 1;
    if (lep_ed25519_verify(sig, pk, m, n) == 0) return 11;
    fill(pk, 32);
    (void)lep_ed25519_public_key_is_valid(pk);
    (void)lep_ed25519_verify(sig, pk, m, n);
    free(m);
  }

  puts("sanitize: every lep_ function exercised, no sanitizer reports");
  return 0;
}
