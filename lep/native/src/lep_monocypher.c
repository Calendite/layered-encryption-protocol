/*
 * Monocypher, compiled here rather than on its own so the Ed25519 public-key check below can use
 * its point decoder, which upstream keeps static. Upstream code is included unmodified.
 */
#include "monocypher.c"

#include "lep_native.h"

/* y of the two points of order 8, little-endian with the sign bit clear (RFC 8032 §5.1.3 encoding). */
static const uint8_t lep_order8_y1[32] = {
  0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f,
  0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a,
};
static const uint8_t lep_order8_y2[32] = {
  0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0,
  0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05,
};

static int lep_y_equals(const uint8_t pk[32], const uint8_t y[32])
{
  for (int i = 0; i < 31; i++) {
    if (pk[i] != y[i]) {
      return 0;
    }
  }
  return (pk[31] & 0x7f) == y[31];
}

int lep_ed25519_public_key_is_valid(const uint8_t pk[32])
{
  /* y must be canonical and not p - 1: bytes 1..30 all 0xff, top byte 0x7f, low byte >= 0xec. */
  int upper_is_p = (pk[31] & 0x7f) == 0x7f;
  int middle_zero = (pk[31] & 0x7f) == 0;
  for (int i = 1; i < 31; i++) {
    upper_is_p &= pk[i] == 0xff;
    middle_zero &= pk[i] == 0x00;
  }
  if (upper_is_p && pk[0] >= 0xec) {
    return -1;
  }
  /* y = 0 and y = 1 (whatever the sign bit). */
  if (middle_zero && pk[0] <= 1) {
    return -1;
  }
  if (lep_y_equals(pk, lep_order8_y1) || lep_y_equals(pk, lep_order8_y2)) {
    return -1;
  }
  /* On the curve: x^2 = (y^2 - 1) / (d y^2 + 1) has a root. */
  ge point;
  return ge_frombytes_neg_vartime(&point, pk) == 0 ? 0 : -1;
}
