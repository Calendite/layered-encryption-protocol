# Bouncy Castle parity vectors

`bouncycastle-parity.txt` records what `BouncyCastleCryptoProvider` does on about 2,000 inputs,
across every `CryptoProvider` primitive and the constructions built on them (X-Wing, the cascade,
hybrid signatures). Any other provider is held to it byte for byte.

Each case records:

- **the inputs**: lengths across block and rate boundaries, large inputs, malformed keys,
  tampered ciphertexts and signatures, low-order and non-canonical curve points;
- **every randomness request** the operation made, in order and with its size;
- **the result**: the exact output bytes, true or false, or which kind of exception
  (`CryptoException`, a fail-closed rejection, or any other, bad input).

A provider passes only if, replaying the recorded randomness, it asks for the same draws in the
same sizes and order, and produces the same result. The format is documented in
lep/src/commonTest/.../parity/ParityVectors.kt.

## Tests

- `BouncyCastleParityVectorsTest` (jvmTest):
  - the file is exactly what the current Bouncy Castle generates;
  - Bouncy Castle replays it with no differences;
  - controls: a one-byte change to a result, and a provider drawing randomness in other sizes, are
    both reported.
- `AppleProviderParityTest` (macosArm64Test): `AppleCryptoProvider` replays it, with a tamper
  control of its own.

## Deliberate differences

`AppleProviderParityTest` holds the macOS provider to a different result in exactly two places.
Both are inputs LEP never produces, where it is stricter than Bouncy Castle. Each is pinned to the
number of cases it covers:

- **AES-GCM nonces of 1-11 bytes**: Bouncy Castle accepts them; CryptoKit only takes 12 or more.
  The cascade, LEP's only AES-GCM caller, always uses 12.
- **ML-DSA-65 private keys that are not 4032 bytes**: Bouncy Castle pads or truncates them and
  signs anyway; the macOS provider refuses.

## Regenerating

Regenerate after adding cases or upgrading Bouncy Castle:

    ./gradlew :lep:jvmTest -Plep.parity.regenerate --tests '*BouncyCastleParityVectorsTest*'

Then rerun every provider's parity test. Never edit the file by hand: the JVM test fails on any
difference from what Bouncy Castle generates.
