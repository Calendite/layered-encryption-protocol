# lep/native: the macOS CryptoProvider's native half

`AppleCryptoProvider` (lep/src/macosMain) is the provider for Calendite's background daemons on
the Mac, which run as Kotlin/Native. It must be indistinguishable from `BouncyCastleCryptoProvider`
byte for byte: a daemon reads keys the Mac app wrote on the JVM, and talks to phones running
Bouncy Castle. This directory holds the native code it binds, none of it cryptography written here.

## Where each primitive comes from, and why

| Primitive | Source | Why not CryptoKit |
|---|---|---|
| SHA-256, HMAC-SHA256, randomness | CommonCrypto, Security (called from Kotlin) | (system code either way) |
| HKDF-SHA256 | RFC 5869 in Kotlin over CommonCrypto's HMAC | CryptoKit's HKDF stops the process on some bad sizes |
| ChaCha20-Poly1305, AES-GCM, X25519 | CryptoKit, through `swift/LepCryptoKit.swift` | (it is CryptoKit) |
| SHA3-256, SHAKE256 | mlkem-native's Keccak | CryptoKit has no SHAKE |
| ML-KEM-768 | mlkem-native | CryptoKit loads private keys only from their 64-byte seed; every device stores the 2400-byte FIPS 203 encoding |
| ML-DSA-65 | mldsa-native | Same, for the 4032-byte FIPS 204 encoding |
| Ed25519 | Monocypher (`optional/monocypher-ed25519`) | CryptoKit's Ed25519 signatures are randomised; RFC 8032 and Bouncy Castle are deterministic |

The C never draws randomness. Kotlin draws it in the same calls and sizes Bouncy Castle does and
passes it in, which is what lets recorded vectors be replayed exactly.

## Vendored code

Copied unmodified from upstream release tags. Only what the build uses is kept, plus each licence.

| Library | Upstream | Tag | Commit | Licence |
|---|---|---|---|---|
| mlkem-native | github.com/pq-code-package/mlkem-native (`mlkem/`) | v2.0.0 | d1b2fe782888bdb761a50336012923180be7f502 | Apache-2.0 OR ISC OR MIT |
| mldsa-native | github.com/pq-code-package/mldsa-native (`mldsa/`) | v2.0.0 | 834a90d5e846ffa1e1611bd24e160bb2e9b86d35 | Apache-2.0 OR ISC OR MIT |
| Monocypher | github.com/LoupVaillant/Monocypher (`src/`) | 4.0.3 | ab2b16dd619ad5f6979a4fbe69cfa324a6fcc35f | CC0-1.0 OR BSD-2-Clause |

mlkem-native and mldsa-native are PQ Code Package (Linux Foundation) projects; parts of both carry
CBMC and HOL-Light proofs. Monocypher was audited by Cure53.

To check a copy is unmodified: clone the upstream tag and `diff -r` the directory named above
against `third_party/<library>`.

To update: replace the directory from the new tag, update the table, run `test/sanitize.sh`, then
`./gradlew :lep:macosArm64Test`. The parity vectors decide whether the update changed anything.

## Layout

- `include/lep_native.h`: the C API Kotlin binds. Fixed-size, uniform, `lep_` prefixed.
- `include/lep_cryptokit.h`: the C declarations of the Swift wrappers.
- `src/lep_mlkem.c`, `src/lep_mldsa.c`: each library as a single compilation unit, deterministic
  API only, internals made static, behind small wrappers.
- `src/lep_ed25519.c`, `src/lep_monocypher.c`: Ed25519 signing, and Monocypher compiled with a
  public-key check matching Bouncy Castle's (`Ed25519.validatePublicKeyPartial`).
- `swift/LepCryptoKit.swift`: the AEADs and X25519, exposed with `@_cdecl`.
- `build.sh`: builds both static libraries. Gradle runs it before cinterop
  (`:lep:buildLepNativeMacosArm64`). It needs only the Command Line Tools.
- `test/sanitize.sh`: every C function under AddressSanitizer and UBSan.

## Build notes

- Everything is partially linked (`ld -r`) into one object exporting only the functions in
  `lep_native.h`. Monocypher's `crypto_*` names would otherwise collide with libsodium's in
  whatever links this.
- The Swift library targets macOS 12 (the Mac app's minimum) with
  `-runtime-compatibility-version none`. Below macOS 14, swiftc otherwise asks the linker for the
  toolchain's back-deployment archives, which Kotlin/Native's link does not search. The code uses
  no parameter packs, and the Swift 5.6 fixes only concern runtimes older than macOS 12.3.
- cinterop runs with `ignoreXcodeVersionCheck=true`: it calls `xcodebuild -version` only to check
  the version, and the Command Line Tools have everything else it uses.
- cinterop copies the static libraries into its klib without counting them as inputs, so
  lep/build.gradle.kts adds them. Without that, a rebuilt library is silently linked as the old one.
