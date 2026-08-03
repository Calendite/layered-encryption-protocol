# Layered Encryption Protocol

A Kotlin Multiplatform library for **end-to-end encrypted sync between a small number of devices
that trust each other and nothing else** — no accounts, no server that can read anything, and no
assumption that the network, the relay, or a future quantum computer is on your side.

It provides the parts that are hard to get right and easy to get subtly wrong: a two-cipher
cascade for data, a hybrid post-quantum key agreement, an in-person pairing ceremony with
short-authentication-string verification, asynchronous invites for when both people cannot be
present, an append-only signed membership log, and a sealed envelope format for the data itself.

It deliberately does **not** provide transport, storage, or any opinion about what your data
means. You hand it bytes; it hands back sealed bytes, and vice versa.

```
                    ┌──────────────────────────────────────────┐
your app ──bytes──▶ │  seal   ChaCha20-Poly1305 → AES-256-GCM   │ ──▶ sealed envelope
                    │  keys   X25519 + ML-KEM-768 (X-Wing)      │
your app ◀─bytes─── │  trust  SAS pairing, signed member log    │ ◀── sealed envelope
                    └──────────────────────────────────────────┘
```

## Why it looks like this

**Two ciphers, not one.** Data is encrypted with ChaCha20-Poly1305 and then again with
AES-256-GCM, under independent keys derived from separate HKDF labels. Reading it requires
breaking both. Cascades are unusual in messaging protocols and normal in disk encryption
(VeraCrypt, TripleSec); the cost is a few microseconds per op, and the benefit is that a single
cipher break is not a data break.

**Hybrid key agreement, because "later" is a threat model.** Key agreement is
[X-Wing](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/), the IETF hybrid of
X25519 and ML-KEM-768. Traffic recorded today and kept until a quantum computer exists is the
present-day threat — *harvest now, decrypt later* — and the lattice leg is what defeats it. The
classical leg is what protects you if ML-KEM turns out to have an implementation bug: an attacker
needs to break **both**. A hand-rolled combiner would not give that property, which is why this
uses the specified one, pinned to its IETF test vectors.

**Trust is established by humans, once.** Pairing derives a shared secret and shows both people
the same short authentication string; keys are only released after both confirm. There is no
directory, no key server, and nothing to impersonate. Asynchronous invites use a pre-published
signed bundle pinned by a fingerprint carried in the invite link, so a relay that swaps the bundle
is caught.

**Membership is a signed, hash-chained log.** Devices are added and revoked by entries signed by
an existing member, verified as a chain before any change is honoured. A compromised relay cannot
inject "and now this device is also a member".

**Signatures are Ed25519, deliberately, for now.** Signature forgery needs a *live* quantum
computer and cannot be done retroactively from recorded traffic, so it is a materially less urgent
threat than encryption. ML-DSA dual-signing is a tracked upgrade rather than a shipped feature.

## Using it

```kotlin
val provider = platformCryptoProvider()          // Bouncy Castle on JVM/Android

// Encrypt something. The library neither knows nor cares what these bytes mean.
val sealed = Cascade.seal(provider, masterKey, plaintext = myBytes, aad = context)
val opened = Cascade.open(provider, masterKey, sealed, aad = context)

// Or use the envelope, which binds a header (calendar, lane, sequence) into the ciphertext so a
// relay cannot re-label a message without decryption failing.
val envelope = LaneEnvelope.seal(provider, masterKey, calendarId, lane, seq, plaintext = myBytes)
val bytes = envelope.open(provider, masterKey)   // throws on tamper; never returns unverified data
```

Pairing, over any channel that can send and receive byte frames:

```kotlin
// One device hosts, the other joins. Both humans compare the same six-word string and confirm.
val result = PairingFerry.host(channel, inviter, confirmSas = { sas -> ui.askUser(sas) })
val result = PairingFerry.join(channel, joiner, confirmSas = { sas -> ui.askUser(sas) })
```

Implement `FrameChannel` over whatever you have — a socket, a WebSocket, a relay, a Bluetooth
link. The library provides the length codec (`intToBytes` / `bytesToInt`) so your framing agrees
with its own.

## What you have to bring

- **Transport.** The library never opens a socket.
- **Storage.** It never writes a file. Keys are passed in as `ByteArray`; where you keep them
  (hardware keystore, Secure Enclave, a file you should not use) is your decision.
- **Meaning.** It has no idea what your plaintext is, and this is on purpose: a library that
  knows about your domain cannot be reasoned about independently of it.

## Platforms

| Target | Status |
| --- | --- |
| JVM | Full (Bouncy Castle) |
| Android | Full (Bouncy Castle) |
| iOS | Declared, not implemented — CryptoKit binding is future work |
| wasmJs | Declared, not implemented — WebCrypto + libsodium.js is future work |

The JVM and Android targets share one implementation, so the whole protocol suite runs on a
laptop without a device or an emulator.

## Building and testing

```
./gradlew :lep:jvmTest      # the protocol suite: primitives, KATs, ceremonies
./gradlew :lep:assemble     # all targets
```

The suite includes ML-KEM-768 known-answer tests and X-Wing vectors, plus full pairing and
async-invite ceremonies run end to end over an in-memory channel.

## Consuming it

Published as `org.layeredencryption:lep`. While the API is settling, a Gradle composite build
avoids publishing anything at all:

```kotlin
// settings.gradle.kts
includeBuild("../layered-encryption-protocol")
```

The consumer then declares the ordinary coordinates and Gradle substitutes the local build.
Switching to a published artifact later means deleting that one line.

## Status and honesty

This is **version 0.1.0** and the API will move. It has not been independently audited. It is
extracted from a working application (a shared calendar), which means every part of it is
exercised by something real, and also that its shape reflects that application's needs; if
something here looks oddly specific, that is why.

The threat model, the reasoning behind each choice, and the known gaps are written up in
`docs/Protocol.md`.
