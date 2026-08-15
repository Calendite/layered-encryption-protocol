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
your app ──bytes──▶ │  seal   ChaCha20-Poly1305 → AES-256-GCM  │ ──▶ sealed envelope
                    │  keys   X25519 + ML-KEM-768 (X-Wing)     │
your app ◀─bytes─── │  sign   Ed25519 + ML-DSA-65 (both must)  │ ◀── sealed envelope
                    │  trust  SAS pairing, signed member log   │
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
inject "and now this device is also a member". When two devices change membership at once, forks
resolve by **removal precedence** — a branch that revokes a device beats a longer branch that
does not, and the revoked set from both branches is always honoured — so a member cannot escape
its own revocation by padding a competing branch.

**Signatures are hybrid too, so nothing here is classical-only.** Every signature is Ed25519 and
ML-DSA-65 over the same message, and **both** must verify or the signature is rejected. Note that
this is the mirror image of the key agreement rather than more of the same. For the KEM an attacker
must break *both* legs to read traffic; for signatures an attacker must forge *both* legs to
impersonate a device. There is no combiner because signatures do not need one: verifying each leg
independently and requiring both already yields the stronger of the two.

Be clear about what that buys, because the two threats are easy to conflate. Breaking Ed25519 in
2035 would not decrypt traffic recorded in 2026 — that is *harvest now, decrypt later*, and X-Wing
already handles it. What it would allow is forging a device identity and impersonating a member
from that point on. ML-DSA-65 closes exactly that gap. It is NIST category 3, matching ML-KEM-768,
so neither side of the protocol is the weak one.

Signatures appear only where a third party must verify something *without* holding the shared key:
a device identity, a membership log entry, an async invite bundle, and the LAN session challenge.
Messages are not signed. Once two devices share a key the AEAD tags already prove a message came
from a holder of that key, symmetrically and so without a quantum weakness of their own; signing
each one would add 3.3 KB and no assurance.

The cost is size, and it is not small: identities go from about 140 bytes to 1984 + 3373, and each
membership entry grows by 3373. Nothing in the protocol was size-constrained enough to care — the
pairing QR carries only a short code, and frames are capped at 16 MB — but a consumer storing
identities should expect kilobytes, not bytes.

## Using it

```kotlin
val provider = platformCryptoProvider()          // Bouncy Castle on JVM/Android

// Encrypt something. The library neither knows nor cares what these bytes mean.
val sealed = Cascade.seal(provider, masterKey, plaintext = myBytes, aad = context)
val opened = Cascade.open(provider, masterKey, sealed, aad = context)

// Or use the envelope, which binds a header (context, lane, sequence, epoch) into the ciphertext
// so a relay cannot re-label a message without decryption failing. Envelopes take the context's
// EpochKeys — every key the context has had — so old epochs stay readable after rotations.
// Opening validates freshness against a FreshnessStore, so a replayed or regressed envelope
// throws instead of being delivered twice. (Re-reading your own trusted local storage is the one
// job of the explicitly named `openWithoutReplayProtection`.)
val keys = EpochKeys.founding(masterKey)
val freshness = InMemoryFreshnessStore()         // production JVM/Android: FileBackedFreshnessStore
val envelope = LaneEnvelope.seal(provider, keys, contextId, lane, seq, plaintext = myBytes)
val bytes = envelope.openAndValidate(provider, keys, contextId, lane, freshness)
```

Pairing, over any channel that can send and receive byte frames:

```kotlin
// One device invites, the other joins. Both humans compare the same six-digit string and
// confirm; the ferry releases the master key only after both confirmations.
val masterKey = PairingFerry.runInviter(channel, inviter, confirmSas = { sas -> ui.askUser(sas) })
val masterKey = PairingFerry.runJoiner(channel, joiner, confirmSas = { sas -> ui.askUser(sas) })
```

`PairingFerry` is the safe facade, and using it is the recommended path: it drives the ceremony in
order and gates key release on both humans. If you drive the low-level `Inviter`/`Joiner` sessions
directly instead, they enforce the same order themselves — every step checks its prerequisite, and
`complete()`/`onInviterComplete()` require the `SasConfirmation` token that `confirmSas()` issues
only after the SAS has been verified, so the human gate cannot be skipped.

Implement `FrameChannel` over whatever you have — a socket, a WebSocket, a relay, a Bluetooth
link. The library provides the length codec (`intToBytes` / `bytesToInt`) so your framing agrees
with its own.

## Namespacing: do this before you ship

Every HKDF label, signature domain, and signed-transcript prefix is built from a vendor token,
and the default is `calendite`, the application this was extracted from. Pass your own —
**everywhere**, starting with identity generation:

```kotlin
val namespace = ProtocolNamespace("mycoolapp")   // labels become mycoolapp/v1/...

val device = DeviceKeys.generate(provider, namespace)          // identity binding
val inviter = Inviter(provider, device, code, namespace = namespace)   // live pairing
val invite = AsyncInviter.create(provider, device, now, expiry, namespace = namespace)
val log = MembershipLog.found(provider, device.identity, device.signingKeyPair, namespace = namespace)
Cascade.seal(provider, key, plaintext, aad, namespace)         // data
```

This is not cosmetic, and it is all-or-nothing: the namespace domain-separates *every* artifact —
identity bindings, membership signatures and hash chains, pairing and invite transcripts, and the
data cascade — so an identity generated under one namespace does not verify under another, one
app's membership log is `InvalidBranch` to another, and cross-namespace ceremonies fail closed at
the first MAC. Mixing namespaces between calls is therefore a correctness bug that verification
will catch, not a silent compatibility mode. The default exists only so that devices already
paired in the field keep working; a test pins every shipped label byte for byte, because changing
one character silently orphans every existing pairing.

## What you have to bring

- **Transport.** The library never opens a socket.
- **Storage.** Keys are passed in as `ByteArray`; where you keep them (hardware keystore,
  Secure Enclave, a file you should not use) is your decision. The one exception is opt-in:
  the sealed-file invite and freshness stores (`org.layeredencryption.storage`, JVM/Android)
  write exactly the files you point them at, under a key you supply.
- **Meaning.** It has no idea what your plaintext is, and this is on purpose: a library that
  knows about your domain cannot be reasoned about independently of it.

## Key retention and post-compromise security

History stays readable by design, and that sentence is a security decision, so here is its
fine print:

- **Every device retains every epoch key it ever received**, indefinitely, unless the
  application prunes. Rotation (a revocation, a `ROTATE` entry, a fork resolution) starts a
  new epoch; the old keys stay so the shared history they sealed stays readable.
- **Who receives history:** a synchronously-paired device gets the full set — both sides are
  the same person. A member added later starts at their join epoch: rotations wrap exactly
  one key, and pre-join envelopes are permanently unreadable to them. An async invite founds
  a fresh context, so there is no earlier history to hand over at all.
- **Forward secrecy is deliberately absent within the retained window**: compromising a
  device exposes everything that device can read — which is the same set of events its
  owner can read, screenshots included. Post-compromise security is real across rotations:
  revoke the compromised member and everything sealed afterwards is out of the attacker's
  reach, and the freshness store's epoch monotonicity stops retired keys forging new traffic.
- **Retention is boundable**: `EpochKeys.retainingFrom(epoch)` plus destroying the superseded
  instance is cryptographic erasure of older history on that device. The library ships the
  primitive and deliberately no policy — how much history a calendar keeps is a product
  question.
- **Backups:** an epoch-key set at rest is key material. Keep it out of generic backups
  (`noBackupFilesDir` on Android), same as the sealed stores.

## Platforms

| Target | Status |
| --- | --- |
| JVM | Full (Bouncy Castle) |
| Android | Full (Bouncy Castle); minSdk 28 — the platform's ChaCha20-Poly1305 starts there |
| iOS | Declared, not implemented — CryptoKit binding is future work. The conformance suite **self-skips** here: a green iOS build verifies no cryptography |
| wasmJs | Full (noble: `@noble/hashes`, `ciphers`, `curves`, `post-quantum`); the conformance and X-Wing KAT suites run in a real browser |

The JVM and Android targets share one implementation, so the whole protocol suite runs on a
laptop without a device or an emulator.

## Building and testing

```
./gradlew :lep:jvmTest      # the protocol suite: primitives, KATs, ceremonies
./gradlew :lep:assemble     # all targets
```

The suite includes ML-KEM-768 known-answer tests and X-Wing vectors, plus full pairing and
async-invite ceremonies run end to end over an in-memory channel.

## Playground

```
./gradlew :playground:run          # then open http://localhost:8088
```

Two devices in one process, pairing over a **real socket** with the real ceremony, on ports 8089
and 8090. Type a sentence, press send, and watch it become ciphertext on one device, cross a TCP
connection, and come back out as your words on the other. Every value shown is what the library
produced; the bytes marked in transit are the bytes that went down the socket.

Tick **flip a byte in transit** to see the other half of the story: the tags fail, the message is
rejected, and no plaintext is returned, because the cascade fails closed rather than handing back
something half-decrypted.

The playground is also the library's first consumer, which makes it a standing check on the
public API: if using this thing is awkward, it is awkward here first.

## Inspecting a ceremony

`./gradlew :lep:jvmTest` runs a full pairing with a seeded generator and writes
`lep/build/inspector/index.html`: every message, its size, the algorithms that produced it, a
digest of each field, and what each step actually established. Open it from disk; there is no
server, and it travels attached to a bug report.

It is generated by *running the library*, so it cannot drift from the code, and the same run
asserts what the page claims: that both sides derived the same key, that the messages appear in
protocol order, and that no key material occurs anywhere in the output. That last check holds the
run's real private keys and searches for them, rather than trusting that nothing leaked.

Recording is a transport decorator (`RecordingChannel`), not a hook inside the ceremony, so
instrumenting a run cannot change what it does, and the recorder structurally sees no more than a
wiretap would. Production passes no recorder at all.

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
