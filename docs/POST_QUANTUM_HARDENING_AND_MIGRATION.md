# Post-Quantum Hardening and Migration Brief

## Scope

This brief assesses how the Layered Encryption Protocol (LEP) should strengthen its post-quantum posture without invalidating existing identities, pairings, membership histories, epoch keys, or encrypted data.

It is based on the public `Calendite/layered-encryption-protocol` repository at commit [`2114c6a`](https://github.com/Calendite/layered-encryption-protocol/commit/2114c6aaa1aa0277e18275bdba7b80a909fe76f9).

## Executive conclusion

LEP already has a credible hybrid post-quantum design:

- X-Wing combines X25519 with ML-KEM-768 for key establishment.
- Hybrid signatures require both Ed25519 and ML-DSA-65 to verify.
- Payload encryption uses 256-bit symmetric keys with ChaCha20-Poly1305 and AES-256-GCM.
- Pairing, asynchronous invitation, and master-key distribution use the hybrid KEM rather than relying only on classical public-key cryptography.

Under current cryptographic understanding, this is designed to resist a future cryptographically relevant quantum computer. It also materially addresses **store now, decrypt later**, provided that the X-Wing/ML-KEM path is used from the first exchange and plaintext or keys are not later obtained from endpoints, backups, logs, or a compromised random-number generator.

It would still be incorrect to promise that LEP is simply “quantum-proof.” ML-KEM and ML-DSA are believed secure against known classical and quantum attacks; that is not a proof against every future discovery. The current X-Wing construction is also an Internet-Draft rather than a final IETF standard.

The best next step is therefore **cryptographic agility**, not an immediate replacement of the current algorithms. LEP should preserve its present construction as a frozen first suite and add a versioned, downgrade-resistant mechanism through which a later standardized suite can be introduced.

## Will this break what already exists?

**Not if it is implemented as a side-by-side, versioned migration.** Existing data can remain byte-for-byte unchanged and continue to be opened with the current suite.

**It will break compatibility if the current algorithms, sizes, encodings, or domain-separation labels are changed in place.** Those values are already embedded in identities, signatures, membership hashes, pairing messages, invitation bundles, and encrypted envelopes.

| Proposed action | Existing data | Existing applications | Result |
|---|---|---|---|
| Replace algorithms inside the current formats | Fails verification or decoding | Breaks | Do not do this |
| Change an existing `ProtocolLabels` value | Existing signatures/derivations can fail | Breaks | Never change frozen labels |
| Add fields without incrementing a format version | Parsers disagree about byte boundaries | Breaks | Do not do this |
| Preserve current decoders and add new versioned formats | Remains readable | Updated apps read both | Recommended |
| Upgrade a live context only after every retained device supports the new suite | History remains readable | Updated devices continue normally | Recommended |
| Send a new-suite artifact to an old application | Old app cannot understand it | New activity unavailable there | Expected incompatibility |
| Re-encrypt all historical data | Can alter object identifiers and sync semantics | High migration risk | Avoid initially |

The unavoidable boundary is the live upgrade itself: an application that has not been updated cannot read or create artifacts using a new suite. It must be updated before the context upgrades, or its device must be deliberately removed from that context. This is a capability transition, not loss of old ciphertext.

## Recommended suite model

Introduce an immutable `ProtocolSuite` definition and a registry indexed by a stable numeric `suiteId`.

### Suite 1: freeze the current protocol

For example:

`LEP_HYBRID_2026 = 1`

Suite 1 should mean exactly the implementation and encodings currently shipped:

- X-Wing draft-10: X25519 + ML-KEM-768
- Ed25519 + ML-DSA-65, with both signatures required
- ChaCha20-Poly1305 followed by AES-256-GCM
- The current KDFs, hashes, encodings, size limits, and labels

Once named, Suite 1 must remain frozen. Later corrections that change bytes or cryptographic meaning require another suite or format version.

### Suite 2: reserve, but do not invent

Do not define Suite 2 merely by substituting ML-KEM-1024 into X-Wing. X-Wing specifies a particular construction, transcript, encoding, and parameter set. An ad hoc “X-Wing-1024” would be a new cryptographic protocol requiring its own analysis.

Suite 2 should be assigned only when there is an appropriate final, reviewed standard. Candidates may include:

- The final standardized form of X-Wing, if materially different from Suite 1.
- Another standardized hybrid KEM at a higher security category.
- ML-KEM-1024 and ML-DSA-87 where used by a reviewed, interoperable construction rather than a locally invented composition.
- A later standardized HQC-based suite if implementation diversity is required.

The selected suite should be implemented from the exact standard, tested against official vectors, and independently reviewed before it is enabled for production creation.

### Suggested Kotlin shape

```kotlin
@JvmInline
value class SuiteId(val value: UShort)

interface ProtocolSuite {
    val id: SuiteId
    val name: String

    fun encapsulate(publicKey: ByteArray): KemResult
    fun decapsulate(privateKey: ByteArray, ciphertext: ByteArray): ByteArray
    fun sign(privateKey: ByteArray, message: ByteArray): ByteArray
    fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean
    fun seal(key: ByteArray, nonce: ByteArray, aad: ByteArray, plaintext: ByteArray): ByteArray
    fun open(key: ByteArray, nonce: ByteArray, aad: ByteArray, ciphertext: ByteArray): ByteArray
}

object SuiteRegistry {
    fun require(id: SuiteId): ProtocolSuite =
        suites[id] ?: throw UnsupportedSuiteException(id)
}
```

The real interface may separate KEM, signing, and symmetric operations more finely. The security requirements are more important than the exact class design:

- Unknown suite identifiers fail closed.
- Suite selection is authenticated wherever it is negotiated.
- A suite identifier is included in every new signature transcript, KDF context, hash-chain entry, and AEAD associated-data value that depends on it.
- Existing Suite 1 bytes continue through legacy code paths or compatibility fixtures with identical output.
- Policy can specify a minimum acceptable suite and prevent silent fallback.

## Repository-specific implementation plan

### 1. Freeze compatibility before refactoring

Before introducing abstractions, commit fixtures containing real Suite 1 artifacts for:

- Device identities
- Membership entries and complete logs
- Synchronous pairing messages
- Asynchronous invitation links and bundles
- Lane envelopes
- Epoch-key serialization
- Sealed state files

Tests must prove that the refactored implementation parses and verifies those fixtures and, where deterministic inputs are used, reproduces the same bytes. This is the guard against accidentally changing the protocol while reorganizing it.

### 2. Version device identities

`DeviceIdentity` currently relies on fixed key and signature sizes and has no suite identifier. Do not reinterpret its current byte representation.

Add a new identity representation with at least:

```text
formatVersion | suiteId | signingPublicKey | identityDhPublicKey |
kemPublicKey | bindingSignature
```

When a device adopts a new suite, it should generate new suite-appropriate keys and publish a `KeyTransition` signed by both its old and new signing identities. That establishes continuity and possession of both private keys. Without this transition, a replacement identity is indistinguishable from an unrelated new device.

Keep the legacy identity decoder indefinitely for verifying historical membership entries.

### 3. Add authenticated suite negotiation to pairing

`PairingWire` currently uses fixed message tags and fixed sizes. Keep the existing messages unchanged for Suite 1.

Add a new message family or a versioned outer frame containing:

- Protocol format version
- Initiator-supported suite IDs
- Responder-supported suite IDs
- Fresh nonces from both parties
- Selected suite ID
- Any relevant policy, such as minimum suite

The complete offer, response, nonces, and selection must be covered by the handshake transcript, KDF context, and final authentication. Otherwise an attacker may be able to remove stronger suites and force Suite 1.

Rules for negotiation:

1. Select the strongest mutually supported suite permitted by both policies.
2. Reject an unknown or disallowed selection.
3. Never silently retry a weaker suite after the peer has demonstrated support for a stronger one.
4. Bind the selected suite into every proof and derived key.
5. Treat the current pairing messages as an explicit legacy Suite 1 flow, not as an ambiguous auto-detection fallback.

### 4. Version asynchronous invitations

The current invitation bundle and link are also based on fixed Suite 1 sizes. Add a new link/bundle version that carries its `suiteId` and, if negotiation is needed, authenticated capabilities.

The inviter's signature must cover the version, suite, recipient information, expiration or replay controls, and all encapsulated material. Existing links must remain assigned to the existing Suite 1 parser.

### 5. Make suite upgrades membership operations

Changing a context's suite affects every active member and must not be a local setting. Add an authenticated membership operation such as `SUITE_UPGRADE`.

An upgrade entry should bind at least:

- Previous membership-log head
- Old and new suite IDs
- The exact transition epoch
- Fresh master-key material wrapped for every retained member using the new suite
- Replacement identities or validated `KeyTransition` records where required
- The exact retained/revoked device set
- Acknowledgements or authorization required by the context's governance policy

The entry should atomically rotate the context key and change the suite. No valid log prefix should indicate that the suite has changed while omitting the corresponding fresh keys.

Recommended policy: require every device that will remain active after the upgrade to advertise support and provide its new public material first. A quorum may authorize the operation, but a retained device without the new capability would still be unable to continue.

Verification of old membership history must use the suite active for each historical entry. Suite changes should be monotonic unless an explicit, strongly authorized recovery procedure exists; ordinary processing must reject downgrade operations.

### 6. Introduce a new envelope version

`LaneEnvelope` currently identifies itself as version 2. Preserve version 2 as Suite 1.

Create version 3 with an explicit `suiteId` and include the identifier in AEAD associated data:

```text
version | suiteId | contextId | lane | sequence | epoch | ciphertext
```

The context state should record which suite starts at which epoch, for example:

```text
startEpoch -> suiteId
```

Alternatively, each stored epoch key can carry its suite ID. A context-level epoch schedule is preferable because a suite transition is a membership event and an epoch boundary, not a property that individual devices should choose independently.

After an upgrade:

- Version 2 envelopes and pre-upgrade epochs remain decryptable with Suite 1.
- Version 3 envelopes use the suite recorded for their epoch.
- The `contextId` remains stable; it should not change merely because algorithms rotate.
- Re-encryption of history is optional and should not be part of the first migration.

### 7. Preserve domain separation

`ProtocolLabels.kt` correctly treats existing labels as frozen. Do not edit or reuse those labels with different algorithms.

Define new labels under an unambiguous suite namespace, for example:

```text
LEP-SUITE-0002/<operation>/<version>
```

The suite ID itself should also be encoded in the authenticated transcript. A label name alone is not a substitute for a parsed, validated suite identifier.

### 8. Keep stored-state compatibility

The sealed state file's current symmetric cascade already uses quantum-resistant key sizes under present understanding. It does not need to be rewritten solely to obtain a post-quantum claim.

If the internal state schema must store suite schedules or new identities, add a new state-file version while continuing to read version 1. Perform upgrades with an atomic write, and retain a recoverable backup until the new file is verified.

The platform mechanism that protects the state-file key also matters. A post-quantum wire protocol does not help if the same key is exported or backed up using only RSA or elliptic-curve encryption.

### 9. Add policy and lifecycle controls

Expose policy separately from cryptographic implementation:

- Minimum suite accepted for new pairings
- Suites allowed for creating new contexts
- Suites retained only for historical reads
- Upgrade readiness per device
- Deadline after which Suite 1 creation is disabled
- Key-retention and secure-pruning policy

Historic reads and new writes need not have the same policy. Suite 1 can remain available for decrypting old data after the application stops creating new Suite 1 contexts.

## Safe rollout sequence

### Phase 0 — non-breaking internal work

1. Add Suite 1 compatibility fixtures and known-answer tests.
2. Introduce `SuiteId`, `ProtocolSuite`, and `SuiteRegistry`.
3. Route current operations through Suite 1 without changing a single protocol byte.
4. Confirm interoperability with the current release.

### Phase 1 — additive wire support

1. Add version-aware identity, invitation, pairing, membership, epoch, and envelope parsers.
2. Add the new authenticated capability negotiation.
3. Add `SUITE_UPGRADE` validation and mixed-suite historical verification.
4. Continue creating Suite 1 data by default until the new paths have been tested and audited.

### Phase 2 — implement a standardized successor

1. Wait for the selected construction to be final and stable.
2. Pin exact algorithm identifiers, document revisions, encodings, and parameter sets.
3. Use official known-answer vectors.
4. Test against an independent implementation.
5. Complete parser fuzzing, malformed-ciphertext tests, timing/side-channel review, and an external cryptographic audit.

### Phase 3 — upgrade one context atomically

1. Every retained device updates its application.
2. Each device generates required new keys and submits authenticated transition material.
3. The context verifies that all retained devices support the target suite.
4. An authorized device appends one `SUITE_UPGRADE` operation and rotates the master key at a new epoch.
5. New messages use the new suite; historical messages remain under their original suite.
6. Unsupported devices are updated or explicitly revoked, never silently abandoned.

### Phase 4 — gradual deprecation

Stop using Suite 1 for new contexts or pairings only after deployment evidence supports that decision. Retain its parsing, verification, and decryption code for as long as users may possess Suite 1 data.

## Required security tests

Add tests covering at least:

- Byte-for-byte decoding and verification of frozen Suite 1 fixtures
- Old ciphertext decrypting after a context upgrades
- Old membership entries verifying under the suite active at that point
- Unknown suite identifiers failing closed
- Negotiation offers and selections being authenticated
- Removal or reordering of supported suites causing transcript verification to fail
- No silent fallback following a stronger authenticated offer
- Rejection of a suite downgrade membership operation
- Rejection of an upgrade that omits any retained member's fresh wrapped key
- Rejection of truncated upgrade entries or incomplete key transitions
- Safe rejection, rather than misparsing, of new artifacts by legacy decoders
- Official KEM/signature known-answer tests and cross-implementation vectors
- Malformed public keys, ciphertexts, signatures, lengths, and integer values
- Decapsulation-failure behavior and timing-sensitive paths
- Atomic state migration and recovery after an interrupted write

## What this does and does not protect

| Threat | Expected result after this design |
|---|---|
| Classical attack on one hybrid component | Other required component should still protect the operation, subject to correct composition |
| Future quantum attack on X25519 or Ed25519 | ML-KEM/ML-DSA components are intended to preserve confidentiality/authenticity |
| Store now, decrypt later | Addressed for properly established hybrid sessions unless keys/plaintext are later compromised |
| Cryptanalysis of one deployed suite | Versioned successor can be introduced without discarding history |
| Negotiation downgrade | Prevented by authenticating capabilities, selection, and policy |
| Stolen unlocked endpoint | Not prevented by post-quantum cryptography |
| Extracted keys, insecure backups, weak randomness | Not prevented by algorithm choice |
| Traffic analysis, metadata leakage, denial of service | Not inherently prevented by this protocol change |
| Unknown future quantum or mathematical breakthroughs | No absolute guarantee is possible |

## Recommended public wording

> LEP uses hybrid classical and post-quantum cryptography and is designed to protect confidentiality and authenticity against known classical attacks and future quantum attacks under current cryptographic assumptions. Its versioned suite design allows algorithms to be upgraded as standards and cryptanalysis evolve. This is not a guarantee against endpoint compromise, implementation defects, or unknown future breakthroughs.

Avoid the unqualified terms “quantum-proof,” “unhackable,” or “guaranteed safe from quantum computers.”

## Priority order

1. Freeze Suite 1 with compatibility fixtures.
2. Add suite-aware parsing and authenticated, downgrade-resistant negotiation.
3. Add the atomic context upgrade mechanism and per-epoch suite history.
4. Review endpoint key storage, export, backup, randomness, and pruning.
5. Commission independent protocol and implementation audits.
6. Adopt a successor suite only from a stable, reviewed standard.

The main engineering risk is not that the current cryptographic choices are obviously too weak. It is accidentally breaking or downgrading a sound existing protocol while trying to make it more future-proof. Versioned suites, frozen legacy formats, authenticated transitions, and comprehensive compatibility fixtures are the safest route.

## Standards references

- [NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204: Module-Lattice-Based Digital Signature Standard](https://csrc.nist.gov/pubs/fips/204/final)
- [X-Wing hybrid KEM Internet-Draft](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/)
- [CFRG Hybrid KEM Internet-Draft](https://datatracker.ietf.org/doc/draft-irtf-cfrg-hybrid-kems/)
- [NIST Post-Quantum Cryptography project](https://www.nist.gov/pqc)
- [NIST PQC security-category FAQ](https://csrc.nist.gov/projects/post-quantum-cryptography/faqs)

