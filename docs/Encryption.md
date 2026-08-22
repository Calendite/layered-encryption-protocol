# The Encryption Algorithm, As Built

This describes what the library actually does today, field by field and byte by byte. It is a
description of the implementation rather than a design document; where the two could drift, the
code is authoritative and this file is wrong.

`Protocol.md` is the companion piece: it carries the threat model, the reasoning behind each
choice, and the known gaps. This one answers "what exactly happens to my bytes".

Every size quoted here was measured from the built code, not calculated.

> **On staleness.** An earlier version of this file went out of date badly: it described a v2
> identity, an envelope with no epoch, and thirteen frozen labels, months after all three had
> changed. A document that confidently states the wrong thing is worse than no document. If you
> change a wire format, change this in the same commit.

---

## 1. The shape of it

```
                 ┌────────────────────────────────────────────────┐
your bytes ────▶ │ seal   ChaCha20-Poly1305, then AES-256-GCM      │ ───▶ envelope
                 │ keys   X25519 + ML-KEM-768   (X-Wing)           │
your bytes ◀──── │ sign   Ed25519 + ML-DSA-65   (both required)    │ ◀─── envelope
                 │ trust  6-digit SAS, signed hash-chained log     │
                 │ rotate a new key per removal, old ones retained │
                 └────────────────────────────────────────────────┘
```

| Mechanism | Job | Failure if it alone is broken |
| --- | --- | --- |
| Cascade | Confidentiality and integrity of data | Both ciphers must fall before plaintext leaks |
| X-Wing | Agreeing the master key | Both legs must fall before traffic can be read |
| Hybrid signatures | Proving who a device is | Both algorithms must fall before impersonation |
| SAS with commitment | Deciding who to trust in the first place | A human comparing six digits catches it |
| Key epochs | Making removal mean something | A removed member reads nothing sealed after they left |

---

## 2. Data encryption: the cascade

`Cascade.seal` encrypts twice, under two independent keys.

```
chachaKey = HKDF-SHA256(ikm = masterKey, salt = none, info = "<vendor>/v1/layer-chacha", len = 32)
aesKey    = HKDF-SHA256(ikm = masterKey, salt = none, info = "<vendor>/v1/layer-aes",    len = 32)

n1 = 12 random bytes
n2 = 12 random bytes

inner = ChaCha20-Poly1305(chachaKey, n1, plaintext, aad)
outer = AES-256-GCM     (aesKey,    n2, inner,     aad)

blob  = n1 ‖ n2 ‖ outer
```

Opening reverses it: the AES tag is verified first, then the ChaCha tag. Either failure throws
`CryptoException` and no plaintext is returned. There is no code path that hands back
unauthenticated bytes.

**The keys are independent.** Same master key, different HKDF labels, unrelated outputs.

**The same associated data binds both layers**, so it cannot be altered even though it travels in
the clear.

**The layers fail independently.** Each has its own random nonce, so a collision in one is
statistically independent of one in the other. Section 9 covers why the nonces are random.

Overhead is **56 bytes**: 24 of nonce plus a 16-byte tag from each layer.

---

## 3. The envelope

`LaneEnvelope` is the unit that travels. A lane is one device's append-only log; `seq` is the op's
position in it; `epoch` says which master key sealed it.

```
envelope = frame(version) ‖ frame(contextId) ‖ frame(lane) ‖ frame(seq) ‖ frame(epoch) ‖ frame(ciphertext)
aad      = frame(version) ‖ frame(contextId) ‖ frame(lane) ‖ frame(seq) ‖ frame(epoch)
```

`frame(x)` is a 4-byte big-endian length followed by the bytes. `version`, `seq` and `epoch` are
written as decimal ASCII. **Version is 2**; v1 had no epoch field and a v1 reader would take it for
the ciphertext.

The header is deliberately plaintext so devices and relays can reconcile without decrypting, and it
is exactly the `aad`, so a relay can see that a lane holds 47 ops and refuse to serve them, but
cannot move an op to another lane, renumber it, re-attribute it to another context, or relabel its
epoch. **Metadata is visible; metadata is not malleable.**

Total header overhead is **170 bytes** on top of the cascade's 56.

`seal` takes raw bytes rather than a typed payload. What the plaintext means is the caller's
business, and keeping the library ignorant of it is what makes the envelope auditable on its own
terms.

---

## 4. Key agreement: X-Wing

The master key is agreed once, during pairing, using the X-Wing hybrid KEM
(draft-connolly-cfrg-xwing-kem-10 — a work-in-progress Internet-Draft, not yet an RFC; the
pinned draft version is re-checked before release).

```
secret key  = seed(32)   — everything below is derived from it:
                expanded = SHAKE256(seed, 96)
                (pk_M, sk_M) = ML-KEM-768.KeyGen_internal(expanded[0:32], expanded[32:64])
                sk_X = expanded[64:96];  pk_X = X25519(sk_X, BASE)
public key  = mlkem_pk(1184) ‖ x25519_pk(32)                        = 1216 B
ciphertext  = mlkem_ct(1088) ‖ x25519_ephemeral_pk(32)              = 1120 B

ss = SHA3-256( ss_mlkem ‖ ss_x25519 ‖ ct_x25519 ‖ pk_x25519 ‖ label(6 bytes) )
```

The combiner and seed expansion are transcribed verbatim from the draft and pinned to its
Appendix C test vectors (`XWingKatTest`, run against Bouncy Castle on JVM/Android and noble on
Wasm), with negative tests proving any other field ordering fails. This is not a place with
design latitude: a naive `HKDF(ss1 ‖ ss2)` fails to bind the public keys and ciphertexts,
opening identity-misbinding and re-encapsulation attacks. The label is the six ASCII bytes
`\.//^\`, hashed **last**. An earlier revision hashed it first, which was its own construction
rather than X-Wing — the vector pinning exists so that class of drift breaks a test instead of
shipping (LEP-02).

An attacker needs **both**. ML-KEM defeats harvest now, decrypt later; X25519 is what protects you
if the much younger ML-KEM implementation has a bug, so the worst case degrades to the classical
baseline rather than below it.

---

## 5. Signatures: Ed25519 with ML-DSA-65

Every signature is both algorithms over the same message, and **both must verify**.

```
public key = ed25519_pk(32)   ‖ mldsa65_pk(1952)    = 1984 B
signature  = ed25519_sig(64)  ‖ mldsa65_sig(3309)   = 3373 B
```

No combiner, because signatures do not need one. Each leg is verified independently and acceptance
requires both, so forging means forging both.

This is the mirror image of the key agreement rather than more of the same:

- **X-Wing**: an attacker must break **both** legs to *read* traffic.
- **Hybrid signatures**: an attacker must forge **both** legs to *impersonate* a device.

Breaking Ed25519 in 2035 would not decrypt traffic recorded in 2026; that is X-Wing's job and it is
already handled. What it would allow is forging a device identity from that point onward, and
ML-DSA-65 closes exactly that. NIST category 3, matching ML-KEM-768, so neither side is the weak one.

### 5.1 Where signatures appear, and where they deliberately do not

| Site | What it proves |
| --- | --- |
| Device identity binding | This signing key, X25519 key and KEM key belong together |
| Membership log entry | An existing member authorised this addition or removal |
| Async invite bundle | The published bundle is the inviter's, not a relay's substitute |
| LAN session challenge | The peer connecting holds the identity private key |

**Messages are not signed.** Once two devices share a key, the AEAD tags already prove a message
came from a holder of that key, symmetrically and so without a quantum weakness of their own.
Signing each message would add 3,373 bytes and no assurance. A test counts signing calls during a
seal and open cycle and asserts zero.

### 5.2 The device identity

```
DeviceIdentity = framed( formatVersion(1)=0x02 ‖ suiteId(2 BE)
                         ‖ signing_pk(1984) ‖ x25519_ik_pk(32) ‖ xwing_pk(1216) ‖ bindingSig(3373) )
               = 6632 B under Suite 1 (per-suite sizes; the identity is self-describing)

bindingSig = suite signing over framed( "<vendor>/v4/device-identity" ‖ formatVersion ‖ suiteId
                                        ‖ signing_pk ‖ x25519_ik_pk ‖ xwing_pk )
```

Three long-term keypairs: the hybrid signing key, an X25519 identity key for the async invite's
`dh1`, and an **X-Wing key others encapsulate to** when they need to hand this device a secret.
Section 7 is why that last one exists.

**The binding covers the whole key set, and it has to.** Signing only `x25519_ik_pk` is where a
hybrid identity fails quietly: an attacker who has broken Ed25519 but not ML-DSA takes an honest
identity, splices in an ML-DSA key of their own, forges the classical leg, and produces the
post-quantum leg legitimately because the substituted key is theirs. The tampered identity verifies
and the post-quantum leg has protected nothing. The same argument applies to the KEM key, where the
prize is receiving the rotations meant for somebody else.

This is the device certificate everywhere: handshake transcripts, membership entries including
genesis, and async bundles.

---

## 6. Pairing

Five messages, over any transport that can carry framed bytes.

```
1  InviterHello      inviter X-Wing public key, inviter identity, SAS commitment
2  JoinerResponse    KEM ciphertext, joiner identity, joiner MAC
3  InviterConfirm    inviter MAC, SAS nonce
4  SasConfirmed      (no payload: a human pressed yes)
5  InviterComplete   sealed membership log and wrapped keys
```

### 6.1 Two independent locks

```
K_handshake = HKDF-SHA256(ikm = ss, salt = transcript, info = "<vendor>/v1/pairing",     len = 32)
codeSecret  = HKDF-SHA256(ikm = code, salt = none,     info = "<vendor>/v1/code-secret", len = 32)

MAC = HMAC-SHA256( K_handshake ‖ codeSecret , transcript ‖ role )
SAS = HKDF-SHA256(ikm = ss, salt = transcript ‖ sasNonce, info = "sas", len = 8) mod 10^6
```

The **MAC** is keyed partly by the typed code, so an attacker in the middle who does not know it
fails outright. The **SAS** is six digits, shown as two groups of three, and catches an attacker who
learned the code but sits between the devices.

### 6.2 The SAS commitment, and why it exists

```
commitment = SHA-256( "<vendor>/v2/sas-commitment" ‖ nonce )
```

The inviter publishes this in message 1 and reveals the nonce in message 3. The joiner cannot derive
the SAS until then, and verifies the nonce opens the commitment before trusting the digits.

Without it the SAS is worthless. The joiner moves last: it picks the KEM ciphertext *after* seeing
everything else that feeds the SAS, so it can re-encapsulate offline until the digits match any
target it likes. **Measured against this library that takes about 39 seconds on eight threads**,
comfortably inside a code's lifetime, and it would let a machine in the middle show both people
identical digits and pass a correctly performed human check.

With the commitment neither side can steer the result: the joiner cannot compute a candidate because
the nonce is hidden, and the inviter is bound to a nonce chosen before it saw the ciphertext.

### 6.3 The transcript binds everything

```
transcript = frame("<vendor>/v1/transcript")
           ‖ frame(inviter X-Wing public key)
           ‖ frame(inviter device identity)
           ‖ frame(KEM ciphertext)
           ‖ frame(joiner device identity)
           ‖ frame(SAS commitment)
```

About 15.7 KB, dominated by the two identities. Every downstream derivation is salted with it, so
swapping any field produces different keys, a failing MAC and different digits. There is no
directory and no key server, so there is nothing to impersonate.

---

## 7. Membership, and removing somebody

An append-only, hash-chained log. Devices are added and revoked by entries signed by a device that
was already a member; any active member may sign, not only the founder.

```
entry      = { prev_hash, op, device_identity, wrapped_keys?, signer_pk, sig }

signed     = frame("<vendor>/v2/membership") ‖ frame(prev_hash) ‖ op(1)
             ‖ frame(device_identity) ‖ frame(wrapped_keys) ‖ frame(signer_pk)

entry_hash = SHA-256( signed ‖ sig )
```

Genesis chains to 32 zero bytes. Verification walks the chain checking, for every entry, that it
chains to the previous hash, that its hybrid signature is valid, that the signer was an active member
at that point, and that the subject's own identity binding verifies.

An entry is about **12.1 KB**, dominated by the identity it carries.

### 7.1 Rotation is what makes removal real

A revoke entry on its own ejects a device from the log and changes nothing it can read: it keeps the
master key, and because the relay slot derives from that key it could carry on collecting the mailbox
indefinitely. So a removal also **replaces the context key**, and seals the replacement once per
remaining member:

```
for each remaining member R:
  (ct, ss) = XWing.encapsulate(R.xwing_pk)
  wk       = HKDF-SHA256(ss, salt = none, info = "<vendor>/v1/member-key-wrap", 32)
  sealed   = Cascade(wk, newMasterKey, aad = R.serialise())

wrapped_keys = framed( for each R: framed(memberId) ‖ framed(ct) ‖ framed(sealed) )
```

The removed device is simply not a recipient, so **the entry that ejects them is the entry they
cannot read**.

Three properties, each with a test:

- **Hybrid, deliberately.** The identity also carries a classical X25519 key and wrapping under it
  would be shorter. It would also mean a recorded rotation falls to a quantum adversary, and a
  rotation is long-lived material written into a replicated log.
- **The recipient's identity is the associated data**, so a copy sealed for one member cannot be
  re-addressed to another, even by somebody who can rewrite the log.
- **A member reads only their own copy.**

A wrapped copy is **5,188 bytes** per recipient, so a revoke with two remaining members adds about
22.4 KB to the log.

> **Known inefficiency.** Of those 5,188 bytes, 3,972 is the recipient's entire hybrid public key
> written out as hexadecimal, because the full key is used as a member id throughout. The
> cryptography is about 1,200 bytes of it. A short fingerprint would roughly halve a revoke entry.
> Not yet done, and it is a wire change.

### 7.2 Key epochs

Rotation would take the shared history with it unless old keys are kept, so a device holds them all:
it **seals with the newest** and **opens with whichever epoch the envelope names**.

- Epoch 0 is the founding key, delivered by pairing.
- Epoch *n* is the key introduced by the *n*-th revoke entry.

An envelope naming an epoch a device does not hold is not corruption. It means the device was added
after that rotation, and the error says so rather than surfacing as a tag failure.

A newcomer receives **every** epoch, not just the current one, so the shared history stays readable
to them. Handing over only the newest key would leave everything before the last rotation
permanently opaque on their phone.

### 7.3 Concurrent changes

Two devices can change membership at once. Reordering a signed hash chain is impossible, since every
entry signs the previous hash, and discarding a branch would silently lose a removal. So:

| Outcome | Action |
| --- | --- |
| Identical | Nothing |
| One extends the other | Adopt the longer |
| **Forked** | Take the deterministic winner, then re-assert **only entries this device signed** |
| **Unrelated** | Refuse, always |

The winner is the longer branch, ties broken by the lower head hash, so both devices reach the same
answer without exchanging a word. Replaying only your own entries is what makes it converge: if every
device replayed everybody's, each would sign its own copy and fork again.

Lost **removals** are re-asserted automatically; lost **additions** are reported to the user instead.
Fail towards fewer members, never towards more.

"Unrelated" means sharing not one entry, not even genesis. That is a different calendar, and treating
it as a fork would let a stranger's log replace yours on the longest-branch rule.

---

## 8. The context identifier

```
contextId = SHA-256( "<vendor>/context-id/v2" ‖ genesisEntryHash )
```

Named after the **founding log entry**, not the master key. Entries are only appended, so entry zero
never moves, and the calendar keeps its name through every rotation.

It used to hash the master key, which was fine while that key was permanent. It is not: removing a
member rotates it, and under the old derivation that renamed the calendar and orphaned every lane and
chain at exactly the moment a user least wants surprises. A calendar's identity and its current key
are different things and are now derived from different values.

---

## 9. Nonces: why they are random

Each cascade layer uses a fresh 96-bit random nonce, transmitted with the message. Deriving them
deterministically from `(lane, seq)` would save 24 bytes and remove the birthday bound. It was
considered and rejected.

**The risk trade runs the wrong way.** Random 96-bit nonces collide with probability about
`q² / 2⁹⁷`, roughly 10⁻¹⁸ over a million operations. A single deterministic-nonce reuse under
AES-GCM leaks the GHASH key, enabling forgery of *any* message under it.

**It would couple confidentiality to durable sync state.** Deterministic nonces are safe only if the
counter never rewinds, which is a strong claim about state on a mobile device across migrations,
crash recovery and repair paths.

**It would defeat the cascade's independence.** Both nonces would derive from the same `(lane, seq)`,
so one rewind reuses both and the premise in section 2 collapses.

If determinism is ever wanted, the principled route is a misuse-resistant AEAD such as AES-GCM-SIV.
If the goal is only to retire the birthday bound, XChaCha20-Poly1305's 192-bit nonce does it with no
state at all.

---

## 10. Domain separation

Every derivation is labelled and every label carries a vendor prefix, so two applications built on
this library derive unrelated keys from an identical master secret.

```
label = "<vendor>/<suffix>"
```

The **fifteen** suffixes live in one file, `ProtocolLabels`, and are frozen. Changing one changes the
key or signature it produces, so two devices disagreeing about a single character cannot talk: a label
edit is a wire break that orphans existing pairings.

| Label | Used for |
| --- | --- |
| `v1/layer-chacha` | Cascade inner layer key |
| `v1/layer-aes` | Cascade outer layer key |
| `v1/transcript` | Pairing transcript hash |
| `v1/pairing` | Pairing master-key derivation |
| `v2/sas-commitment` | The inviter's SAS commitment |
| `v1/code-secret` | Pairing code secret |
| `v3/device-identity` | Device identity binding signature |
| `v1/member-key-wrap` | Wrapping a rotated key for one member |
| `v2/membership` | Membership log entry signatures |
| `v2/invite-bundle` | Async invite bundle signature |
| `v1/transcript-async` | Async pairing transcript |
| `v1/pairing-async` | Async pairing master-key derivation |
| `rendezvous/v1` | Rendezvous id, in-person |
| `rendezvous-async/v1` | Rendezvous id, async |
| `context-id/v2` | Context identifier |

Version numbers here mean the *derivation* changed, not merely the spelling. `v2/sas-commitment` and
`v1/member-key-wrap` are new; `v3/device-identity` gained the KEM key; `context-id/v2` moved off the
master key.

A test asserts this list and the labels the code uses are the same set, so a label added, removed or
edited fails the build until somebody acknowledges it. An earlier version kept its own copy of the
list and could not detect drift; it once enshrined a rename instead of catching it, which is why the
check exists in its current form.

---

## 11. Primitives, and where they come from

| Primitive | Role | Post-quantum |
| --- | --- | --- |
| ML-KEM-768 | Key agreement, post-quantum leg | Yes |
| X25519 | Key agreement, classical leg | No |
| ML-DSA-65 | Signatures, post-quantum leg | Yes |
| Ed25519 | Signatures, classical leg | No |
| ChaCha20-Poly1305 | Cascade inner layer | Symmetric |
| AES-256-GCM | Cascade outer layer | Symmetric |
| HKDF-SHA256 | All key derivation | Symmetric |
| HMAC-SHA256 | Pairing transcript MAC | Symmetric |
| SHA-256 | Hash chains, context ids, commitments, fingerprints | Symmetric |
| SHA3-256 | X-Wing combiner only | Symmetric |

Grover halves the effective key length, so 256-bit symmetric keys retain a 128-bit margin and need no
replacement.

On JVM and Android these come from Bouncy Castle 1.81 through its lightweight API, by direct class
reference rather than JCA, so the library never touches Android's repackaged Bouncy Castle. iOS and
Wasm providers are declared but not implemented, and throw if invoked.

---

## 12. Sizes

Measured, not calculated.

| Thing | Size |
| --- | --- |
| Cascade overhead per message | 56 B |
| Envelope overhead per message | 170 B |
| X-Wing public key | 1,216 B |
| X-Wing ciphertext | 1,120 B |
| Hybrid signing public key | 1,984 B |
| Hybrid signature | 3,373 B |
| Device identity | 6,621 B |
| Membership entry | ~12,100 B |
| Wrapped key, per recipient | 5,188 B |
| Revoke entry, two remaining | ~22,400 B |
| Pairing transcript | ~15,700 B |

Identity and signature sizes are the price of the post-quantum legs and dominate everything. Nothing
here was size-constrained enough to object: the pairing QR carries a 24-character code rather than a
key, and the frame reader caps at 16 MB. A consumer storing identities should expect kilobytes.

---

## 13. What this does not do

Recorded verbatim from the honest-limits section of `Protocol.md`, because a description of an
encryption algorithm that omits its limits is marketing.

- **A compromised endpoint loses.** Every guarantee is about data in transit and at rest, not about
  a device an attacker already controls.
- **Metadata is visible to a relay.** Which lanes exist, how many ops each holds, when they arrive.
  Contents are not, and the header cannot be altered, but the traffic pattern is real.
- **No forward secrecy within an epoch — or across them, on a compromised device.** Rotation
  happens on removal, not on a schedule, and historical epoch keys are deliberately retained so
  old data stays readable. A later endpoint or key-store compromise therefore decrypts every epoch
  present on that device. Do not confuse this with the harvest-now/decrypt-later resistance above:
  that holds against *passively recorded traffic* cryptanalysed in the future, not against keys
  stolen from an endpoint later (LEP-07).
- **A removed member keeps what they already had.** Rotation stops them reading anything new. It
  cannot reach backwards, and nothing can.
- **Not independently audited.** The construction follows specified primitives and pins the X-Wing
  combiner to IETF vectors, but no third party has reviewed this code.
- **iOS and Web are unimplemented.** Both providers throw rather than falling back to something
  weaker, which is the correct failure but is not support.
- **Nothing here has run on real hardware.** Every test is JVM. The rotation, epoch and fork paths
  have unit-level confidence only.
