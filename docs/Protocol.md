# Protocol

> Threat model and reasoning. For a field-by-field description of what the code actually
> does today, see [`Encryption.md`](Encryption.md).

The cryptographic design behind `layered-encryption-protocol`: what each choice defends against,
and what it deliberately does not.

> Extracted from the specification of the application this library was built for (a shared
> calendar). Section numbers are kept from that document so existing cross-references still
> resolve; application-specific sections are omitted rather than renumbered. Where the text says
> "calendar", read "the shared dataset"; where it says "the app", read "the consuming
> application".

## 4. Cryptographic Architecture

### 4.1 Design principles

1. **No single algorithm is a single point of failure** — for reading data
   *and* for stealing keys.
2. **Audited code everywhere an audited implementation exists.** Unaudited code
   is quarantined to slots where its total failure degrades security to the
   classical audited baseline, never below it.
3. **Hot paths get hardware/constant-time code.** The KEM runs once per pairing;
   the symmetric layers run on every blob — allocate scrutiny accordingly.
4. **No negotiation.** Each protocol version pins exactly one ciphersuite.
   Unknown version ⇒ refuse. Negotiation is how attackers strip the PQ layer.

### 4.2 Data encryption — the cascade

```
plaintext ── ChaCha20-Poly1305 (K1, n1) ── AES-256-GCM (K2, n2) ──> blob
```

- **Independent keys**: `K1 = HKDF(master, "calendite/v1/layer-chacha")`,
  `K2 = HKDF(master, "calendite/v1/layer-aes")`. Never the same key twice; with
  independent keys a cascade is provably at least as strong as its strongest layer.
- **Unrelated designs**: AES is a substitution-permutation block cipher, ChaCha
  an ARX stream cipher. A breakthrough against one family says nothing about the
  other. (Cascading AES with itself would be pointless.)
- **Both AEAD tags verified** on decrypt, outer first. Either tag fails ⇒ blob
  rejected, fail closed.
- **Nonces**: fresh 96-bit random per layer per blob, from the platform CSPRNG.
  At calendar-event volumes the GCM birthday bound is irrelevant (it bites near
  ~2³² messages per key).
- **Cost**: double symmetric work on kilobyte blobs — unmeasurable.
- Precedent: VeraCrypt cascades, Keybase TripleSec. Belt-and-braces, priced in.

**Read requirement**: break ChaCha20 **and** AES-256, or obtain the keys.

### 4.3 Key agreement — hybrid X-Wing

```
X25519 (classical)  ─┐
                     ├─ X-Wing combiner ──> shared secret ──> HKDF ──> keys
ML-KEM-768 (PQ)     ─┘
```

- **Why hybrid**: Shor's algorithm breaks X25519 on a large quantum computer;
  ML-KEM is new and less battle-tested. Requiring both to fail covers both risks.
- **Why X-Wing specifically, not a hand-rolled combiner**: naive
  `HKDF(ss1 ‖ ss2)` fails to bind public keys and ciphertexts into the derived
  key, opening identity-misbinding and re-encapsulation attacks; XOR combiners
  let a broken component *choose* the output. X-Wing is the IETF-drafted
  hybrid for exactly X25519 + ML-KEM-768, with a formal IND-CCA proof and
  published test vectors. We **transcribe the spec**, we do not design a combiner.
  Status honestly: X-Wing is a work-in-progress Internet-Draft (we implement
  draft-10 exactly — seed-based key generation included, secret key = 32-byte
  seed), not yet an RFC; its status is re-checked before release.
- The combiner is implemented **once in `commonMain`** (SHA-3 over fixed inputs,
  ~20 lines), pinned to the draft-10 Appendix C vectors by `XWingKatTest` on
  every platform, with the X25519 and ML-KEM primitives injected per platform.
  iOS ignores it and uses Apple's native X-Wing (§5); the interop suite proves
  all implementations agree.

**Key-theft requirement**: break X25519 **and** ML-KEM.

### 4.4 Quantum threat analysis

| Threat | Status |
|---|---|
| Shor vs X25519 | Broken by a future CRQC — this is why ML-KEM exists in the stack |
| Shor vs Ed25519 signatures | Forgeable by a future CRQC, but cannot be *harvested* retroactively. **Closed**: every signature is now Ed25519 + ML-DSA-65 with both required (`Encryption.md` §5) |
| Grover vs AES-256 / ChaCha20 | Halves effective strength to ~128-bit — still secure. Symmetric layers need **no** replacement |
| Harvest-now-decrypt-later | The real present-day threat. All recorded traffic is protected by the ML-KEM leg |

**Failure matrix**

| Event | Outcome |
|---|---|
| ML-KEM implementation bug (unaudited leg) | Security = audited classical X25519 + cascade — the pre-PQ industry baseline |
| Quantum computer arrives | X25519 leg falls; ML-KEM holds. Attacker needs **quantum AND an ML-KEM implementation bug simultaneously** |
| AES-256 broken | ChaCha20 layer still stands (and vice versa) |
| Both symmetric ciphers broken | Global cryptographic apocalypse; out of scope |

### 4.5 Pairing authentication — SAS, not a PAKE

SPAKE2 was dropped: it is ECC-based (its transcript is quantum-harvestable) and
has no platform implementation on iOS, which would reintroduce unaudited
third-party code. Replacement, two independent locks:

1. **Code-keyed transcript MAC.** Both sides prove knowledge of the pairing
   code: `HMAC(K_handshake ‖ code-secret, transcript ‖ role)`. A MITM without
   the code cannot complete the handshake at all.
2. **Human SAS comparison.** `SAS = HKDF(shared-secret, transcript, "sas") mod 10⁶`,
   shown as **6 digits** on both screens (grouped 3-3, same Atkinson Mono
   display style as the pairing code — digits chosen over words/emoji for the
   same localisation reasons as §6.1). Users confirm they match. A MITM who
   somehow intercepted the code still cannot survive the comparison.

### 4.6 Key hierarchy

```
pairing handshake (X-Wing) ──> K_handshake        (delivers wrapped keys once)
calendar master key  ──HKDF──> K1 (ChaCha), K2 (AES), K_lane-auth, ...
creator personal key ──────--> hidden-event payloads (§3)
device identity keypair ─────> Ed25519 + ML-DSA-65, both required
                               (signs membership log & LAN challenges)
                               + X25519 identity key, bound by a hybrid signature (async dh1, §6.5)
```

The device identity is a unified certificate — `framed(signing_pk ‖ x25519_ik_pk ‖ bindingSig)` —
carried in handshake transcripts, membership entries (genesis included), and async bundles.
Membership verification checks each entry's binding signature. The binding message covers the
signing key as well as the X25519 key, without which the post-quantum leg could be substituted by
an attacker who had broken the classical one (`Encryption.md` §5.2).

- Master key generated on the creating device; **never transits unwrapped** —
  only wrapped under `K_handshake` (pairing) or a device's wrap key (rotation).
- **At rest**: master + personal keys wrapped by a hardware-backed key —
  Android Keystore (StrongBox where present) / iOS Secure Enclave via Keychain.
  ML-KEM private keys cannot live *inside* enclaves (no lattice support) but are
  stored wrapped by the hardware key; they are ephemeral per pairing anyway.
- All HKDF labels namespaced `calendite/v1/...` for domain separation. The spelling is a
  **frozen wire constant** — every platform must match it byte-for-byte, and it is never
  respelled after ship (a one-character change re-derives every key).

### 4.7 Membership log

A compromised relay must not be able to inject "new device added". The device
list is an **append-only, hash-chained log**, every entry signed by an existing
member device (Keybase sigchain / Matrix cross-signing pattern):

```
entry_n = { prev_hash, op: add|revoke|rotate, device_pubkey, wrapped_keys?, sig }
```

Clients verify the full chain before honouring any membership change. Signing is hybrid
Ed25519 + ML-DSA-65 as of v2, and **both** legs must verify, so forging an entry means forging
both algorithms.

Ops: `add` (subject joins; `wrapped_keys` optionally carries the context key sealed to them),
`revoke` (subject leaves; `wrapped_keys` carries a fresh context key sealed per remaining
member — the entry that ejects a device is the entry it cannot read), and `rotate` (no
membership change; a self-signed rekey whose mandatory `wrapped_keys` seals a fresh context
key to every active member). `rotate` exists because fork resolution can drop a key-holder
with nobody left to revoke — a member added on a losing branch — and doubles as the periodic
or post-compromise rekey primitive.

**Fork resolution is enforced, not advisory.** Two branches appended concurrently reconcile
by removal precedence (most revocations, then length, then head hash), and the resolving
device *appends* the consequences to the winning branch: every member revoked on either
branch is revoked on the resolved log, additions sponsored — directly or transitively — by a
member the fork revokes fall with their sponsor, and resolution ends with a `rotate` sealed
only to post-resolution members whenever anyone holding key material did not survive. A
device the fork itself condemns cannot resolve; it re-pairs.

### 4.8 Revocation & the breakup case

- **Revoke a device**: append signed revoke entry → generate master key K′ →
  wrap K′ for every remaining device → all future ops under K′-derived keys.
  The revoked device retains what it already decrypted (unavoidable —
  screenshots exist); it can read **nothing after** revocation.
- **Soft split**: stop sharing future events; both keep synced history.
- **Hard split**: full revoke + rekey; optionally owner dissolves the calendar
  and clears any relay storage.
- **Export anytime** — people leave with their history. Graceful exit is a
  deliberate product differentiator.
- **No cloud key recovery.** New phone / reinstall ⇒ re-pair (fresh code + SAS).
  Optional recovery phrase is an open question (§9).

**Epoch-key retention policy.** Devices retain every epoch key they received,
indefinitely by default; the library provides `EpochKeys.retainingFrom` as the
pruning/cryptographic-erasure primitive and imposes no policy of its own. Sync
pairing transfers the full retained set (same owner); a member added by log
entry starts at their join epoch and can never read earlier ones; an async
invite founds a fresh context. Within the retained window there is no forward
secrecy — endpoint compromise exposes what that endpoint could read — and
across rotations there is post-compromise security: a revoked or excluded
attacker reads nothing sealed after the rotation, and freshness-store epoch
monotonicity keeps retired keys from forging fresh traffic.

---

## 5. Libraries & Provenance

### 5.1 Per-platform sourcing

| Component | Android | iOS | Web (Wasm — future, §9.3) |
|---|---|---|---|
| ChaCha20-Poly1305 (layer 1) | JCA built-in (API 28+) | CryptoKit `ChaChaPoly` (iOS 13+) | libsodium.js — `ietf` variant, RFC 8439 |
| AES-256-GCM (layer 2) | JCA built-in (Conscrypt / BoringSSL) | CryptoKit `AES.GCM` (iOS 13+) | WebCrypto `SubtleCrypto` |
| X25519 | Platform XDH (API 33+); Bouncy Castle below | inside CryptoKit X-Wing | WebCrypto (all evergreen browsers) |
| ML-KEM-768 | **Bouncy Castle** ≥ 1.81 (FIPS 203 final) | inside CryptoKit X-Wing (iOS 26+, formally verified, Secure Enclave) | **Kodium** — raw ML-KEM primitive **only** |
| X-Wing combiner | shared `commonMain` impl | CryptoKit native | shared `commonMain` impl |
| HKDF | Bouncy Castle (RFC 5869) | CryptoKit `HKDF` (iOS 14+) | WebCrypto |
| Key at rest | Keystore / StrongBox | Secure Enclave / Keychain | non-extractable `CryptoKey` in IndexedDB |
| CSPRNG | `SecureRandom` | `SecRandomCopyBytes` | `crypto.getRandomValues` |

Wired through an `expect`/`actual` `CryptoProvider` interface in `commonMain`.
The Wasm column is designed now, implemented only when the web App version
becomes a sync client.

### 5.2 Provenance tiers

- **OS / platform (audited, hardware-accelerated)**: all of iOS; Android
  symmetric + X25519 + Keystore; web AES/X25519/HKDF.
- **Third-party, heavily scrutinised**: Bouncy Castle (Android ML-KEM),
  libsodium.js (audited C compiled to Wasm).
- **Third-party, unaudited, quarantined**: **Kodium** (pure-Kotlin ML-KEM), web
  only, ML-KEM leg only — chosen over noble-post-quantum for zero JS interop
  and Maven-only supply chain; no audited JS PQC exists, and a total Kodium
  failure degrades web pairing to classical security (§4.4). Pinned version;
  provider interface makes swapping a one-file change.
- **Our own crypto-touching code**: the `commonMain` X-Wing combiner
  (transcribed from the IETF spec) and cascade orchestration — both vector-pinned.

**Kodium licence**: Apache 2.0 (patent grant included). Bouncy Castle: MIT-style.
libsodium: ISC. Atkinson Hyperlegible Mono: SIL OFL 1.1 — bundle **unmodified**
(subsetting counts as modification and triggers the reserved-name rename rule).

### 5.3 Version gates

- **iOS 26+** for the sharing feature only (CryptoKit ML-KEM / X-Wing). Gate the
  feature, not the app. Check whether swift-crypto back-deploys the PQ API —
  would soften the gate.
- **Android API 28+** effectively (platform ChaCha20-Poly1305); Bouncy Castle
  covers X25519 below API 33.

### 5.4 CI test matrix

- NIST **ACVP** known-answer vectors for ML-KEM-768 against Bouncy Castle *and*
  Kodium; cross-check the two against each other on JVM.
- **X-Wing IETF vectors** against all implementations (commonMain and CryptoKit).
- **RFC 8439** (ChaCha20-Poly1305) and **RFC 5869** (HKDF) vectors on every platform.
- **Round-trip interop**: encrypt on each platform, decrypt on the others —
  including the full pairing handshake cross-platform.
- Membership-log chain verification fixtures (tamper cases must fail).

### 5.5 Pre-launch security checklist

- [ ] Verify Kodium's raw ML-KEM output against ACVP + Bouncy Castle (never use `Kodium.pqc`'s bundled hybrid or SecretBox)
- [ ] Independent review of the commonMain X-Wing combiner + cascade orchestration (small, cheap to review)
- [ ] Confirm no key material in logs, crash reports, or analytics
- [ ] Export-compliance declarations filed (§10)
- [ ] Threat-model doc (§9) reviewed against final implementation

---

## 6. Pairing Protocol

### 6.1 The code

- **6 characters from the full 36-char alphabet** (A–Z, 0–9), generated by the
  platform CSPRNG. 36⁶ = 2,176,782,336 ≈ **31 bits**.
- Full alphabet (not Crockford) is deliberate: no per-language word lists to
  curate, and the confusables are handled by display + lenient verification
  instead of alphabet restriction.
- **One-shot** (burns on success), **3 wrong attempts** burns it, **10-minute
  expiry**. Guessing is online-only — each attempt needs the inviting device
  (Phase 1) or relay slot (Phase 2) to respond — so 3 tries against ~10⁹ ≈
  1-in-360-million. The inviter enforces these rules locally in Phase 1; the
  Worker enforces the identical rules in Phase 2.

### 6.2 Display & input

- **Display**: uppercase, grouped `K7M-0F2`, in **Atkinson Hyperlegible Mono**
  (bundled, unmodified). Letters and digits in **different theme colours**
  (e.g. letters `text`, digits `accent`, via the dark-mode transformer). Every
  classic confusable pair — O/0, I/1, S/5, B/8, Z/2, G/6 — is letter-vs-digit,
  so class colouring disambiguates the whole set; the font handles shape; colour
  stays redundant, so colour-blind users lose nothing.
- **Input**: same Mono font; auto-uppercase; strip hyphens/spaces; autocorrect
  and suggestions off; **live class-colouring** as they type so mistranscription
  is self-evident. Clipboard chip ("Paste K7M-0F2?") via `UIPasteControl` /
  Android clipboard chip — never silent clipboard reads.
- **Verification forgives exactly one pair**: {0, O}. Everything else must be
  entered as shown — `1`, `I` and `L` are three distinct characters. The display
  already solves confusability (uppercase Atkinson Hyperlegible Mono + letter/digit
  class colouring), so folding those classes would spend entropy to fix a problem
  the typography has already fixed. `0`/`O` is kept because it is the one pair whose
  shapes stay close even so. Effective space 35⁶ ≈ 1.84 bn ≈ **30.8 bits**.
  Copy-paste paths (the common remote case) are character-faithful anyway; the
  single fold covers typed-from-sight, voice, and paper.

### 6.3 Handshake (transport-agnostic)

Let `S` = canonicalised code. `rid = SHA-256("calendite/rendezvous/v1" ‖ S)`.

```
1. A (inviter) generates ephemeral X-Wing keypair
   → posts {xwing_pk, A_device_cert} at rid          [mDNS name = rid | mailbox slot = rid]
2. B enters code → computes rid → fetches bundle
   → X-Wing encapsulate → (ct, ss) → posts {ct, B_device_cert}
3. Both derive K_handshake = HKDF(ss, transcript, "calendite/v1/pairing")
4. Mutual code-keyed MACs (§4.5) — MITM without S fails here
5. Both display SAS (6 digits from HKDF(ss, transcript, "sas")) → humans confirm
6. A appends signed membership entry adding B (§4.7)
   → sends master key + log head wrapped under K_handshake
7. rid burns; ephemeral keys discarded
```

Steps 2–7 are **byte-identical** in both phases; only the step-1 lookup differs.
In Phase 1 the inviter's phone *is* the mailbox.

### 6.4 Link upgrade (Phase 2+)

A link is a code in costume: `https://calendite.com/join#K7M-0F2`. The code
lives in the **URL fragment** — fragments never reach the web server, so even
our own infrastructure never sees codes in logs. Universal/App Links open the
app with the field pre-filled; manual entry remains forever as the fallback and
the LAN-only path.

### 6.5 Async invites (PQXDH-derived)

A **second door** for when the partner can't do the live 10-minute ceremony. It borrows PQXDH's
pre-published-bundle mechanism while rejecting its directory/accounts trust model. Relay-only (Phase
2) — something must hold the bundle while the inviter sleeps. Full spec: `Async_Invites_Spec.md`.

- **Link** — `https://calendite.com/join#A2.<secret>.<fp>`: an `A2` tag, a **32-byte** CSPRNG
  `secret` (base64url), and `fp` = first 16 bytes of `SHA-256(ed25519_pk_A)`. The fragment never
  reaches a server (§6.4). `rid_async = SHA-256("calendite/rendezvous-async/v1" ‖ secret)`.
  Because the relay sees `rid_async`, that hash is an **offline** verifier for secret guesses —
  the secret must carry full-strength entropy. `A2` replaces the 8-byte-secret `A1` format, whose
  64-bit keyspace a GPU farm could cover within an invite's lifetime (LEP-01); `A1` links are
  rejected. The library also caps invite lifetime at **7 days** (`AsyncInviter.MAX_LIFETIME_SECONDS`).
- **Bundle** — the inviter posts a long-lived, hybrid-signed `InviteBundle`
  `{ inviteXWingPublicKey, deviceIdentityA, expiry, sigA }` at `rid_async`. The joiner pins it by
  the `fp` in the link, so a relay that swaps the bundle is caught — this is the anti-directory
  property that replaces PQXDH's trusted key server.
- **Derivation** — X-Wing runs as usual (`ss`, combiner verbatim); an identity DH
  `dh1 = X25519(ik_S, spk_A)` is chained in afterwards, Noise-style, with every public value bound
  via the transcript: `K_async = HKDF(ss ‖ dh1, "calendite/v1/pairing-async", transcript, 32)`.
  A contributory (all-zero / low-order) `dh1` is rejected.
- **Auth** — two gates. First a cheap link-possession MAC
  (`HMAC(secret, framed("…/async-link-auth" ‖ rid_async ‖ ct ‖ identity_S))`) that the inviter
  verifies **before** any signature verification, ML-KEM decapsulation, or X25519 — a stranger
  without the link cannot make the inviter spend post-quantum compute (LEP-06). Then the full
  handshake MAC (`HMAC(K_async ‖ secret, transcript ‖ role)`) gates the joiner even appearing in
  the owner's queue; a lazily-compared 6-digit SAS backs it up. Key release is **approval-gated**:
  the master key is delivered (wrapped under `K_async`, inside the membership log's `ADD` entry)
  **only** on the owner's explicit `approve()`.
- **Lifecycle** — `PENDING → CLAIMED → APPROVED | REJECTED | EXPIRED`. First valid response claims;
  later valid ones report "already claimed" (mirroring the live one-shot property).
- **Caveat** — the bundle signature (Ed25519) and `dh1` (X25519) are classical, so async
  *authentication* inherits PQXDH's documented limitation (a live quantum attacker could forge it);
  **confidentiality is unaffected** (`ss` is hybrid). **Bundle signatures are now hybrid**, so the
  signature half of this caveat is closed; `dh1` remains X25519 and is still classical.

---

## 9. Threat Model & Honest Limits

### 9.1 What we do not protect against

- **The partner you shared with.** Screenshots, memory, and already-synced
  events are theirs. Revocation and hiding protect the **future** only. This is
  stated plainly in the removal dialog and docs.
- **A compromised endpoint device.** Device-level malware sees what the user sees.

### 9.2 Metadata

- Relay (Phase 2): social graph, timing, sizes (padding open — §9.2).
- LAN (Phase 1): presence of *a* Calendite device on the network is visible;
  identity/trackability mitigated by rotating derived service names (§7.2).

### 9.3 Web / Wasm

Not a sharing client in v1. When the web App version arrives: the browser is the
weakest platform regardless of ciphers — the server re-delivers the code every
page load (one malicious serve defeats E2E; cf. Signal's no-web stance,
WhatsApp's Code Verify), and there is no hardware key custody (non-extractable
`CryptoKey` resists export, not XSS *use*). Recommendation: web joins as
**view-only** first — a stolen read key leaks a calendar but cannot forge events
or membership. Maps to the Viewer role.

### 9.4 Implementation-level

- Pure-Kotlin/JS crypto has weaker constant-time guarantees than platform code —
  acceptable for the once-per-pairing KEM under a phone threat model; the hot
  path is hardware AES/ChaCha (§4.1.3).
- Anti-rollback: lane sequence numbers are monotonic per device; peers reject
  regressions via `LaneEnvelope.openAndValidate` + a `FreshnessStore` — per-lane
  strictly-increasing sequences and non-decreasing epochs, checked before
  decryption and recorded atomically only after the AEAD verifies. A retired
  epoch key therefore cannot authenticate new ops once a newer epoch has been
  seen on the lane. What stays with the consumer: durable, rollback-protected
  persistence of the freshness state, gap policy (suppression vs. reordering),
  and only honouring lanes of currently-active members.

---

