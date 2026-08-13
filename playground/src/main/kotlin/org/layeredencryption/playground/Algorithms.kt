package org.layeredencryption.playground

/**
 * Where each algorithm actually does its work.
 *
 * Written by reading the library rather than generated from it, so it can drift; the test
 * `AlgorithmMapTest` guards the claim that matters most, which is that nothing in the message
 * path signs anything.
 *
 * The panel exists because the obvious question after watching a message go through is "where is
 * the signature?", and the honest answer, that messages are not signed and here is why, is more
 * useful than a badge that pretends otherwise.
 */
class AlgorithmUse(
    val name: String,
    val postQuantum: Boolean,
    val whenUsed: String,
    val what: String,
)

val ALGORITHM_MAP = listOf(
    AlgorithmUse(
        "ML-KEM-768", postQuantum = true, whenUsed = "pairing only",
        what = "The post-quantum half of the key agreement. Its job is traffic recorded today and " +
            "opened years later; it is not used again once the two devices share a key.",
    ),
    AlgorithmUse(
        "X25519", postQuantum = false, whenUsed = "pairing only",
        what = "The classical half of the same agreement. An attacker must break this as well as " +
            "ML-KEM, so a flaw in either one alone is survivable.",
    ),
    AlgorithmUse(
        "HKDF-SHA256", postQuantum = false, whenUsed = "pairing and every message",
        what = "Turns one master key into several independent keys, one per purpose, each under a " +
            "different label. Two labels differing by a character produce unrelated keys.",
    ),
    AlgorithmUse(
        "ChaCha20-Poly1305", postQuantum = false, whenUsed = "every message",
        what = "The inner encryption layer, and the inner authentication tag.",
    ),
    AlgorithmUse(
        "AES-256-GCM", postQuantum = false, whenUsed = "every message",
        what = "The outer layer over the top of it, under a separate key. Both tags are checked on " +
            "the way back, outer first.",
    ),
    AlgorithmUse(
        "HMAC-SHA256", postQuantum = false, whenUsed = "pairing only",
        what = "Proves each side typed the same pairing code, without either side revealing it.",
    ),
    AlgorithmUse(
        "Ed25519", postQuantum = false, whenUsed = "identity, membership and invites, never per message",
        what = "The classical half of every signature, always paired with ML-DSA-65. It signs the " +
            "things a third party has to verify without holding the shared key: a device's identity " +
            "certificate, each entry in the membership log, and an async invite bundle. Messages " +
            "are not signed, and do not need to be: once two devices share a key, the AEAD tags " +
            "already prove a message came from someone holding it, far more cheaply than a " +
            "signature per message would.",
    ),
    AlgorithmUse(
        "ML-DSA-65", postQuantum = true, whenUsed = "alongside Ed25519, everywhere a signature appears",
        what = "The post-quantum half of every signature. Both halves must verify or the signature " +
            "is rejected, so forging an identity means breaking Ed25519 and ML-DSA-65 at once. " +
            "Note the difference from the key agreement: a broken Ed25519 would not decrypt old " +
            "traffic, it would let an attacker impersonate a device from then on, and this is what " +
            "stops that. Category 3, matching ML-KEM-768, so neither side of the protocol is the " +
            "weak one.",
    ),
    AlgorithmUse(
        "SHA-256", postQuantum = false, whenUsed = "throughout",
        what = "Hash chaining in the membership log, the context id, and the digests shown on this page.",
    ),
)
