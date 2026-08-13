package org.layeredencryption

/**
 * Hybrid Ed25519 + ML-DSA-65 signatures: the signing counterpart to [XWing].
 *
 * ```
 * Ed25519 (classical) ─┐
 *                      ├─ both signatures required ──> accepted
 * ML-DSA-65 (PQ)      ─┘
 * ```
 *
 * ### Why there is no combiner here
 * [XWing] needs a carefully specified combiner because a KEM's two shared secrets must be mixed
 * into one key without losing the binding to the public keys. Signatures have the opposite shape:
 * each leg is verified independently and [verify] accepts only when **both** legs pass. An attacker
 * therefore has to forge Ed25519 *and* ML-DSA-65 over the same message, so the construction is as
 * strong as whichever leg survives. Inventing a combiner would add design risk and buy nothing.
 *
 * This is the mirror image of the KEM's guarantee, and worth stating precisely because the two are
 * easy to conflate:
 * - [XWing]: an attacker must break **both** legs to *read* traffic.
 * - [HybridSignature]: an attacker must forge **both** legs to *impersonate* a device.
 *
 * ### What this does and does not protect
 * Signatures are authenticity, not confidentiality. A quantum computer that breaks Ed25519 in 2035
 * cannot use that to decrypt traffic recorded in 2026 — that threat is [XWing]'s job, and it is
 * already handled. What it could do is forge a device identity and impersonate a member from that
 * point on. The ML-DSA leg closes exactly that gap, which is why the protocol has no remaining
 * classical-only dependency.
 *
 * ### Deliberately not used per message
 * Nothing on the message path signs. Once two devices share a key, the cascade's AEAD tags already
 * prove a message came from a holder of that key, symmetrically and therefore without a quantum
 * weakness of their own. Signing every message would add 3.3 KB and buy no assurance. Signatures
 * appear only where a third party must verify something *without* holding the shared key: a device
 * identity, a membership log entry, and an async invite bundle.
 *
 * ### Why not a standard composite
 * Bouncy Castle 1.81 ships `MLDSA65_Ed25519_SHA512` from the IETF LAMPS composite-signatures draft.
 * It is not used here for three reasons: it is a draft rather than a standard; it is exposed only
 * through the JCA layer, while this provider deliberately uses the lightweight API so it never
 * touches Android's repackaged Bouncy Castle; and the iOS actual will obtain Ed25519 and ML-DSA
 * from CryptoKit as separate primitives, with no composite to call. Concatenation is the portable
 * choice, and is simple enough to re-derive on any platform from this file alone.
 *
 * ### Encoding
 * Fixed-width concatenation, classical leg first, so every field can be split by offset with no
 * length prefixes to disagree about across platforms:
 *
 * - public key = `ed25519_pk(32) ‖ mldsa65_pk(1952)`     = 1984 B
 * - secret key = `ed25519_sk(32) ‖ mldsa65_sk(4032)`     = 4064 B
 * - signature  = `ed25519_sig(64) ‖ mldsa65_sig(3309)`   = 3373 B
 */
object HybridSignature {

    const val ED25519_PUBLIC_SIZE = 32
    const val ED25519_SIGNATURE_SIZE = 64
    const val MLDSA65_PUBLIC_SIZE = 1952
    const val MLDSA65_SIGNATURE_SIZE = 3309

    /** 1984 B: the classical public key followed by the post-quantum one. */
    const val PUBLIC_KEY_SIZE = ED25519_PUBLIC_SIZE + MLDSA65_PUBLIC_SIZE

    /** 3373 B: the classical signature followed by the post-quantum one. */
    const val SIGNATURE_SIZE = ED25519_SIGNATURE_SIZE + MLDSA65_SIGNATURE_SIZE

    /** Generates both legs independently and concatenates them. */
    fun generateKeyPair(provider: CryptoProvider): KeyPair {
        val classical = provider.ed25519GenerateKeyPair()
        val postQuantum = provider.mlDsa65GenerateKeyPair()
        return KeyPair(
            publicKey = classical.publicKey + postQuantum.publicKey,
            privateKey = classical.privateKey + postQuantum.privateKey,
        )
    }

    /** Signs [message] with both legs. The same bytes go to each; neither leg sees the other's output. */
    fun sign(provider: CryptoProvider, privateKey: ByteArray, message: ByteArray): ByteArray {
        val classical = provider.ed25519Sign(classicalSecret(privateKey), message)
        val postQuantum = provider.mlDsa65Sign(postQuantumSecret(privateKey), message)
        return classical + postQuantum
    }

    /**
     * Verifies both legs, and accepts only if both pass.
     *
     * A malformed signature or public key is a rejection rather than an exception: callers treat a
     * `false` here as "reject this identity", and a length mismatch is just one more way for a
     * signature to be wrong.
     */
    fun verify(
        provider: CryptoProvider,
        publicKey: ByteArray,
        message: ByteArray,
        signature: ByteArray,
    ): Boolean {
        if (publicKey.size != PUBLIC_KEY_SIZE) return false
        if (signature.size != SIGNATURE_SIZE) return false
        val classicalOk = provider.ed25519Verify(
            classicalPublic(publicKey), message, signature.copyOfRange(0, ED25519_SIGNATURE_SIZE),
        )
        val postQuantumOk = provider.mlDsa65Verify(
            postQuantumPublic(publicKey), message, signature.copyOfRange(ED25519_SIGNATURE_SIZE, signature.size),
        )
        return classicalOk && postQuantumOk
    }

    /** The Ed25519 half of a hybrid public key. */
    fun classicalPublic(publicKey: ByteArray): ByteArray {
        require(publicKey.size == PUBLIC_KEY_SIZE) { "Not a hybrid public key" }
        return publicKey.copyOfRange(0, ED25519_PUBLIC_SIZE)
    }

    /** The ML-DSA-65 half of a hybrid public key. */
    fun postQuantumPublic(publicKey: ByteArray): ByteArray {
        require(publicKey.size == PUBLIC_KEY_SIZE) { "Not a hybrid public key" }
        return publicKey.copyOfRange(ED25519_PUBLIC_SIZE, publicKey.size)
    }

    private fun classicalSecret(privateKey: ByteArray): ByteArray {
        require(privateKey.size > ED25519_PUBLIC_SIZE) { "Hybrid secret key too short" }
        return privateKey.copyOfRange(0, ED25519_PUBLIC_SIZE)
    }

    private fun postQuantumSecret(privateKey: ByteArray): ByteArray {
        require(privateKey.size > ED25519_PUBLIC_SIZE) { "Hybrid secret key too short" }
        return privateKey.copyOfRange(ED25519_PUBLIC_SIZE, privateKey.size)
    }
}
