package org.layeredencryption

/**
 * The domain-separation namespace every label in the protocol is built from.
 *
 * Labels are not decoration. They are the `info` and `salt` inputs to HKDF and the prefixes of
 * signed transcripts, so **one changed character re-derives every key and invalidates every
 * existing pairing**. Two implementations that disagree about a single byte here produce
 * different keys and identical-looking code, which is among the hardest classes of bug to see.
 *
 * That is also why the namespace is a value rather than a constant. Two applications built on
 * this library *should* have incompatible key derivation: a device paired for one has no business
 * decrypting data from the other, even by accident. Passing your own vendor token is how you get
 * that separation for free.
 *
 * ```kotlin
 * val namespace = ProtocolNamespace("mycoolapp")   // labels become mycoolapp/v1/...
 * Cascade.seal(provider, key, plaintext, aad, namespace)
 * ```
 *
 * [Default] is `calendite`, the application this library was extracted from. It is the default
 * purely so that devices already paired in the field keep working; new adopters should pass their
 * own token, and two deployments that do will never derive the same key from the same secret.
 */
class ProtocolNamespace(val vendor: String = DEFAULT_VENDOR) {

    init {
        require(vendor.isNotBlank()) { "A namespace vendor token cannot be blank" }
        require(!vendor.contains('/')) { "A vendor token is one path segment, without '/'" }
    }

    /**
     * `"$vendor/$suffix"` as bytes.
     *
     * Callers pass the whole remaining path rather than a bare name because the shipped labels
     * are not uniformly shaped: most read `vendor/v1/thing`, a few read `vendor/thing/v1`. That
     * inconsistency is a historical accident, and it is frozen, so it stays visible at the call
     * site instead of being tidied away into a scheme that would silently change bytes.
     */
    fun label(suffix: String): ByteArray = "$vendor/$suffix".encodeToByteArray()

    override fun equals(other: Any?): Boolean = other is ProtocolNamespace && other.vendor == vendor

    override fun hashCode(): Int = vendor.hashCode()

    override fun toString(): String = "ProtocolNamespace($vendor)"

    companion object {
        /**
         * The vendor token of the application this library came from. Frozen: devices paired
         * against it derive their keys from these exact bytes.
         */
        const val DEFAULT_VENDOR = "calendite"

        val Default = ProtocolNamespace(DEFAULT_VENDOR)
    }
}
