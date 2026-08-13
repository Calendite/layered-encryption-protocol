package org.layeredencryption.invite

import org.layeredencryption.CryptoProvider
import org.layeredencryption.identity.DeviceIdentity
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/**
 * The async invite link (Async_Invites_Spec.md §2.2):
 *
 * ```
 * https://calendite.com/join#A2.<secret>.<fp>
 * ```
 *
 * - `A2` — async-invite v2 tag (disambiguates from live-code links).
 * - `secret` — 32 CSPRNG bytes, base64url unpadded (43 chars).
 * - `fp` — first 16 bytes of `SHA-256(ed25519_pk_A)`, base64url unpadded (22 chars). Pins the
 *   inviter's identity so a relay that swaps the bundle is caught (§2.7 step 2).
 *
 * `A2` replaces the 8-byte-secret `A1` format (LEP-01). `rid_async` is a hash of the secret that
 * the relay necessarily sees, which makes it an **offline** verifier for secret guesses: at 64 bits
 * a GPU farm could cover the keyspace within an invite's lifetime. At 256 bits the same attack is
 * out of reach, and the secret travels in a link/QR code so the extra length costs nothing.
 * `A1` links no longer parse; any pending ones must be regenerated.
 *
 * The whole payload lives in the URL **fragment**, so it never reaches any web server (design §6.4).
 * Parsing is strict: exact tag, exact field count, exact decoded lengths — anything else is rejected.
 */
class InviteLink(val secret: ByteArray, val fingerprint: ByteArray) {

    /** The `A2.<secret>.<fp>` fragment payload (without the URL prefix). */
    fun fragment(): String = "$TAG.${b64(secret)}.${b64(fingerprint)}"

    /** The full shareable URL. */
    fun url(): String = "$URL_PREFIX${fragment()}"

    companion object {
        const val TAG = "A2"
        const val SECRET_SIZE = 32
        private const val URL_PREFIX = "https://calendite.com/join#"
        private const val FINGERPRINT_SIZE = 16

        /** Builds a link for a fresh [secret] and the inviter's identity (fingerprint derived here). */
        fun create(provider: CryptoProvider, secret: ByteArray, inviterIdentity: DeviceIdentity): InviteLink {
            require(secret.size == SECRET_SIZE) { "Invite secret must be $SECRET_SIZE bytes" }
            return InviteLink(secret, fingerprintOf(provider, inviterIdentity))
        }

        /** The 16-byte fingerprint of an identity: `SHA-256(ed25519_pk)[0..16]`. */
        fun fingerprintOf(provider: CryptoProvider, identity: DeviceIdentity): ByteArray =
            provider.sha256(identity.signingPublicKey).copyOfRange(0, FINGERPRINT_SIZE)

        /**
         * Strictly parses a fragment payload (`A2.<secret>.<fp>`), or returns `null` if malformed.
         * Legacy `A1` links are rejected here by the tag check — their 64-bit secrets are
         * brute-forceable offline (LEP-01) and must not be honoured.
         */
        fun parse(fragment: String): InviteLink? {
            val body = fragment.substringAfter('#', fragment) // tolerate a full URL or bare fragment
            val parts = body.split('.')
            if (parts.size != 3 || parts[0] != TAG) return null
            val secret = decode(parts[1], SECRET_SIZE) ?: return null
            val fingerprint = decode(parts[2], FINGERPRINT_SIZE) ?: return null
            return InviteLink(secret, fingerprint)
        }

        @OptIn(ExperimentalEncodingApi::class)
        private val B64 = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT)

        @OptIn(ExperimentalEncodingApi::class)
        private fun b64(bytes: ByteArray): String = B64.encode(bytes)

        @OptIn(ExperimentalEncodingApi::class)
        private fun decode(text: String, expectedSize: Int): ByteArray? {
            val bytes = runCatching { B64.decode(text) }.getOrNull() ?: return null
            return if (bytes.size == expectedSize) bytes else null
        }
    }
}
