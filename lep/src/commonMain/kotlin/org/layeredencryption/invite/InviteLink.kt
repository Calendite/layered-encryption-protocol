package org.layeredencryption.invite

import org.layeredencryption.CryptoProvider
import org.layeredencryption.identity.DeviceIdentity
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/**
 * The async invite link (Async_Invites_Spec.md §2.2):
 *
 * ```
 * https://calendite.com/join#A1.<secret>.<fp>
 * ```
 *
 * - `A1` — async-invite v1 tag (disambiguates from live-code links).
 * - `secret` — 8 CSPRNG bytes, base64url unpadded (11 chars).
 * - `fp` — first 16 bytes of `SHA-256(ed25519_pk_A)`, base64url unpadded (22 chars). Pins the
 *   inviter's identity so a relay that swaps the bundle is caught (§2.7 step 2).
 *
 * The whole payload lives in the URL **fragment**, so it never reaches any web server (design §6.4).
 * Parsing is strict: exact tag, exact field count, exact decoded lengths — anything else is rejected.
 */
class InviteLink(val secret: ByteArray, val fingerprint: ByteArray) {

    /** The `A1.<secret>.<fp>` fragment payload (without the URL prefix). */
    fun fragment(): String = "$TAG.${b64(secret)}.${b64(fingerprint)}"

    /** The full shareable URL. */
    fun url(): String = "$URL_PREFIX${fragment()}"

    companion object {
        const val TAG = "A1"
        private const val URL_PREFIX = "https://calendite.com/join#"
        private const val SECRET_SIZE = 8
        private const val FINGERPRINT_SIZE = 16

        /** Builds a link for a fresh [secret] and the inviter's identity (fingerprint derived here). */
        fun create(provider: CryptoProvider, secret: ByteArray, inviterIdentity: DeviceIdentity): InviteLink {
            require(secret.size == SECRET_SIZE) { "Invite secret must be $SECRET_SIZE bytes" }
            return InviteLink(secret, fingerprintOf(provider, inviterIdentity))
        }

        /** The 16-byte fingerprint of an identity: `SHA-256(ed25519_pk)[0..16]`. */
        fun fingerprintOf(provider: CryptoProvider, identity: DeviceIdentity): ByteArray =
            provider.sha256(identity.signingPublicKey).copyOfRange(0, FINGERPRINT_SIZE)

        /** Strictly parses a fragment payload (`A1.<secret>.<fp>`), or returns `null` if malformed. */
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
