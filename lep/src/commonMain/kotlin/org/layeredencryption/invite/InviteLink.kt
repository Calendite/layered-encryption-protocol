package org.layeredencryption.invite

import org.layeredencryption.CryptoProvider
import org.layeredencryption.identity.DeviceIdentity
import org.layeredencryption.suite.SuiteId
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/**
 * The async invite link (Async_Invites_Spec.md §2.2):
 *
 * ```
 * https://calendite.com/join#A3.<sid>.<secret>.<fp>
 * ```
 *
 * - `A3` — the async-invite tag (disambiguates from live-code links; `A1`/`A2` are burned
 *   pre-release formats and no longer parse).
 * - `sid` — the canonical decimal suite id of the bundle waiting at the rendezvous. The link
 *   travels out of band, so a relay cannot rewrite it — which makes the suite hint the joiner's
 *   downgrade guard: the fetched bundle's authenticated suite must equal the link's.
 * - `secret` — 32 CSPRNG bytes, base64url unpadded (43 chars). `rid_async` is a hash of the
 *   secret that the relay necessarily sees — an **offline** verifier for secret guesses, which
 *   is why the secret is 256 bits.
 * - `fp` — first 16 bytes of `SHA-256(signing_pk_A)`, base64url unpadded (22 chars). Pins the
 *   inviter's identity so a relay that swaps the bundle is caught (§2.7 step 2).
 *
 * The whole payload lives in the URL **fragment**, so it never reaches any web server (design §6.4).
 * Parsing is strict: exact tag, exact field count, exact decoded lengths — anything else is rejected.
 * A suite id the application does not recognise is a *data* outcome, deliberately not a parse
 * failure: "update your app to join" is a different message from "this link is corrupt", and the
 * caller checks its registry before proceeding.
 */
class InviteLink(
    secret: ByteArray,
    fingerprint: ByteArray,
    /** The suite of the bundle this link points at — the joiner's out-of-band downgrade guard. */
    val suiteId: SuiteId,
) {

    // Copied both ways: the link is the *application's* handle on the secret, deliberately not an
    // alias of the live inviter's array — mutating a link cannot corrupt an active invite, and an
    // invite scrubbing itself does not reach into links the app already rendered.
    private val _secret = secret.copyOf()
    private val _fingerprint = fingerprint.copyOf()

    val secret: ByteArray get() = _secret.copyOf()
    val fingerprint: ByteArray get() = _fingerprint.copyOf()

    /** The fragment payload (without the URL prefix): `A3.<sid>.<secret>.<fp>`. */
    fun fragment(): String = "$TAG.${suiteId.value}.${b64(_secret)}.${b64(_fingerprint)}"

    /** The full shareable URL. */
    fun url(): String = "$URL_PREFIX${fragment()}"

    companion object {
        const val TAG = "A3"
        const val SECRET_SIZE = 32
        private const val URL_PREFIX = "https://calendite.com/join#"
        private const val FINGERPRINT_SIZE = 16

        /** Builds a link for a fresh [secret]: the suite hint comes from the inviter's identity. */
        fun create(provider: CryptoProvider, secret: ByteArray, inviterIdentity: DeviceIdentity): InviteLink {
            require(secret.size == SECRET_SIZE) { "Invite secret must be $SECRET_SIZE bytes" }
            return InviteLink(secret, fingerprintOf(provider, inviterIdentity), inviterIdentity.suiteId)
        }

        /** The 16-byte fingerprint of an identity: `SHA-256(signing_pk)[0..16]` — size-independent. */
        fun fingerprintOf(provider: CryptoProvider, identity: DeviceIdentity): ByteArray =
            provider.sha256(identity.signingPublicKey).copyOfRange(0, FINGERPRINT_SIZE)

        /**
         * Strictly parses a **bare** fragment payload, or returns `null` if malformed. Anything
         * URL-shaped (containing `#`, `/`, or `:`) is rejected here — full links go through
         * [parseUrl], which checks the origin. An earlier version took whatever followed `#`,
         * which accepted a link from any origin at all.
         *
         * The suite id must be canonical decimal (no sign, no leading zero, ≤ 65535). The burned
         * `A1`/`A2` formats are rejected by the tag check.
         */
        fun parse(fragment: String): InviteLink? {
            if (fragment.any { it == '#' || it == '/' || it == ':' }) return null
            val parts = fragment.split('.')
            if (parts.size != 4 || parts[0] != TAG) return null
            val suiteId = canonicalSuiteId(parts[1]) ?: return null
            val secret = decode(parts[2], SECRET_SIZE) ?: return null
            val fingerprint = decode(parts[3], FINGERPRINT_SIZE) ?: return null
            return InviteLink(secret, fingerprint, suiteId)
        }

        /**
         * Strictly parses a full invite URL, requiring the exact canonical origin and path
         * (`https://calendite.com/join#…`) before the fragment is even looked at.
         */
        fun parseUrl(url: String): InviteLink? {
            if (!url.startsWith(URL_PREFIX)) return null
            return parse(url.removePrefix(URL_PREFIX))
        }

        /** Exactly the digits `UShort.toString` produces: no sign, no leading zero, in range. */
        private fun canonicalSuiteId(text: String): SuiteId? {
            val value = text.toIntOrNull() ?: return null
            if (value < 0 || value > 0xFFFF || value.toString() != text) return null
            return SuiteId(value.toUShort())
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
