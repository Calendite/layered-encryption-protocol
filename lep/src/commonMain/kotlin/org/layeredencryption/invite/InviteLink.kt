package org.layeredencryption.invite

import org.layeredencryption.CryptoProvider
import org.layeredencryption.identity.DeviceIdentity
import org.layeredencryption.identity.DeviceIdentityV2
import org.layeredencryption.suite.SuiteId
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/**
 * The async invite link (Async_Invites_Spec.md §2.2), in two versions:
 *
 * ```
 * https://calendite.com/join#A2.<secret>.<fp>          the Suite 1 flow, byte-frozen
 * https://calendite.com/join#A3.<sid>.<secret>.<fp>    the suited flow (migration brief §4)
 * ```
 *
 * - `A2` — async-invite v2 tag (disambiguates from live-code links).
 * - `A3` — the suited link: `sid` is the canonical decimal suite id of the bundle waiting at
 *   the rendezvous. The link travels out of band, so a relay cannot rewrite it — which makes
 *   the suite hint the joiner's downgrade guard: the fetched bundle's authenticated suite must
 *   equal the link's, and an `A3` link is assigned to the v2 bundle parser only (an `A2` link
 *   to the v1 parser only), never auto-detected.
 * - `secret` — 32 CSPRNG bytes, base64url unpadded (43 chars).
 * - `fp` — first 16 bytes of `SHA-256(signing_pk_A)`, base64url unpadded (22 chars). Pins the
 *   inviter's identity so a relay that swaps the bundle is caught (§2.7 step 2).
 *
 * `A2` replaces the 8-byte-secret `A1` format. `rid_async` is a hash of the secret that
 * the relay necessarily sees, which makes it an **offline** verifier for secret guesses: at 64 bits
 * a GPU farm could cover the keyspace within an invite's lifetime. At 256 bits the same attack is
 * out of reach, and the secret travels in a link/QR code so the extra length costs nothing.
 * `A1` links no longer parse; any pending ones must be regenerated.
 *
 * The whole payload lives in the URL **fragment**, so it never reaches any web server (design §6.4).
 * Parsing is strict: exact tag, exact field count, exact decoded lengths — anything else is rejected.
 * An `A3` suite id the application does not recognise is a *data* outcome, deliberately not a parse
 * failure: "update your app to join" is a different message from "this link is corrupt", and the
 * caller checks its registry before proceeding.
 */
class InviteLink(
    secret: ByteArray,
    fingerprint: ByteArray,
    /** The suited (`A3`) link's suite hint; null for a legacy `A2` link. */
    val suiteId: SuiteId? = null,
) {

    // Copied both ways: the link is the *application's* handle on the secret, deliberately not an
    // alias of the live inviter's array — mutating a link cannot corrupt an active invite, and an
    // invite scrubbing itself does not reach into links the app already rendered.
    private val _secret = secret.copyOf()
    private val _fingerprint = fingerprint.copyOf()

    val secret: ByteArray get() = _secret.copyOf()
    val fingerprint: ByteArray get() = _fingerprint.copyOf()

    /** The fragment payload (without the URL prefix): `A2.<secret>.<fp>` or `A3.<sid>.<secret>.<fp>`. */
    fun fragment(): String = when (suiteId) {
        null -> "$TAG.${b64(_secret)}.${b64(_fingerprint)}"
        else -> "$TAG_SUITED.${suiteId.value}.${b64(_secret)}.${b64(_fingerprint)}"
    }

    /** The full shareable URL. */
    fun url(): String = "$URL_PREFIX${fragment()}"

    companion object {
        const val TAG = "A2"
        const val TAG_SUITED = "A3"
        const val SECRET_SIZE = 32
        private const val URL_PREFIX = "https://calendite.com/join#"
        private const val FINGERPRINT_SIZE = 16

        /** Builds a legacy `A2` link for a fresh [secret] and the inviter's v1 identity. */
        fun create(provider: CryptoProvider, secret: ByteArray, inviterIdentity: DeviceIdentity): InviteLink {
            require(secret.size == SECRET_SIZE) { "Invite secret must be $SECRET_SIZE bytes" }
            return InviteLink(secret, fingerprintOf(provider, inviterIdentity))
        }

        /** Builds a suited `A3` link: the suite hint comes from the inviter's v2 identity. */
        fun createSuited(provider: CryptoProvider, secret: ByteArray, inviterIdentity: DeviceIdentityV2): InviteLink {
            require(secret.size == SECRET_SIZE) { "Invite secret must be $SECRET_SIZE bytes" }
            return InviteLink(secret, fingerprintOf(provider, inviterIdentity), inviterIdentity.suiteId)
        }

        /** The 16-byte fingerprint of an identity: `SHA-256(ed25519_pk)[0..16]`. */
        fun fingerprintOf(provider: CryptoProvider, identity: DeviceIdentity): ByteArray =
            fingerprintOfKey(provider, identity.signingPublicKey)

        /** The same fingerprint for a v2 identity — size-independent by construction. */
        fun fingerprintOf(provider: CryptoProvider, identity: DeviceIdentityV2): ByteArray =
            fingerprintOfKey(provider, identity.signingPublicKey)

        private fun fingerprintOfKey(provider: CryptoProvider, signingPublicKey: ByteArray): ByteArray =
            provider.sha256(signingPublicKey).copyOfRange(0, FINGERPRINT_SIZE)

        /**
         * Strictly parses a **bare** fragment payload, or returns `null` if malformed. Anything
         * URL-shaped (containing `#`, `/`, or `:`) is rejected here — full links go through
         * [parseUrl], which checks the origin. An earlier version took whatever followed `#`,
         * which accepted a link from any origin at all.
         *
         * `A2` parses exactly as it always has; `A3` additionally requires a canonical decimal
         * suite id (no sign, no leading zero, ≤ 65535). Legacy `A1` links are rejected by the
         * tag check — their 64-bit secrets are brute-forceable offline and must not be honoured.
         */
        fun parse(fragment: String): InviteLink? {
            if (fragment.any { it == '#' || it == '/' || it == ':' }) return null
            val parts = fragment.split('.')
            return when {
                parts.size == 3 && parts[0] == TAG -> {
                    val secret = decode(parts[1], SECRET_SIZE) ?: return null
                    val fingerprint = decode(parts[2], FINGERPRINT_SIZE) ?: return null
                    InviteLink(secret, fingerprint)
                }
                parts.size == 4 && parts[0] == TAG_SUITED -> {
                    val suiteId = canonicalSuiteId(parts[1]) ?: return null
                    val secret = decode(parts[2], SECRET_SIZE) ?: return null
                    val fingerprint = decode(parts[3], FINGERPRINT_SIZE) ?: return null
                    InviteLink(secret, fingerprint, suiteId)
                }
                else -> null
            }
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
