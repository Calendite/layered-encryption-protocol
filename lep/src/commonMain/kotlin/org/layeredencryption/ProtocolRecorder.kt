package org.layeredencryption

/**
 * Records what a ceremony actually did, so it can be inspected afterwards.
 *
 * Optional and off by default: production passes nothing and the calls compile away to null
 * checks. It exists because a protocol whose failures are "the signature did not verify" is
 * nearly impossible to debug from the outside, and because a second implementation needs
 * something concrete to be written against.
 *
 * **Nothing secret may pass through here.** Not the master key, not a private key, not a raw
 * shared secret. Public values, byte counts, label names and digests only. That rule is enforced
 * by a test that holds the real secrets from a recorded run and asserts none of them occurs in
 * the output, rather than by everyone remembering it.
 */
interface ProtocolRecorder {

    /** One message crossing the channel. */
    fun message(step: RecordedMessage)

    /** A value derived from key material: the label used, never the material or the result. */
    fun derivation(label: String, from: String, produces: String)

    /** Bytes that both sides must compute identically (a transcript, an AAD, a signed payload). */
    fun agreedBytes(name: String, bytes: ByteArray, composition: List<RecordedField>)

    /** Something worth saying in prose at this point in the ceremony. */
    fun note(text: String)

    /** The outcome, once the ceremony has either finished or failed. */
    fun outcome(succeeded: Boolean, detail: String)
}

/** One field within a message or a composed byte string. */
class RecordedField(
    val name: String,
    val bytes: Int,
    /** A digest or a public value; never key material. */
    val value: String,
    val algorithm: String? = null,
    val note: String? = null,
)

class RecordedMessage(
    val name: String,
    val tag: Int,
    /** `"inviter"` or `"joiner"`: who sent it. */
    val from: String,
    val sizeBytes: Int,
    val fields: List<RecordedField>,
    val algorithms: List<String> = emptyList(),
    val establishes: String? = null,
    val elapsedMillis: Long = 0,
)
