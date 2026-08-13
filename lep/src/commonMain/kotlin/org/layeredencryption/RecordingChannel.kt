package org.layeredencryption

import org.layeredencryption.identity.DeviceIdentity
import org.layeredencryption.pairing.PairingWire

/**
 * A [FrameChannel] that reports every frame crossing it to a [ProtocolRecorder].
 *
 * Recording lives here, at the transport, rather than inside the ceremony. Two reasons, and the
 * second matters more than the first:
 *
 * 1. The protocol code stays untouched, so instrumenting a run cannot change what it does.
 * 2. This decorator sees exactly what a wiretap would see and nothing else. "No key material in
 *    the recording" is therefore structural rather than a rule somebody has to keep remembering:
 *    there is no path from here to a private key.
 *
 * Wrap either side of a ceremony:
 *
 * ```kotlin
 * PairingFerry.runInviter(RecordingChannel(socket, recorder, "inviter", provider), inviter, ::askUser)
 * ```
 */
class RecordingChannel(
    private val delegate: FrameChannel,
    private val recorder: ProtocolRecorder,
    /** Which side this channel belongs to, so a frame can be attributed to its sender. */
    private val side: String,
    private val provider: CryptoProvider,
    private val clock: () -> Long = { 0 },
) : FrameChannel {

    private val other: String get() = if (side == "inviter") "joiner" else "inviter"
    private var lastAt: Long = clock()

    override suspend fun send(frame: ByteArray) {
        delegate.send(frame)
        record(frame, from = side)
    }

    override suspend fun receive(): ByteArray = delegate.receive().also { record(it, from = other) }

    override fun close() = delegate.close()

    private fun record(frame: ByteArray, from: String) {
        val now = clock()
        val elapsed = now - lastAt
        lastAt = now
        recorder.message(describe(frame, from, elapsed))
    }

    private fun digest(bytes: ByteArray): String = provider.sha256(bytes).toHexString().take(16)

    /**
     * Decodes a frame far enough to describe it. Anything that will not decode is still reported,
     * as an unreadable frame of a known size, because "the bytes were garbage" is itself the most
     * useful thing an inspector can say.
     */
    private fun describe(frame: ByteArray, from: String, elapsed: Long): RecordedMessage {
        val tag = if (frame.isEmpty()) -1 else frame[0].toInt()
        return runCatching {
            when (tag) {
                PairingWire.TAG_INVITER_HELLO -> {
                    val hello = PairingWire.decodeInviterHello(frame)
                    RecordedMessage(
                        name = "InviterHello", tag = tag, from = from, sizeBytes = frame.size,
                        algorithms = listOf("ML-KEM-768 keygen", "X25519 keygen"),
                        establishes = "nothing yet: an identity has been carried, not believed",
                        elapsedMillis = elapsed,
                        fields = listOf(
                            field("xWingPublicKey", hello.xWingPublicKey, "ML-KEM-768 + X25519",
                                "Two public keys concatenated in the order X-Wing specifies. Reversing them is a silent interop failure."),
                            identityField(hello.inviterDeviceIdentity),
                        ),
                    )
                }
                PairingWire.TAG_JOINER_RESPONSE -> {
                    val response = PairingWire.decodeJoinerResponse(frame)
                    RecordedMessage(
                        name = "JoinerResponse", tag = tag, from = from, sizeBytes = frame.size,
                        algorithms = listOf("ML-KEM-768 encapsulation", "X25519 agreement", "HKDF-SHA256"),
                        establishes = "a shared secret exists on both sides, unauthenticated; no key released",
                        elapsedMillis = elapsed,
                        fields = listOf(
                            field("kemCiphertext", response.kemCiphertext, "ML-KEM-768",
                                "The encapsulation. Both legs are combined by the X-Wing combiner, so a broken leg cannot choose the output."),
                            identityField(response.joinerDeviceIdentity),
                            field("joinerMac", response.joinerMac, "HMAC-SHA256",
                                "Proves the joiner holds the typed pairing code without revealing it."),
                        ),
                    )
                }
                PairingWire.TAG_INVITER_CONFIRM -> {
                    val confirm = PairingWire.decodeInviterConfirm(frame)
                    RecordedMessage(
                        name = "InviterConfirm", tag = tag, from = from, sizeBytes = frame.size,
                        algorithms = listOf("HMAC-SHA256"),
                        establishes = "the inviter proved it holds the same code and transcript",
                        elapsedMillis = elapsed,
                        fields = listOf(field("inviterMac", confirm.inviterMac, "HMAC-SHA256",
                            "Computed over the transcript with the inviter's role label, so echoing the joiner's MAC back does not work.")),
                    )
                }
                PairingWire.TAG_SAS_CONFIRMED -> RecordedMessage(
                    name = "SasConfirmed", tag = tag, from = from, sizeBytes = frame.size,
                    algorithms = listOf("no algorithm: a person"),
                    establishes = "both humans agree they are talking to each other",
                    elapsedMillis = elapsed,
                    fields = emptyList(),
                )
                PairingWire.TAG_INVITER_COMPLETE -> {
                    val complete = PairingWire.decodeInviterComplete(frame)
                    RecordedMessage(
                        name = "InviterComplete", tag = tag, from = from, sizeBytes = frame.size,
                        algorithms = listOf("ChaCha20-Poly1305", "AES-256-GCM", "Ed25519", "ML-DSA-65"),
                        establishes = "paired: both hold the master key, neither sent it in the clear",
                        elapsedMillis = elapsed,
                        fields = listOf(
                            field("membershipLog", complete.membershipLog, "Ed25519 + ML-DSA-65 + SHA-256 + cascade",
                                "Hash-chained and signed, and it carries the master key wrapped under K_handshake. " +
                                    "The key itself never crosses the wire, and the joiner verifies the chain from genesis before honouring any of it."),
                        ),
                    )
                }
                else -> unreadable(frame, from, elapsed, "unknown tag $tag")
            }
        }.getOrElse { failure ->
            unreadable(frame, from, elapsed, failure.message ?: "would not decode")
        }
    }

    private fun unreadable(frame: ByteArray, from: String, elapsed: Long, why: String) = RecordedMessage(
        name = "unreadable frame", tag = if (frame.isEmpty()) -1 else frame[0].toInt(),
        from = from, sizeBytes = frame.size, elapsedMillis = elapsed,
        establishes = "nothing: $why",
        fields = listOf(RecordedField("raw", frame.size, digest(frame), note = why)),
    )

    private fun field(name: String, bytes: ByteArray, algorithm: String? = null, note: String? = null) =
        RecordedField(name = name, bytes = bytes.size, value = digest(bytes), algorithm = algorithm, note = note)

    private fun identityField(identity: DeviceIdentity) = RecordedField(
        name = "deviceIdentity",
        bytes = identity.serialise().size,
        value = identity.signingPublicKey.toHexString().take(16),
        algorithm = "Ed25519 + ML-DSA-65 + X25519",
        note = "A certificate, not a bare key: a hybrid Ed25519 + ML-DSA-65 signing key, an X25519 identity key, and a signature over both binding them together.",
    )
}
