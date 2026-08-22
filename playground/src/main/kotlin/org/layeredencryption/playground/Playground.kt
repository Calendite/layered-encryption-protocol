package org.layeredencryption.playground

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import kotlinx.coroutines.runBlocking
import org.layeredencryption.BouncyCastleCryptoProvider
import org.layeredencryption.Cascade
import org.layeredencryption.CryptoProvider
import org.layeredencryption.FrameChannel
import org.layeredencryption.ProtocolNamespace
import org.layeredencryption.ProtocolRecorder
import org.layeredencryption.RecordedField
import org.layeredencryption.RecordedMessage
import org.layeredencryption.RecordingChannel
import org.layeredencryption.bytesToInt
import org.layeredencryption.envelope.EpochKeys
import org.layeredencryption.envelope.LaneEnvelope
import org.layeredencryption.identity.DeviceKeys
import org.layeredencryption.intToBytes
import org.layeredencryption.pairing.ContextId
import org.layeredencryption.pairing.Inviter
import org.layeredencryption.pairing.Joiner
import org.layeredencryption.pairing.PairingCode
import org.layeredencryption.pairing.PairingFerry
import org.layeredencryption.toHexString
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.Executors
import kotlin.concurrent.thread

/**
 * Two devices, two real TCP ports, one message.
 *
 * Type something into the page, and it is sealed on device A, pushed down a socket, and opened on
 * device B, with every step of the journey reported as it happens. Nothing is simulated: the two
 * halves pair over the socket using the real ceremony, and the bytes on the wire are the bytes the
 * library produced.
 *
 * It exists because "your data is encrypted" is a claim, and watching your own sentence turn into
 * a sealed blob, cross a socket, and come back is the shortest route to believing it or catching
 * us out.
 */

private const val WEB_PORT = 8088
private const val DEVICE_A_PORT = 8089
private const val DEVICE_B_PORT = 8090

private val provider: CryptoProvider = BouncyCastleCryptoProvider()
private val namespace = ProtocolNamespace("playground")
private val events = EventLog()

fun main() {
    val session = pairTwoDevices()
    startWebServer(session)
    println("Playground on http://localhost:$WEB_PORT")
    println("Device A listens on $DEVICE_A_PORT, device B on $DEVICE_B_PORT")
}

/** One paired pair of devices, ready to carry messages. */
private class Session(
    val keys: EpochKeys,
    val contextId: String,
    val laneA: String,
) {
    var seq: Int = 0
}

/**
 * Runs the real pairing ceremony between two sockets, reporting each step.
 *
 * The devices are in one process, but they are not talking through memory: device B dials device
 * A's port, and every frame of the ceremony crosses a real socket.
 */
private fun pairTwoDevices(): Session {
    val listener = ServerSocket(DEVICE_A_PORT)
    val code = PairingCode.generate(provider)
    events.add("pairing", "A", "Pairing code generated", "Device A is listening on port $DEVICE_A_PORT. The code the other device must be told: ${code.display}")

    val inviterKeys = DeviceKeys.generate(provider)
    val joinerKeys = DeviceKeys.generate(provider)

    lateinit var result: PairingFerry.PairingResult
    val inviterThread = thread {
        listener.accept().use { socket ->
            runBlocking {
                // The library's own recorder decodes each frame, so the pairing section is
                // described by the protocol rather than by this demo guessing.
                result = PairingFerry.runInviter(
                    RecordingChannel(SocketChannel(socket, "A"), PairingRecorder(events), "inviter", provider),
                    provider, inviterKeys, code,
                    confirmSas = { sas ->
                        events.add("pairing", "A", "Short authentication string", "Device A shows $sas")
                        true
                    },
                )
            }
        }
    }
    Thread.sleep(120)
    Socket("127.0.0.1", DEVICE_A_PORT).use { socket ->
        runBlocking {
            PairingFerry.runJoiner(
                SocketChannel(socket, "B"),
                provider, joinerKeys, code,
                confirmSas = { sas ->
                    events.add("pairing", "B", "Short authentication string", "Device B shows $sas; both humans compare and confirm")
                    true
                },
            )
        }
    }
    inviterThread.join()
    listener.close()

    val contextId = ContextId.forCalendar(provider, result.membershipLog, namespace)
    val lane = "device-" + provider.sha256(inviterKeys.identity.signingPublicKey).toHexString().take(16)
    events.add("pairing", "both", "Paired", "Both devices hold the same master key; context ${contextId.take(16)}…")
    return Session(result.calendarKeys, contextId, lane)
}

/** A [FrameChannel] over a plain socket, using the library's own length framing. */
private class SocketChannel(private val socket: Socket, private val side: String) : FrameChannel {
    private val input = socket.getInputStream()
    private val output = socket.getOutputStream()

    override suspend fun send(frame: ByteArray) {
        // No event here: RecordingChannel wraps this one and describes each frame properly.
        output.write(intToBytes(frame.size))
        output.write(frame)
        output.flush()
    }

    override suspend fun receive(): ByteArray {
        val header = ByteArray(4).also { readFully(it) }
        val frame = ByteArray(bytesToInt(header, 0)).also { readFully(it) }
        return frame
    }

    override fun close() = Unit

    private fun readFully(into: ByteArray) {
        var read = 0
        while (read < into.size) {
            val count = input.read(into, read, into.size - read)
            if (count < 0) throw IllegalStateException("socket closed mid-frame")
            read += count
        }
    }
}

/**
 * Sends one message from A to B over a fresh socket, narrating every transformation.
 *
 * [tamper] flips a single bit in transit, which is the most instructive thing this page can do:
 * the cascade's tags fail, the message is rejected, and nothing half-decrypted comes out.
 */
private fun sendMessage(session: Session, text: String, tamper: Boolean) {
    events.clearMessages()
    events.lastTampered = tamper
    val plaintext = text.encodeToByteArray()

    events.add(
        "message", "A", "Typed", "Your words, as bytes, before anything has happened to them",
        parts = listOf(Part("plaintext", plaintext.size, note = "readable: this is what an attacker wants")),
        hex = plaintext.toHexString(), text = text,
    )

    // The header comes first, because the encryption is bound to it. Showing the sealing before
    // the addressing would be a tidier story and the wrong one.
    val header = LaneEnvelope(
        LaneEnvelope.VERSION, session.contextId, session.laneA, session.seq,
        session.keys.current, ByteArray(0),
    )
    events.add(
        "message", "A", "Addressed",
        "A routing header, in the clear, so a relay can carry this without being able to read it. " +
            "It is written in canonical length-prefixed framing and then bound into the encryption " +
            "below as associated data, which is what makes moving the message to another lane or " +
            "sequence number break decryption rather than succeed quietly.",
        algorithms = listOf("canonical framing"),
        parts = listOf(
            Part("version", 1, header.version.toString()),
            Part("context", header.contextId.length, header.contextId.take(16) + "…", "which shared dataset this belongs to"),
            Part("lane", header.lane.length, header.lane, "which device wrote it"),
            Part("seq", header.seq.toString().length, header.seq.toString(), "its position in that device's log"),
        ),
    )

    val envelope = LaneEnvelope.seal(
        provider, session.keys, session.contextId, session.laneA, session.seq++, plaintext,
        namespace = namespace,
    )
    val sealed = envelope.ciphertext
    events.add(
        "message", "A", "Sealed",
        "Encrypted twice under independent keys, each derived from the master key by HKDF with a " +
            "different label, and both bound to the header above. Reading it needs both ciphers " +
            "broken, not one.",
        algorithms = listOf("HKDF-SHA256", "ChaCha20-Poly1305", "AES-256-GCM"),
        parts = listOf(
            Part("inner nonce", 12, sealed.toHexString().take(24), "fresh per message, for the ChaCha20 layer"),
            Part("outer nonce", 12, sealed.toHexString().drop(24).take(24), "fresh per message, for the AES layer"),
            Part("ciphertext + 2 tags", sealed.size - 24, note = "${plaintext.size} B of plaintext, plus a 16 B tag from each layer"),
        ),
        hex = sealed.toHexString(),
    )

    val wire = envelope.serialise()
    events.add(
        "message", "A", "Framed for the wire",
        "Header and sealed payload written as one length-prefixed frame, ready for any transport " +
            "that can carry bytes.",
        algorithms = listOf("canonical framing"),
        parts = listOf(
            Part("header", wire.size - sealed.size, note = "plaintext, and bound into the ciphertext"),
            Part("sealed payload", sealed.size, note = "the only part that is secret"),
        ),
        hex = wire.toHexString(),
    )

    val listener = ServerSocket(DEVICE_B_PORT)
    var received: ByteArray? = null
    val receiver = thread {
        listener.accept().use { socket ->
            val header = ByteArray(4)
            socket.getInputStream().readNBytes(header, 0, 4)
            received = socket.getInputStream().readNBytes(bytesToInt(header, 0))
        }
    }
    Thread.sleep(60)
    Socket("127.0.0.1", DEVICE_B_PORT).use { socket ->
        val onTheWire = if (tamper) wire.copyOf().also { it[it.size - 1] = (it[it.size - 1] + 1).toByte() } else wire
        socket.getOutputStream().apply { write(intToBytes(onTheWire.size)); write(onTheWire); flush() }
        events.add(
            "message", "wire", if (tamper) "In transit, tampered with" else "In transit",
            if (tamper) "One byte of the ciphertext was flipped on the way, the way an attacker or a " +
                "faulty link would. Everything else is untouched."
            else "${onTheWire.size} B crossed a TCP connection to port $DEVICE_B_PORT. This is all an " +
                "eavesdropper would see.",
            parts = listOf(Part("frame", onTheWire.size, note = "4-byte length prefix, then the envelope")),
            hex = onTheWire.toHexString(),
        )
    }
    receiver.join()
    listener.close()

    val arrived = received ?: run {
        events.lastVerdict = "nothing arrived"
        events.lastDelivered = false
        events.add("message", "B", "Nothing arrived", "the socket closed early", failed = true)
        return
    }
    val firstDifference = arrived.indices.firstOrNull { it >= wire.size || arrived[it] != wire[it] }
    events.add(
        "message", "B", "Received",
        if (firstDifference == null) "Byte-identical to what left device A."
        else "Byte $firstDifference differs from what left device A. Device B has no way to know that " +
            "by looking; it finds out by checking the tags.",
        parts = listOf(Part("frame", arrived.size)),
        hex = arrived.toHexString(),
    )

    val opened = runCatching { LaneEnvelope.deserialise(arrived).openWithoutReplayProtection(provider, session.keys, namespace) }
    opened.onSuccess { bytes ->
        events.lastVerdict = "delivered"
        events.lastDelivered = true
        events.add(
            "message", "B", "Opened",
            "The outer AES tag verified, then the inner ChaCha20 tag, and both were computed over the " +
                "routing header as well, so the header is proven to be the one the sender used. Note " +
                "what is absent: nothing was signed. Once two devices share a key, the tags already " +
                "prove the message came from someone holding it, and a signature per message would " +
                "cost more for no extra assurance.",
            algorithms = listOf("AES-256-GCM", "ChaCha20-Poly1305"),
            parts = listOf(Part("plaintext", bytes.size, note = "identical to what was typed")),
            hex = bytes.toHexString(), text = bytes.decodeToString(),
        )
    }.onFailure { failure ->
        events.lastVerdict = "rejected"
        events.lastDelivered = false
        events.add(
            "message", "B", "Rejected",
            "${failure.message}. No plaintext is returned on this path: the library fails closed " +
                "rather than handing back bytes it could not verify. A single flipped byte is enough.",
            algorithms = listOf("AES-256-GCM"),
            failed = true,
        )
    }
}

private fun startWebServer(session: Session) {
    val server = HttpServer.create(InetSocketAddress(WEB_PORT), 0)
    server.executor = Executors.newFixedThreadPool(4)

    server.createContext("/") { exchange ->
        respond(exchange, 200, "text/html; charset=utf-8", PLAYGROUND_PAGE)
    }
    server.createContext("/send") { exchange ->
        val body = exchange.requestBody.readBytes().decodeToString()
        val text = body.substringAfter("text=", "").substringBefore("&tamper").let(::urlDecode)
        val tamper = body.contains("tamper=true")
        runCatching { sendMessage(session, text.ifBlank { "(nothing typed)" }, tamper) }
            .onFailure { events.add("message", "wire", "Failed", it.message ?: "unknown error", failed = true) }
        respond(exchange, 200, "application/json", """{"ok":true}""")
    }
    server.createContext("/events") { exchange ->
        respond(exchange, 200, "application/json", events.asJson())
    }
    server.start()
}

private fun respond(exchange: HttpExchange, status: Int, type: String, body: String) {
    val bytes = body.encodeToByteArray()
    exchange.responseHeaders.add("Content-Type", type)
    exchange.sendResponseHeaders(status, bytes.size.toLong())
    exchange.responseBody.use { it.write(bytes) }
}

private fun urlDecode(value: String): String =
    java.net.URLDecoder.decode(value, Charsets.UTF_8)
