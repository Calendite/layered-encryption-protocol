package org.layeredencryption

/**
 * Unambiguous binary framing for the sharing protocol.
 *
 * Every variable-length field is written with a 4-byte big-endian length prefix, so concatenated
 * fields can never be confused for one another. This matters because these byte strings are hashed,
 * signed, and MAC'd (transcripts §4.5, membership entries §4.7): without length-prefixing, an
 * attacker could shift bytes between adjacent fields and produce a different logical message with an
 * identical serialisation.
 */
class FrameWriter {
    private val chunks = mutableListOf<ByteArray>()

    fun putBytes(value: ByteArray): FrameWriter {
        chunks.add(intToBytes(value.size))
        chunks.add(value)
        return this
    }

    fun putByte(value: Int): FrameWriter {
        chunks.add(byteArrayOf(value.toByte()))
        return this
    }

    fun toByteArray(): ByteArray {
        val total = chunks.sumOf { it.size }
        val out = ByteArray(total)
        var offset = 0
        for (chunk in chunks) {
            chunk.copyInto(out, offset)
            offset += chunk.size
        }
        return out
    }
}

/**
 * Reads back a byte stream produced by [FrameWriter].
 *
 * All bounds arithmetic is checked subtraction (`length <= data.size - position`), never
 * `position + length`, because a hostile 4-byte length can be up to `Int.MAX_VALUE` and addition
 * would wrap negative and slip past the guard. Every failure is an [IllegalArgumentException];
 * no input reaches the copy with out-of-range indices.
 */
class FrameReader(private val data: ByteArray) {
    private var position = 0

    fun readByte(): Int {
        require(data.size - position >= 1) { "Frame underflow reading byte" }
        return data[position++].toInt() and 0xFF
    }

    fun readBytes(): ByteArray = readBytes(Int.MAX_VALUE)

    /**
     * [readBytes] with a protocol-imposed ceiling, checked **before** the copy is made — an
     * oversize field costs the caller nothing but the length read.
     */
    fun readBytes(maxLength: Int): ByteArray {
        require(data.size - position >= 4) { "Frame underflow reading length" }
        val length = bytesToInt(data, position)
        position += 4
        require(length >= 0) { "Negative frame length $length" }
        require(length <= maxLength) { "Frame field of $length bytes exceeds the $maxLength-byte limit" }
        require(length <= data.size - position) { "Frame underflow reading $length bytes" }
        return data.copyOfRange(position, position + length).also { position += length }
    }

    fun hasRemaining(): Boolean = position < data.size

    /**
     * Strict decoders call this after the final field: trailing bytes mean the input is a
     * different message than the one just read, and accepting it would let two byte strings
     * deserialise to the same logical value.
     */
    fun expectEnd() {
        require(!hasRemaining()) { "Trailing bytes after the final field" }
    }
}

/** Strict UTF-8 for wire strings: a malformed sequence is rejected, never replaced with U+FFFD. */
fun ByteArray.decodeUtf8Strict(): String = try {
    decodeToString(throwOnInvalidSequence = true)
} catch (e: CharacterCodingException) {
    throw IllegalArgumentException("Malformed UTF-8 in wire string")
}

/** Lowercase, fixed 2-digits-per-byte hex, used as a stable set key for device public keys. */
fun ByteArray.toHexString(): String =
    joinToString("") { ((it.toInt() and 0xFF) + 0x100).toString(16).substring(1) }

/** 8-byte big-endian encoding of a Long (e.g. an epoch-seconds expiry). */
fun longToBigEndian8(value: Long): ByteArray = ByteArray(8) { index ->
    (value ushr (56 - index * 8)).toByte()
}

fun intToBytes(value: Int): ByteArray = byteArrayOf(
    (value ushr 24).toByte(),
    (value ushr 16).toByte(),
    (value ushr 8).toByte(),
    value.toByte(),
)

fun bytesToInt(data: ByteArray, offset: Int): Int =
    ((data[offset].toInt() and 0xFF) shl 24) or
        ((data[offset + 1].toInt() and 0xFF) shl 16) or
        ((data[offset + 2].toInt() and 0xFF) shl 8) or
        (data[offset + 3].toInt() and 0xFF)
