package org.layeredencryption

/**
 * External declarations over the noble libraries (pure-JS, synchronous), plus the
 * `ByteArray` ↔ `Uint8Array` bridging the wasm↔JS boundary needs.
 *
 * Everything here is a thin, name-for-name mirror of the ESM exports; no logic. The
 * argument orders follow noble's conventions, which differ from [CryptoProvider]'s
 * (`sign(msg, secretKey)`, `verify(sig, msg, publicKey)`) — the provider adapts.
 */

/** The global JS `Uint8Array` — the byte currency of every noble API. */
internal external class Uint8Array(length: Int) : JsAny {
    val length: Int
}

// ── @noble/hashes ─────────────────────────────────────────────────────────────

@JsModule("@noble/hashes/sha2.js")
internal external object NobleSha2 {
    fun sha256(data: Uint8Array): Uint8Array
}

/** The same module again, importing `sha256` as a *value* to hand to hmac/hkdf. */
@JsModule("@noble/hashes/sha2.js")
internal external object NobleSha2Refs {
    @JsName("sha256")
    val sha256Ref: JsAny
}

@JsModule("@noble/hashes/sha3.js")
internal external object NobleSha3 {
    fun sha3_256(data: Uint8Array): Uint8Array
}

@JsModule("@noble/hashes/hmac.js")
internal external object NobleHmac {
    fun hmac(hash: JsAny, key: Uint8Array, message: Uint8Array): Uint8Array
}

@JsModule("@noble/hashes/hkdf.js")
internal external object NobleHkdf {
    fun hkdf(hash: JsAny, ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length: Int): Uint8Array
}

// ── @noble/ciphers ────────────────────────────────────────────────────────────

internal external interface NobleAead {
    fun encrypt(plaintext: Uint8Array): Uint8Array
    fun decrypt(ciphertextAndTag: Uint8Array): Uint8Array
}

@JsModule("@noble/ciphers/chacha.js")
internal external object NobleChaCha {
    fun chacha20poly1305(key: Uint8Array, nonce: Uint8Array): NobleAead
    fun chacha20poly1305(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array): NobleAead
}

@JsModule("@noble/ciphers/aes.js")
internal external object NobleAes {
    fun gcm(key: Uint8Array, nonce: Uint8Array): NobleAead
    fun gcm(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array): NobleAead
}

// ── @noble/curves ─────────────────────────────────────────────────────────────

internal external interface NobleEd25519 {
    fun getPublicKey(privateKey: Uint8Array): Uint8Array
    fun sign(message: Uint8Array, privateKey: Uint8Array): Uint8Array
    fun verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): Boolean
}

internal external interface NobleX25519 {
    fun getPublicKey(privateKey: Uint8Array): Uint8Array
    fun getSharedSecret(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array
}

@JsModule("@noble/curves/ed25519.js")
internal external object NobleCurves {
    val ed25519: NobleEd25519
    val x25519: NobleX25519
}

// ── @noble/post-quantum ───────────────────────────────────────────────────────

internal external interface NobleKeys {
    val publicKey: Uint8Array
    val secretKey: Uint8Array
}

internal external interface NobleEncapsulation {
    val cipherText: Uint8Array
    val sharedSecret: Uint8Array
}

internal external interface NobleMlKem {
    fun keygen(): NobleKeys
    fun encapsulate(publicKey: Uint8Array): NobleEncapsulation
    fun decapsulate(cipherText: Uint8Array, secretKey: Uint8Array): Uint8Array
}

internal external interface NobleMlDsa {
    fun keygen(): NobleKeys
    fun sign(message: Uint8Array, secretKey: Uint8Array): Uint8Array
    fun verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): Boolean
}

@JsModule("@noble/post-quantum/ml-kem.js")
internal external object NoblePqKem {
    val ml_kem768: NobleMlKem
}

@JsModule("@noble/post-quantum/ml-dsa.js")
internal external object NoblePqDsa {
    val ml_dsa65: NobleMlDsa
}

// ── ByteArray ↔ Uint8Array bridging ──────────────────────────────────────────

private fun jsGet(array: Uint8Array, index: Int): Int = js("array[index]")

private fun jsSet(array: Uint8Array, index: Int, value: Int): Unit = js("array[index] = value")

private fun jsRandomFill(array: Uint8Array): Unit = js("crypto.getRandomValues(array)")

internal fun ByteArray.toUint8Array(): Uint8Array {
    val out = Uint8Array(size)
    for (i in indices) jsSet(out, i, this[i].toInt() and 0xFF)
    return out
}

internal fun Uint8Array.toByteArray(): ByteArray {
    val out = ByteArray(length)
    for (i in out.indices) out[i] = jsGet(this, i).toByte()
    return out
}

/** CSPRNG bytes straight from `crypto.getRandomValues`. */
internal fun webRandomBytes(size: Int): ByteArray {
    val array = Uint8Array(size)
    jsRandomFill(array)
    return array.toByteArray()
}
