package org.layeredencryption

/**
 * Web/Wasm [CryptoProvider] — **not yet implemented**.
 *
 * Web is not a sharing client in v1 (docs/Protocol.md §9.3): the browser is the weakest platform
 * regardless of ciphers, so it joins later as view-only. The eventual actual binds WebCrypto
 * (AES-GCM, X25519, HKDF), libsodium.js (ChaCha20-Poly1305) and the quarantined Kodium ML-KEM leg
 * (§5.1). Declared here so the multiplatform build stays green; it throws if ever invoked.
 */
actual fun platformCryptoProvider(): CryptoProvider =
    throw NotImplementedError("Web/Wasm CryptoProvider is not implemented yet — docs/Protocol.md §9.3")
