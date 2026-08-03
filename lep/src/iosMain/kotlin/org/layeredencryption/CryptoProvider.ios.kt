package org.layeredencryption

/**
 * iOS [CryptoProvider] — **not yet implemented**.
 *
 * The iOS actual is a CryptoKit binding (ChaChaPoly, AES.GCM, native X-Wing on iOS 26+ with the
 * KEM inside the Secure Enclave) per docs/Protocol.md §5.1 / §5.3. It is deferred until iOS is
 * a real build target for sharing; the feature is gated to iOS 26 (§5.3), and the cross-platform
 * interop CI matrix (§5.4) only becomes meaningful once this exists.
 *
 * Declared here so the multiplatform build stays green; it throws if ever invoked on iOS.
 */
actual fun platformCryptoProvider(): CryptoProvider =
    throw NotImplementedError("iOS CryptoProvider (CryptoKit, iOS 26+) is not implemented yet — docs/Protocol.md §5.1")
