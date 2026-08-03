package org.layeredencryption

/**
 * JavaScript runs the app on a single thread, so there is nothing to exclude: any block of
 * synchronous code already runs to completion without interleaving.
 */
actual class ProtocolLock {
    actual fun <T> withLock(block: () -> T): T = block()
}
