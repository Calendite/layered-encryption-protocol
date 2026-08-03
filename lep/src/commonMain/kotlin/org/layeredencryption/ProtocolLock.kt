package org.layeredencryption

/**
 * A reentrant mutual-exclusion lock usable from ordinary (non-suspend) code.
 *
 * Protocol state (a pairing ceremony's step machine, say) is driven from several directions at
 * once, through plain non-suspend functions, so a coroutine `Mutex` cannot guard them; this can.
 *
 * Never hold it across network I/O. Take it around the state and lane mutations only, so a stalled
 * socket can never block a user's save.
 */
expect class ProtocolLock() {
    fun <T> withLock(block: () -> T): T
}
