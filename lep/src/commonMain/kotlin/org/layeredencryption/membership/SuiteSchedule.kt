package org.layeredencryption.membership

import org.layeredencryption.suite.SuiteId

/**
 * Which suite governs which epochs of a context — the `startEpoch → suiteId` state the
 * migration brief (§6) requires so that old ciphertext stays readable after an upgrade and new
 * material names the suite that sealed it.
 *
 * Derived from a **verified** membership log ([MembershipLog.suiteSchedule]), never a
 * device-local setting: a suite transition is a membership event and an epoch boundary, so
 * every member computes the same schedule from the same authenticated history. Every context
 * begins at `Era(0, Suite 1)`; each SUITE_UPGRADE appends an era at its transition epoch.
 */
class SuiteSchedule internal constructor(eras: List<Era>) {

    class Era(val startEpoch: Int, val suite: SuiteId)

    /** Eras in order, starting at epoch 0. */
    val eras: List<Era> = eras.toList()

    init {
        require(this.eras.isNotEmpty() && this.eras.first().startEpoch == 0) { "A schedule starts at epoch 0" }
        require(this.eras.zipWithNext().all { (a, b) -> b.startEpoch > a.startEpoch }) { "Eras must be strictly ascending" }
    }

    /** The suite that governs [epoch]: the era with the greatest start not above it. */
    fun suiteAt(epoch: Int): SuiteId {
        require(epoch >= 0) { "Epochs count up from zero" }
        return eras.last { it.startEpoch <= epoch }.suite
    }

    /** The suite for new material — the newest era's. */
    val current: SuiteId get() = eras.last().suite
}
