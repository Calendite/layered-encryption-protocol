package org.layeredencryption.playground

import org.layeredencryption.ProtocolRecorder
import org.layeredencryption.RecordedField
import org.layeredencryption.RecordedMessage

/**
 * Feeds the library's own recording of the pairing ceremony into the page's event log.
 *
 * The descriptions, algorithms and field breakdowns all come from `RecordingChannel`, which
 * decodes each frame as it crosses the socket. This demo adds nothing to them, which is the
 * point: what you read on the page is the protocol describing itself.
 */
class PairingRecorder(private val events: EventLog) : ProtocolRecorder {

    override fun message(step: RecordedMessage) {
        events.add(
            phase = "pairing",
            side = if (step.from == "inviter") "A" else "B",
            title = step.name,
            detail = step.establishes?.let { "Established after this: $it" } ?: "${step.sizeBytes} B",
            algorithms = step.algorithms,
            parts = step.fields.map(::toPart),
        )
    }

    override fun derivation(label: String, from: String, produces: String) {
        events.add("pairing", "both", "Derived $produces", "HKDF with label $label, from $from")
    }

    override fun agreedBytes(name: String, bytes: ByteArray, composition: List<RecordedField>) {
        events.add("pairing", "both", name, "${bytes.size} B both sides compute independently",
            parts = composition.map(::toPart))
    }

    override fun note(text: String) = events.add("pairing", "both", "Note", text)

    override fun outcome(succeeded: Boolean, detail: String) =
        events.add("pairing", "both", if (succeeded) "Paired" else "Failed", detail, failed = !succeeded)

    private fun toPart(field: RecordedField) =
        Part(name = field.name, bytes = field.bytes, value = field.value, note = field.note)
}
