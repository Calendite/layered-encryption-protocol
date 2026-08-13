package org.layeredencryption.playground

/** One named piece of a step: a field of a message, or a segment of a composed byte string. */
class Part(
    val name: String,
    val bytes: Int,
    val value: String? = null,
    val note: String? = null,
)

/** One thing that happened, in the order it happened. */
class Step(
    val phase: String,
    val side: String,
    val title: String,
    val detail: String,
    val algorithms: List<String> = emptyList(),
    val parts: List<Part> = emptyList(),
    val hex: String? = null,
    val text: String? = null,
    val failed: Boolean = false,
)

/**
 * What the page reads. Pairing steps are kept for the life of the process (it happens once);
 * message steps are replaced each time something is sent, so the page always shows one journey
 * rather than an ever-growing pile.
 */
class EventLog {
    private val pairing = mutableListOf<Step>()
    private val message = mutableListOf<Step>()

    /** Set per message so the page can lead with the outcome rather than making you read for it. */
    @Volatile var lastVerdict: String = "nothing sent yet"
    @Volatile var lastTampered: Boolean = false
    @Volatile var lastDelivered: Boolean = false

    @Synchronized
    fun add(
        phase: String,
        side: String,
        title: String,
        detail: String,
        algorithms: List<String> = emptyList(),
        parts: List<Part> = emptyList(),
        hex: String? = null,
        text: String? = null,
        failed: Boolean = false,
    ) {
        val step = Step(phase, side, title, detail, algorithms, parts, hex, text, failed)
        if (phase == "pairing") pairing += step else message += step
    }

    @Synchronized
    fun clearMessages() = message.clear()

    @Synchronized
    fun asJson(): String {
        fun renderParts(parts: List<Part>) = parts.joinToString(",") { part ->
            """{"name":${quote(part.name)},"bytes":${part.bytes},"value":${quote(part.value)},"note":${quote(part.note)}}"""
        }
        fun render(steps: List<Step>) = steps.joinToString(",") { step ->
            """{"side":${quote(step.side)},"title":${quote(step.title)},"detail":${quote(step.detail)},""" +
                """"algorithms":[${step.algorithms.joinToString(",") { quote(it) }}],""" +
                """"parts":[${renderParts(step.parts)}],""" +
                """"hex":${quote(step.hex)},"text":${quote(step.text)},"failed":${step.failed}}"""
        }
        val algorithms = ALGORITHM_MAP.joinToString(",") { use ->
            """{"name":${quote(use.name)},"pq":${use.postQuantum},"when":${quote(use.whenUsed)},"what":${quote(use.what)}}"""
        }
        return """{"verdict":${quote(lastVerdict)},"tampered":$lastTampered,"delivered":$lastDelivered,""" +
            """"algorithms":[$algorithms],""" +
            """"pairing":[${render(pairing)}],"message":[${render(message)}]}"""
    }

    private fun quote(value: String?): String {
        if (value == null) return "null"
        val escaped = StringBuilder("\"")
        for (character in value) {
            when (character) {
                '"' -> escaped.append("\\\"")
                '\\' -> escaped.append("\\\\")
                '\n' -> escaped.append("\\n")
                '\r' -> escaped.append("\\r")
                '\t' -> escaped.append("\\t")
                else -> if (character < ' ') escaped.append("\\u%04x".format(character.code)) else escaped.append(character)
            }
        }
        return escaped.append('"').toString()
    }
}
