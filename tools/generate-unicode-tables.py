#!/usr/bin/env python3
"""Generates lep/src/commonMain/.../diagnostics/UnicodeTables.kt from the Unicode Character
Database, pinned to one Unicode version.

Kotlin's common standard library only exposes character categories for the BMP, and none of the
emoji properties at all — so the character taxonomy (the Layer-1 partition and Layer-2 flags the
tests verify and the log fingerprints use) is generated here as compact range tables and
committed. Re-run with a newer UCD to move Unicode versions; the taxonomy tests pin the version
and the assigned-character count, so an accidental regeneration cannot slip by.

Usage: python3 tools/generate-unicode-tables.py <ucd-dir> <output.kt>
where <ucd-dir> contains UnicodeData.txt, Scripts.txt and emoji-data.txt for one version.
"""

import sys
from pathlib import Path

UNICODE_VERSION = "17.0.0"
MAX_CP = 0x110000

# Layer-1 classes, in the priority order the partition is assigned. Must match the
# CharacterClass enum in CharacterProfile.kt ordinal-for-ordinal.
CLASSES = [
    "ASCII_LETTER", "ASCII_DIGIT", "ASCII_PUNCTUATION", "ASCII_WHITESPACE",
    "C0_CONTROL", "C1_CONTROL",
    "SURROGATE", "NONCHARACTER", "REPLACEMENT_CHARACTER", "PRIVATE_USE", "UNASSIGNED",
    "REGIONAL_INDICATOR", "TAG_CHARACTER", "VARIATION_SELECTOR", "BIDI_CONTROL", "FORMAT",
    "SEPARATOR", "COMBINING_MARK",
    "EMOJI_PRESENTATION", "PICTOGRAPHIC",
    "LETTER", "NUMBER", "PUNCTUATION", "SYMBOL",
    "OTHER",
]
CLASS_ID = {name: i for i, name in enumerate(CLASSES)}

# Layer-2 flag bits. Must match CharFlag in CharacterProfile.kt.
FLAG_EMOJI = 1 << 0
FLAG_EMOJI_PRESENTATION = 1 << 1
FLAG_EMOJI_MODIFIER = 1 << 2
FLAG_EMOJI_MODIFIER_BASE = 1 << 3
FLAG_EMOJI_COMPONENT = 1 << 4
FLAG_EXTENDED_PICTOGRAPHIC = 1 << 5
FLAG_COMPATIBILITY = 1 << 6
FLAG_NORMALIZATION = 1 << 7
FLAG_WHITE_SPACE = 1 << 8

BIDI_CONTROLS = {0x061C, 0x200E, 0x200F, *range(0x202A, 0x202F), *range(0x2066, 0x206A)}
KEYCAP_BASES = {*range(ord("0"), ord("9") + 1), ord("#"), ord("*")}


def parse_unicode_data(path):
    gc = ["Cn"] * MAX_CP
    ccc = [0] * MAX_CP
    decomp = [""] * MAX_CP
    lines = path.read_text().splitlines()
    i = 0
    while i < len(lines):
        fields = lines[i].split(";")
        cp = int(fields[0], 16)
        name, category = fields[1], fields[2]
        if name.endswith(", First>"):
            last = int(lines[i + 1].split(";")[0], 16)
            for c in range(cp, last + 1):
                gc[c] = category
            i += 2
            continue
        gc[cp] = category
        ccc[cp] = int(fields[3])
        decomp[cp] = fields[5]
        i += 1
    return gc, ccc, decomp


def parse_property_file(path):
    """Yields (start, end, property) from Scripts.txt / emoji-data.txt style files."""
    for line in path.read_text().splitlines():
        line = line.split("#")[0].strip()
        if not line:
            continue
        rng, prop = [part.strip() for part in line.split(";")[:2]]
        if ".." in rng:
            start, end = [int(p, 16) for p in rng.split("..")]
        else:
            start = end = int(rng, 16)
        yield start, end, prop


def is_noncharacter(cp):
    return 0xFDD0 <= cp <= 0xFDEF or (cp & 0xFFFE) == 0xFFFE


def main():
    ucd = Path(sys.argv[1])
    out = Path(sys.argv[2])

    gc, ccc, decomp = parse_unicode_data(ucd / "UnicodeData.txt")

    emoji_flags = [0] * MAX_CP
    flag_of = {
        "Emoji": FLAG_EMOJI,
        "Emoji_Presentation": FLAG_EMOJI_PRESENTATION,
        "Emoji_Modifier": FLAG_EMOJI_MODIFIER,
        "Emoji_Modifier_Base": FLAG_EMOJI_MODIFIER_BASE,
        "Emoji_Component": FLAG_EMOJI_COMPONENT,
        "Extended_Pictographic": FLAG_EXTENDED_PICTOGRAPHIC,
    }
    for start, end, prop in parse_property_file(ucd / "emoji-data.txt"):
        bit = flag_of.get(prop)
        if bit:
            for cp in range(start, end + 1):
                emoji_flags[cp] |= bit

    script_names = ["Common", "Inherited", "Unknown"]
    script_id = {name: i for i, name in enumerate(script_names)}
    scripts = [script_id["Unknown"]] * MAX_CP
    for start, end, prop in parse_property_file(ucd / "Scripts.txt"):
        if prop not in script_id:
            script_id[prop] = len(script_names)
            script_names.append(prop)
        for cp in range(start, end + 1):
            scripts[cp] = script_id[prop]

    def classify(cp):
        category = gc[cp]
        if cp < 0x80:
            ch = chr(cp)
            if ch.isascii() and ch.isalpha():
                return CLASS_ID["ASCII_LETTER"]
            if ch.isascii() and ch.isdigit():
                return CLASS_ID["ASCII_DIGIT"]
            if cp in (0x20, 0x09, 0x0A, 0x0B, 0x0C, 0x0D):
                return CLASS_ID["ASCII_WHITESPACE"]
            if cp < 0x20:
                return CLASS_ID["C0_CONTROL"]
            if cp == 0x7F:
                return CLASS_ID["C1_CONTROL"]
            return CLASS_ID["ASCII_PUNCTUATION"]
        if 0x80 <= cp <= 0x9F:
            return CLASS_ID["C1_CONTROL"]
        if category == "Cs":
            return CLASS_ID["SURROGATE"]
        if is_noncharacter(cp):
            return CLASS_ID["NONCHARACTER"]
        if cp == 0xFFFD:
            return CLASS_ID["REPLACEMENT_CHARACTER"]
        if category == "Co":
            return CLASS_ID["PRIVATE_USE"]
        if category == "Cn":
            return CLASS_ID["UNASSIGNED"]
        if 0x1F1E6 <= cp <= 0x1F1FF:
            return CLASS_ID["REGIONAL_INDICATOR"]
        if cp == 0xE0001 or 0xE0020 <= cp <= 0xE007F:
            return CLASS_ID["TAG_CHARACTER"]
        if 0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF or 0x180B <= cp <= 0x180D:
            return CLASS_ID["VARIATION_SELECTOR"]
        if cp in BIDI_CONTROLS:
            return CLASS_ID["BIDI_CONTROL"]
        if category == "Cf":
            return CLASS_ID["FORMAT"]
        if category in ("Zs", "Zl", "Zp"):
            return CLASS_ID["SEPARATOR"]
        if category in ("Mn", "Mc", "Me"):
            return CLASS_ID["COMBINING_MARK"]
        if emoji_flags[cp] & FLAG_EMOJI_PRESENTATION:
            return CLASS_ID["EMOJI_PRESENTATION"]
        if emoji_flags[cp] & FLAG_EXTENDED_PICTOGRAPHIC:
            return CLASS_ID["PICTOGRAPHIC"]
        if category.startswith("L"):
            return CLASS_ID["LETTER"]
        if category.startswith("N"):
            return CLASS_ID["NUMBER"]
        if category.startswith("P"):
            return CLASS_ID["PUNCTUATION"]
        if category.startswith("S"):
            return CLASS_ID["SYMBOL"]
        if category == "Cc":  # unreachable: all Cc are ASCII/C1, kept for totality
            return CLASS_ID["C0_CONTROL"]
        return CLASS_ID["OTHER"]

    payload = [0] * MAX_CP
    other_count = 0
    for cp in range(MAX_CP):
        cls = classify(cp)
        if cls == CLASS_ID["OTHER"]:
            other_count += 1
        flags = emoji_flags[cp]
        if decomp[cp]:
            flags |= FLAG_NORMALIZATION
            if decomp[cp].startswith("<"):
                flags |= FLAG_COMPATIBILITY
        if ccc[cp] != 0:
            flags |= FLAG_NORMALIZATION
        if gc[cp] in ("Zs", "Zl", "Zp") or cp in (0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x85):
            flags |= FLAG_WHITE_SPACE
        payload[cp] = cls | (flags << 6)

    assert other_count == 0, f"{other_count} code points fell into OTHER — extend the taxonomy"

    # The official "number of characters in Unicode X" counts graphic + format characters:
    # everything designated except controls (Cc), surrogates (Cs) and private use (Co).
    assigned = sum(1 for cp in range(MAX_CP) if gc[cp] not in ("Cn", "Cs", "Co", "Cc"))
    designated = sum(1 for cp in range(MAX_CP) if gc[cp] != "Cn")

    def run_length(values):
        runs = []
        start = 0
        for cp in range(1, MAX_CP + 1):
            if cp == MAX_CP or values[cp] != values[start]:
                runs.append((start, cp - 1, values[start]))
                start = cp
        return runs

    def encode(runs):
        return ";".join(f"{s:x}.{e:x}.{v:x}" for s, e, v in runs)

    def chunked_const(name, text, chunk=40_000):
        parts = [text[i:i + chunk] for i in range(0, len(text), chunk)]
        decls = "\n".join(
            f'    private const val {name}_{i} = "{part}"' for i, part in enumerate(parts)
        )
        joined = " + ".join(f"{name}_{i}" for i in range(len(parts)))
        return decls, joined

    class_runs = run_length(payload)
    script_runs = run_length(scripts)

    class_decls, class_join = chunked_const("PAYLOAD", encode(class_runs))
    script_decls, script_join = chunked_const("SCRIPTS", encode(script_runs))

    out.write_text(f"""package org.layeredencryption.diagnostics

// GENERATED by tools/generate-unicode-tables.py from the Unicode {UNICODE_VERSION} Character
// Database — do not edit by hand. {len(class_runs)} class/flag ranges, {len(script_runs)} script
// ranges. The taxonomy tests pin the version and counts below, so a regeneration against a
// different UCD cannot slip through unnoticed.
internal object UnicodeTables {{
    const val UNICODE_VERSION = "{UNICODE_VERSION}"

    /** The official character count: graphic + format characters (not Cn, Cs, Co or Cc). */
    const val ASSIGNED_CHARACTERS = {assigned}

    /** Designated code points of any kind, including private use and surrogates. */
    const val DESIGNATED_CODE_POINTS = {designated}

    const val CODE_POINT_COUNT = 0x110000

{class_decls}

{script_decls}

    private val payloadStarts: IntArray
    private val payloadEnds: IntArray
    private val payloadValues: IntArray
    private val scriptStarts: IntArray
    private val scriptEnds: IntArray
    private val scriptValues: IntArray

    init {{
        fun parse(text: String): Triple<IntArray, IntArray, IntArray> {{
            val runs = text.split(';')
            val starts = IntArray(runs.size)
            val ends = IntArray(runs.size)
            val values = IntArray(runs.size)
            for (i in runs.indices) {{
                val parts = runs[i].split('.')
                starts[i] = parts[0].toInt(16)
                ends[i] = parts[1].toInt(16)
                values[i] = parts[2].toInt(16)
            }}
            return Triple(starts, ends, values)
        }}
        val payload = parse({class_join})
        payloadStarts = payload.first; payloadEnds = payload.second; payloadValues = payload.third
        val scripts = parse({script_join})
        scriptStarts = scripts.first; scriptEnds = scripts.second; scriptValues = scripts.third
    }}

    private fun lookup(starts: IntArray, ends: IntArray, values: IntArray, codePoint: Int): Int {{
        var low = 0
        var high = starts.size - 1
        while (low <= high) {{
            val mid = (low + high) ushr 1
            when {{
                codePoint < starts[mid] -> high = mid - 1
                codePoint > ends[mid] -> low = mid + 1
                else -> return values[mid]
            }}
        }}
        return -1
    }}

    /** Layer-1 class ordinal in bits 0..5, Layer-2 flags from bit 6 up. */
    fun payloadOf(codePoint: Int): Int = lookup(payloadStarts, payloadEnds, payloadValues, codePoint)

    /** Script id; 0 = Common, 1 = Inherited, 2 = Unknown. */
    fun scriptOf(codePoint: Int): Int = lookup(scriptStarts, scriptEnds, scriptValues, codePoint)
}}
""")
    print(f"classes: {len(class_runs)} runs, scripts: {len(script_runs)} runs")
    print(f"assigned(graphic+format)={assigned}, designated={designated}")
    print(f"wrote {out} ({out.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
