package com.mume.core.filters

import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Canonical hash vectors, pinned.
 *
 * These constants were produced by `tools/mume_hash.py` — the Python that
 * builds the intel bundle — via `tools/gen_hash_vectors.py`, and are stored in
 * `shared/hash-vectors.json`. The identical list is pinned in
 * `ios/MumeCore/Tests/MumeCoreTests/HashParityTests.swift`.
 *
 * ## Why constants rather than a property test
 *
 * The property tests in `HashingTest` prove this implementation is internally
 * consistent and well-distributed. They cannot prove it matches the *other two*
 * implementations, and that is the failure that matters: Python writes the
 * password filter, Kotlin and Swift read it, and a one-bit divergence produces
 * no crash — just silently wrong membership answers. For a breached-password
 * check, "silently wrong" means telling someone a compromised password is safe.
 *
 * Reading three implementations side by side cannot catch that. Fixed hex
 * constants can.
 *
 * ## The vectors
 *
 * Chosen to exercise exactly where languages diverge: the empty string, plain
 * ASCII, multi-byte UTF-8 (`münchen`), a NUL byte, a high Latin-1 byte, an
 * astral-plane emoji (a surrogate *pair* in UTF-16, which is why hashing
 * `String.utf16` instead of UTF-8 bytes would fail here and only here), and a
 * long input.
 *
 * If any of these fail, do not "fix" this file. Find out which of the three
 * implementations moved.
 */
class HashVectorsTest {

    private data class Vec(val input: String, val h1: ULong, val h2: ULong)

    private val vectors = listOf(
        Vec("", 0xC3817C016BA4FF30uL, 0xA8AC350571988A20uL),
        Vec("a", 0x5F29C2AADD9B8527uL, 0xE009B507ACA658CAuL),
        Vec("abc", 0x29E32C04EC3F9C30uL, 0xA8178AEED4BAE1B9uL),
        Vec("password", 0xA39E041EB9B79ED7uL, 0x44F3F9107CF1384DuL),
        Vec("123456", 0x1928BFA12710C080uL, 0x23751DABBD3218FDuL),
        Vec("münchen", 0x0066E844F3DB1BFCuL, 0x6B47B31E84D9E732uL),
        Vec("example.com", 0x559608F2BA07D7BFuL, 0xD143CCF01ED7616DuL),
        Vec("doubleclick.net", 0x87F68F78881C00E0uL, 0x5166240B0A71F931uL),
        Vec("standardbank.co.za", 0x43B146A3A6223FCEuL, 0x2B74B26F4F7C4B42uL),
        Vec("the quick brown fox", 0xFEC817530D025724uL, 0x91981A36A398FDB7uL),
        Vec("\u0000\u00FF", 0x8AA0B90692B1A56FuL, 0x51644C7788774CB9uL),
        Vec("🔒emoji", 0x89C71DFBC992A570uL, 0xDDD80EE9156AA228uL),
        Vec(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            0x9DBB843E90867C77uL, 0x50478086A70E91D7uL
        )
    )

    @Test
    fun `h1 matches the canonical vectors`() {
        vectors.forEach { v ->
            assertEquals(
                v.h1, Hashing.h1(v.input),
                "h1 diverged for ${describe(v.input)} — Kotlin and the Python bundle " +
                    "builder no longer agree, so every bundle lookup is unreliable"
            )
        }
    }

    @Test
    fun `h2 matches the canonical vectors`() {
        vectors.forEach { v ->
            assertEquals(v.h2, Hashing.h2(v.input), "h2 diverged for ${describe(v.input)}")
        }
    }

    @Test
    fun `the digest used by the domain tables is h1`() {
        vectors.forEach { v -> assertEquals(v.h1, Hashing.digest(v.input)) }
    }

    @Test
    fun `the mixer matches the reference implementation`() {
        // Pinned separately from the full h1/h2 vectors so a regression can be
        // localised to the mixer rather than the FNV pass. Values come from
        // `splitmix64` in tools/mume_hash.py, which is the authority because it
        // is what builds the shipped bundle.
        assertEquals(0xE220A8397B1DCDAFuL, Hashing.mix(0uL))
        assertEquals(0x910A2DEC89025CC1uL, Hashing.mix(1uL))
        assertEquals(0x6E789E6AA1B965F4uL, Hashing.mix(0x9E3779B97F4A7C15uL))
    }

    private fun describe(s: String): String =
        "'" + s.map { if (it.code in 0x20..0x7E) it.toString() else "\\u%04X".format(it.code) }
            .joinToString("") + "'"
}
