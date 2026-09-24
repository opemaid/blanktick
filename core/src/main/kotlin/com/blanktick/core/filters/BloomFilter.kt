package com.blanktick.core.filters

import kotlin.math.ceil
import kotlin.math.ln
import kotlin.math.roundToInt
import kotlin.math.roundToLong

/**
 * A Bloom filter over the bundled breached-password corpus.
 *
 * ## Why a Bloom filter is the *correct* structure here, not a compromise
 *
 * Bloom filters have false positives but **never false negatives**. Map that
 * onto the product:
 *
 * - False positive → we tell someone to change a password that was actually
 *   safe. Mildly annoying; the advice is still good.
 * - False negative → we tell someone a breached password is fine. Dangerous.
 *
 * The error mode points the safe way, which is the whole reason this is not
 * simply "the small option". By contrast the domain blocklist uses an exact
 * structure ([SortedHashSet64]) because there a false positive blocks a site the
 * user needs — a broken product rather than a mild annoyance.
 *
 * ## Sizing
 *
 * `m = -n·ln(p) / (ln2)²` and `k = (m/n)·ln2`. At n = 2,000,000 and p = 0.001
 * this gives m ≈ 28.76 Mbit (3.43 MB) with k = 10.
 *
 * ## Hashing
 *
 * Kirsch–Mitzenmacher double hashing: `g_i(x) = h1(x) + i·h2(x)`. Two hashes
 * give k probes with provably the same asymptotic false-positive rate as k
 * independent hashes, so lookups cost two hash computations rather than ten.
 *
 * All arithmetic is unsigned; [Hashing] is specified bit-for-bit so the Python
 * builder, this reader and the Swift reader agree exactly.
 */
class BloomFilter internal constructor(
    private val bits: LongArray,
    /** Number of bits in the filter. May be less than `bits.size * 64`. */
    val bitCount: Long,
    val hashCount: Int,
    /** Number of items inserted at build time. Informational. */
    val insertedCount: Long
) {
    init {
        require(bitCount > 0) { "bitCount must be positive" }
        require(hashCount in 1..64) { "hashCount out of range: $hashCount" }
        require(bits.size.toLong() >= (bitCount + 63) / 64) {
            "backing array too small for $bitCount bits"
        }
    }

    /** Approximate memory footprint of the bit array. */
    val sizeBytes: Long get() = bits.size.toLong() * 8

    /**
     * @return false = definitely absent. true = probably present, with the
     *   false-positive probability the filter was built for.
     */
    operator fun contains(value: String): Boolean = contains(value.encodeToByteArray())

    fun contains(value: ByteArray): Boolean {
        val a = Hashing.h1(value)
        val b = Hashing.h2(value)
        val m = bitCount.toULong()
        var probe = a
        for (i in 0 until hashCount) {
            val index = (probe % m).toLong()
            if (!getBit(index)) return false
            probe += b
        }
        return true
    }

    private fun getBit(index: Long): Boolean {
        val word = (index ushr 6).toInt()
        val bit = (index and 63L).toInt()
        return (bits[word] ushr bit) and 1L == 1L
    }

    /** Measured fraction of set bits. Used by the self-test to detect corruption. */
    fun fillRatio(): Double {
        var set = 0L
        for (w in bits) set += java.lang.Long.bitCount(w).toLong()
        return set.toDouble() / bitCount.toDouble()
    }

    /**
     * Estimated false-positive rate given the *observed* fill, rather than the
     * design target. Surfaced in the app's diagnostics screen so the claimed
     * accuracy is measurable rather than asserted.
     */
    fun estimatedFalsePositiveRate(): Double {
        val fill = fillRatio()
        var p = 1.0
        repeat(hashCount) { p *= fill }
        return p
    }

    companion object {
        private val LN2 = ln(2.0)
        private val LN2_SQUARED = LN2 * LN2

        /** Optimal bit count for [n] items at false-positive probability [p]. */
        fun optimalBitCount(n: Long, p: Double): Long {
            require(n > 0) { "n must be positive" }
            require(p > 0.0 && p < 1.0) { "p must be in (0,1)" }
            return ceil(-n.toDouble() * ln(p) / LN2_SQUARED).roundToLong()
        }

        /** Optimal number of probes for [m] bits over [n] items. */
        fun optimalHashCount(m: Long, n: Long): Int {
            require(n > 0) { "n must be positive" }
            return (m.toDouble() / n.toDouble() * LN2).roundToInt().coerceIn(1, 64)
        }

        /** Builds an empty filter sized for [n] items at rate [p]. */
        fun create(n: Long, p: Double): Builder {
            val m = optimalBitCount(n, p)
            val k = optimalHashCount(m, n)
            return Builder(m, k)
        }

        // ---- Serialisation ------------------------------------------------
        //
        // Little-endian throughout, matching both target platforms and Python's
        // '<' struct prefix. Layout:
        //
        //   0  : magic  "MUB1"                (4 bytes)
        //   4  : version                      (u32)
        //   8  : hashCount                    (u32)
        //   12 : reserved / zero              (u32)
        //   16 : bitCount                     (u64)
        //   24 : insertedCount                (u64)
        //   32 : checksum of the bit payload  (u64, FNV-1a over the words)
        //   40 : bit words                    (ceil(bitCount/64) * u64)

        const val MAGIC = "MUB1"
        const val HEADER_BYTES = 40
        private const val FORMAT_VERSION = 1

        fun parse(bytes: ByteArray, verifyChecksum: Boolean = true): BloomFilter {
            require(bytes.size >= HEADER_BYTES) { "truncated bloom filter: ${bytes.size} bytes" }
            val magic = bytes.decodeToString(0, 4)
            require(magic == MAGIC) { "bad magic '$magic', expected '$MAGIC'" }

            val version = readInt(bytes, 4)
            require(version == FORMAT_VERSION) { "unsupported bloom format version $version" }

            val hashCount = readInt(bytes, 8)
            val bitCount = readLong(bytes, 16)
            val inserted = readLong(bytes, 24)
            val checksum = readLong(bytes, 32)

            // bitCount comes straight out of the file header. Without this
            // bound, ((bitCount + 63) / 64).toInt() truncates on any value above
            // 2^37 bits and yields words = 0 -- a filter that parses, passes the
            // length check, and is silently EMPTY. Every lookup then throws and
            // the caller degrades to "not checkable", so it fails closed rather
            // than reporting every password as safe; but a header that cannot be
            // honoured should be rejected outright, not quietly reinterpreted.
            //
            // 2^36 bits is 8 GiB of filter -- four thousand times the shipping
            // size and far past anything that could be loaded anyway.
            require(bitCount in 1..(1L shl 36)) {
                "implausible bloom bitCount $bitCount"
            }
            val words = ((bitCount + 63) / 64).toInt()
            val expected = HEADER_BYTES + words * 8
            require(bytes.size >= expected) {
                "truncated bloom filter: have ${bytes.size} bytes, need $expected"
            }

            val bits = LongArray(words)
            for (i in 0 until words) bits[i] = readLong(bytes, HEADER_BYTES + i * 8)

            if (verifyChecksum) {
                val actual = checksumOf(bits)
                require(actual == checksum) {
                    "bloom filter is corrupt: checksum ${actual.toULong().toString(16)} != " +
                        checksum.toULong().toString(16)
                }
            }

            return BloomFilter(bits, bitCount, hashCount, inserted)
        }

        internal fun checksumOf(bits: LongArray): Long {
            var h = 0xcbf29ce484222325uL
            for (w in bits) {
                var x = w.toULong()
                repeat(8) {
                    h = h xor (x and 0xffuL)
                    h *= 0x100000001b3uL
                    x = x shr 8
                }
            }
            return h.toLong()
        }

        private fun readInt(b: ByteArray, at: Int): Int =
            (b[at].toInt() and 0xff) or
                ((b[at + 1].toInt() and 0xff) shl 8) or
                ((b[at + 2].toInt() and 0xff) shl 16) or
                ((b[at + 3].toInt() and 0xff) shl 24)

        private fun readLong(b: ByteArray, at: Int): Long {
            var v = 0L
            for (i in 7 downTo 0) v = (v shl 8) or (b[at + i].toLong() and 0xff)
            return v
        }
    }

    /**
     * Build-side companion. Kept in the shipping module (not test-only) so the
     * app can construct small local filters — for example the user's own set of
     * previously-dismissed findings — with exactly the same semantics.
     */
    class Builder(private val bitCount: Long, private val hashCount: Int) {
        private val bits = LongArray(((bitCount + 63) / 64).toInt())
        private var inserted = 0L

        fun add(value: String): Builder = add(value.encodeToByteArray())

        fun add(value: ByteArray): Builder {
            val a = Hashing.h1(value)
            val b = Hashing.h2(value)
            val m = bitCount.toULong()
            var probe = a
            for (i in 0 until hashCount) {
                val index = (probe % m).toLong()
                bits[(index ushr 6).toInt()] =
                    bits[(index ushr 6).toInt()] or (1L shl (index and 63L).toInt())
                probe += b
            }
            inserted++
            return this
        }

        fun build(): BloomFilter = BloomFilter(bits, bitCount, hashCount, inserted)

        /** Serialises in the exact format [parse] expects. */
        fun serialize(): ByteArray {
            val out = ByteArray(HEADER_BYTES + bits.size * 8)
            MAGIC.encodeToByteArray().copyInto(out, 0)
            writeInt(out, 4, FORMAT_VERSION)
            writeInt(out, 8, hashCount)
            writeInt(out, 12, 0)
            writeLong(out, 16, bitCount)
            writeLong(out, 24, inserted)
            writeLong(out, 32, checksumOf(bits))
            for (i in bits.indices) writeLong(out, HEADER_BYTES + i * 8, bits[i])
            return out
        }

        private fun writeInt(b: ByteArray, at: Int, v: Int) {
            for (i in 0 until 4) b[at + i] = ((v ushr (8 * i)) and 0xff).toByte()
        }

        private fun writeLong(b: ByteArray, at: Int, v: Long) {
            for (i in 0 until 8) b[at + i] = ((v ushr (8 * i)) and 0xff).toByte()
        }
    }
}
