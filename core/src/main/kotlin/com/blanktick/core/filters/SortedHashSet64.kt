package com.blanktick.core.filters

/**
 * Exact membership over a large set of strings, stored as sorted 64-bit digests.
 *
 * ## Why this and not another Bloom filter
 *
 * This structure backs the **domain blocklist**, where the cost of an error is
 * the opposite of the password corpus:
 *
 * - A false positive blocks a site the user needs. The product looks broken and
 *   the user turns the feature off — which removes all of its protection.
 * - There is no safe direction to be wrong in.
 *
 * So the blocklist is exact. Storing full domain strings would cost ~24 bytes
 * each; storing a 64-bit digest costs 8. The only inexactness left is a digest
 * collision, and by the birthday bound the probability of *any* collision among
 * 2,000,000 keys drawn over 2^64 is about `n²/2^65` ≈ **1.1 × 10⁻⁷** — five
 * orders of magnitude below the rate at which the blocklist itself is wrong.
 *
 * ## Lookup
 *
 * A 65,536-entry index on the top 16 bits of the digest narrows the search to an
 * average of ~30 entries for a 2M-key table, then a binary search finishes it.
 * That is one cache miss for the index and one or two for the payload.
 *
 * The array is a plain `LongArray`, so on Android the asset can be mapped
 * directly rather than copied onto the heap.
 */
class SortedHashSet64 internal constructor(
    private val digests: LongArray,
    /** `index[b]` is the first offset in [digests] whose top 16 bits are >= b. */
    private val index: IntArray
) {
    val size: Int get() = digests.size
    val sizeBytes: Long get() = digests.size.toLong() * 8 + index.size.toLong() * 4

    operator fun contains(value: String): Boolean = containsDigest(Hashing.digest(value))

    fun containsDigest(digest: ULong): Boolean {
        val bucket = (digest shr 48).toInt()
        var lo = index[bucket]
        var hi = index[bucket + 1]
        val target = digest.toLong()
        while (lo < hi) {
            val mid = (lo + hi) ushr 1
            // Compare as unsigned: digests are sorted by unsigned value.
            val cmp = compareUnsigned(digests[mid], target)
            when {
                cmp < 0 -> lo = mid + 1
                cmp > 0 -> hi = mid
                else -> return true
            }
        }
        return false
    }

    /**
     * Looks up [domain] and each of its parents, most specific first.
     *
     * @return the matching entry, or null. Returning *which* parent matched lets
     *   the UI say "blocked because ads.example.com is on the list" rather than
     *   an unexplained block.
     */
    fun matchDomain(domain: String, maxLabels: Int = 5): String? =
        DomainNormalizer.parentChain(domain, maxLabels).firstOrNull { contains(it) }

    private fun compareUnsigned(a: Long, b: Long): Int =
        (a.toULong()).compareTo(b.toULong())

    companion object {
        // Layout, little-endian:
        //   0  : magic "MUS1"   (4 bytes)
        //   4  : version        (u32)
        //   8  : count          (u64)
        //   16 : checksum       (u64)
        //   24 : sorted digests (count * u64)
        const val MAGIC = "MUS1"
        const val HEADER_BYTES = 24
        private const val FORMAT_VERSION = 1
        private const val BUCKETS = 1 shl 16

        fun build(values: Collection<String>): SortedHashSet64 {
            val digests = values.asSequence()
                .map { Hashing.digest(DomainNormalizer.normalize(it)).toLong() }
                .distinct()
                .toMutableList()
            digests.sortWith { a, b -> a.toULong().compareTo(b.toULong()) }
            return fromSortedArray(digests.toLongArray())
        }

        internal fun fromSortedArray(sorted: LongArray): SortedHashSet64 =
            SortedHashSet64(sorted, buildIndex(sorted))

        /**
         * Builds the top-16-bit index in a single pass.
         *
         * `index` has `BUCKETS + 1` entries so that `index[b]` and `index[b+1]`
         * always bound bucket `b`, including the last one — no special case at
         * the end of the array.
         */
        private fun buildIndex(sorted: LongArray): IntArray {
            val index = IntArray(BUCKETS + 1)
            var pos = 0
            for (bucket in 0 until BUCKETS) {
                index[bucket] = pos
                while (pos < sorted.size && (sorted[pos].toULong() shr 48).toInt() == bucket) {
                    pos++
                }
            }
            index[BUCKETS] = sorted.size
            return index
        }

        fun parse(bytes: ByteArray, verifyChecksum: Boolean = true): SortedHashSet64 {
            require(bytes.size >= HEADER_BYTES) { "truncated hash set: ${bytes.size} bytes" }
            val magic = bytes.decodeToString(0, 4)
            require(magic == MAGIC) { "bad magic '$magic', expected '$MAGIC'" }
            val version = readInt(bytes, 4)
            require(version == FORMAT_VERSION) { "unsupported hash-set version $version" }

            val count = readLong(bytes, 8)
            require(count >= 0 && count <= Int.MAX_VALUE) { "implausible entry count $count" }
            val checksum = readLong(bytes, 16)

            val n = count.toInt()
            val expected = HEADER_BYTES + n * 8
            require(bytes.size >= expected) {
                "truncated hash set: have ${bytes.size} bytes, need $expected"
            }

            val digests = LongArray(n)
            for (i in 0 until n) digests[i] = readLong(bytes, HEADER_BYTES + i * 8)

            if (verifyChecksum) {
                val actual = BloomFilter.checksumOf(digests)
                require(actual == checksum) { "hash set is corrupt: checksum mismatch" }
            }

            // Assert the sort invariant. A mis-sorted table would silently make
            // the binary search return false negatives, which is precisely the
            // failure mode this structure exists to avoid.
            for (i in 1 until n) {
                require(digests[i - 1].toULong() < digests[i].toULong()) {
                    "hash set is not strictly sorted at index $i"
                }
            }

            return fromSortedArray(digests)
        }

        fun serialize(set: SortedHashSet64): ByteArray {
            val n = set.digests.size
            val out = ByteArray(HEADER_BYTES + n * 8)
            MAGIC.encodeToByteArray().copyInto(out, 0)
            writeInt(out, 4, FORMAT_VERSION)
            writeLong(out, 8, n.toLong())
            writeLong(out, 16, BloomFilter.checksumOf(set.digests))
            for (i in 0 until n) writeLong(out, HEADER_BYTES + i * 8, set.digests[i])
            return out
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

        private fun writeInt(b: ByteArray, at: Int, v: Int) {
            for (i in 0 until 4) b[at + i] = ((v ushr (8 * i)) and 0xff).toByte()
        }

        private fun writeLong(b: ByteArray, at: Int, v: Long) {
            for (i in 0 until 8) b[at + i] = ((v ushr (8 * i)) and 0xff).toByte()
        }
    }
}
