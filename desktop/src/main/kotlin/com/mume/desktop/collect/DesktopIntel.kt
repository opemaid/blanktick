package com.mume.desktop.collect

import com.mume.core.filters.BloomFilter
import com.mume.core.filters.SortedHashSet64
import com.mume.core.util.IsoDate

/**
 * The bundled threat data, read from the application's own jar.
 *
 * Deliberately the same shape and the same failure behaviour as `IntelBundle`
 * on Android, reading byte-identical files produced by the same
 * `tools/build_intel.py`. Two readers of one format is already one too many;
 * three (Kotlin/Android, Kotlin/desktop, Swift) is why the hash vectors in
 * `shared/hash-vectors.json` exist.
 *
 * ## Missing data is not good news
 *
 * The heavy assets are generated, not committed. A developer build without them
 * must still run, so every accessor degrades to `null` and the rules that depend
 * on the missing data report *not checkable*. The same contract the collectors
 * follow, applied to our own files: **absent evidence is never a pass.**
 */
class DesktopIntel private constructor(
    val manifest: Manifest?,
    private val breachedPasswords: BloomFilter?,
    private val blockedDomains: SortedHashSet64?,
    private val allowedDomains: SortedHashSet64?,
    private val malwareHashes: SortedHashSet64?
) {

    data class Manifest(
        val builtOn: String,
        val passwordCount: Long,
        val domainCount: Int,
        val malwareCount: Int,
        val version: String,
        /** True when the bundle was built from placeholder data, not real corpora. */
        val synthetic: Boolean
    )

    val isComplete: Boolean
        get() = manifest != null && breachedPasswords != null && blockedDomains != null

    fun snapshot(nowIsoDate: String) = DesktopIntelSnapshot(
        builtOn = manifest?.builtOn,
        stalenessDays = manifest?.builtOn?.let {
            IsoDate.daysBetween(it, nowIsoDate)?.toInt()?.coerceAtLeast(0)
        },
        isKnownMalware = malwareHashes?.let { table -> { hash -> table.contains(hash.trim().lowercase()) } }
    )

    /**
     * @return `null` when the corpus is not bundled. The caller must then report
     *   the password check as unavailable, never as "no breaches found".
     */
    fun isPasswordBreached(password: String): Boolean? = breachedPasswords?.contains(password)

    /**
     * Whether a file's SHA-256 is in the bundled known-malware table.
     *
     * @return `null` when no corpus is bundled — the caller must then report
     *   the check as not performed, never as "no malware found". A build
     *   without the table is the ordinary case, not an error.
     */
    fun isKnownMalware(sha256: String): Boolean? =
        malwareHashes?.contains(sha256.trim().lowercase())

    fun domainBlocklist(): SortedHashSet64? = blockedDomains
    fun domainAllowlist(): SortedHashSet64? = allowedDomains

    companion object {
        private const val DIR = "/intel"

        fun load(): DesktopIntel = DesktopIntel(
            manifest = readManifest(),
            breachedPasswords = resource("$DIR/passwords.mub")
                ?.let { runCatching { BloomFilter.parse(it) }.getOrNull() },
            blockedDomains = resource("$DIR/blocklist.mus")
                ?.let { runCatching { SortedHashSet64.parse(it) }.getOrNull() },
            malwareHashes = resource("$DIR/malware.mus")
                ?.let { runCatching { SortedHashSet64.parse(it) }.getOrNull() },
            allowedDomains = resource("$DIR/allowlist.mus")
                ?.let { runCatching { SortedHashSet64.parse(it) }.getOrNull() }
        )

        /** An empty bundle, for tests and for a build with no generated assets. */
        fun empty(): DesktopIntel = DesktopIntel(null, null, null, null, null)

        private fun resource(path: String): ByteArray? = try {
            DesktopIntel::class.java.getResourceAsStream(path)?.use { it.readBytes() }
        } catch (_: Exception) {
            null
        }

        private fun readManifest(): Manifest? {
            val text = resource("$DIR/manifest.txt")?.decodeToString() ?: return null
            val kv = text.lineSequence()
                .mapNotNull { line ->
                    val trimmed = line.trim()
                    if (trimmed.isEmpty() || trimmed.startsWith("#")) return@mapNotNull null
                    val idx = trimmed.indexOf('=')
                    if (idx <= 0) null else trimmed.substring(0, idx) to trimmed.substring(idx + 1)
                }
                .toMap()

            val builtOn = kv["builtOn"]?.takeIf { IsoDate.isValid(it) } ?: return null
            return Manifest(
                builtOn = builtOn,
                passwordCount = kv["passwords"]?.toLongOrNull() ?: 0L,
                domainCount = kv["domains"]?.toIntOrNull() ?: 0,
                malwareCount = kv["malware"]?.toIntOrNull() ?: 0,
                version = kv["version"] ?: "0",
                synthetic = kv["synthetic"]?.equals("true", ignoreCase = true) == true
            )
        }
    }
}
