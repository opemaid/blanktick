package com.blanktick.desktop

import java.io.File

/**
 * User preferences, and the only thing Blanktick writes to disk.
 *
 * ## Read this before adding a field
 *
 * Until now the desktop app wrote **nothing at all** — no config, no cache, no
 * history, no telemetry. That was a deliberate posture, and adding a settings
 * file spends part of it. So the file is bounded by rule, not by intention:
 *
 * **It may contain UI preferences and nothing else.** No scan results, no
 * scores, no findings, no history, no machine identifiers, no paths to anything
 * except a folder the user themselves chose. Persisting how insecure someone's
 * computer was is exactly what decision D-05 forbids, and a settings file is
 * the obvious place that would quietly begin.
 *
 * The About screen states the file's location and the app prints its full
 * contents in Settings, because "nothing leaves this computer" was never the
 * same claim as "nothing is written" and the difference should be visible
 * rather than argued.
 *
 * ## Format
 *
 * Line-oriented `key=value`, the same shape as the intel manifest, for the same
 * reason: it needs no parser dependency (decision D-03), and a person reading a
 * privacy claim should be able to read the evidence file in a text editor.
 */
data class Settings(
    /**
     * Compose Desktop exposes no API for the OS reduce-motion preference — the
     * platform reviewer verified this two ways — so DD-10 cannot be honoured
     * automatically and this switch is the only path to honouring it at all.
     */
    val reduceMotion: Boolean = false,
    /**
     * LIGHT by default, not SYSTEM: the warm paper theme is the brand (it is
     * blanktick.org and the ads), so a new install opens on it even when Windows
     * is in dark mode. Dark and "follow Windows" stay one click away in Settings.
     */
    val theme: ThemeChoice = ThemeChoice.LIGHT,
    /** 1.0 = platform default. Compose Desktop does not read the OS text-size slider. */
    val textScale: Float = 1.0f,
    /** Last folder chosen in the photo scanner. A path the user picked themselves. */
    val lastPhotoFolder: String? = null,
    /**
     * Whether to keep a local, summary-only history of past scans that an MCP
     * client can search. The history lives in a separate file (history.jsonl),
     * never here.
     *
     * This is a *behaviour preference*, which is why it belongs in this file;
     * the scan data it gates does not, which is why that data lives elsewhere.
     * Off by default: it enables the one thing decision D-05 warned against, so
     * the default posture stays "keep nothing" and turning it on is the user's
     * explicit act. See [com.blanktick.desktop.history.ScanHistory].
     */
    val keepHistory: Boolean = false
) {
    enum class ThemeChoice { SYSTEM, LIGHT, DARK }

    fun serialise(): String = buildString {
        appendLine("# Blanktick settings. UI preferences only.")
        appendLine("#")
        // Was "the only file Blanktick writes ... no history" — untrue once
        // keepHistory existed, and printed on screen as proof of the claim.
        appendLine("# This file holds preferences only: no scan results, no scores, no findings")
        appendLine("# and nothing identifying this machine. Scan history, if you turn it on, is")
        appendLine("# kept in history.jsonl beside this file. Delete either at any time; the app")
        appendLine("# will start again with defaults.")
        appendLine()
        appendLine("reduceMotion=$reduceMotion")
        appendLine("theme=${theme.name.lowercase()}")
        appendLine("textScale=$textScale")
        lastPhotoFolder?.let { appendLine("lastPhotoFolder=$it") }
        appendLine("keepHistory=$keepHistory")
    }

    companion object {
        /**
         * Where the file lives, per platform convention.
         *
         * Falls back to the user's home directory if the environment gives us
         * nothing usable — better a predictable location than a silent failure
         * to persist.
         */
        fun file(): File {
            val home = System.getProperty("user.home") ?: "."
            val dir = when {
                System.getProperty("os.name").orEmpty().lowercase().contains("win") ->
                    System.getenv("APPDATA")?.let { File(it, "Blanktick") }
                System.getProperty("os.name").orEmpty().lowercase().let {
                    it.contains("mac") || it.contains("darwin")
                } -> File(home, "Library/Application Support/Blanktick")
                else -> System.getenv("XDG_CONFIG_HOME")?.let { File(it, "blanktick") }
                    ?: File(home, ".config/blanktick")
            } ?: File(home, ".blanktick")
            return File(dir, "settings.conf")
        }

        fun load(): Settings = runCatching {
            val f = file()
            if (!f.isFile) return@runCatching Settings()

            val kv = f.readLines()
                .mapNotNull { line ->
                    val t = line.trim()
                    if (t.isEmpty() || t.startsWith("#")) return@mapNotNull null
                    val i = t.indexOf('=')
                    if (i <= 0) null else t.substring(0, i) to t.substring(i + 1)
                }
                .toMap()

            Settings(
                reduceMotion = kv["reduceMotion"]?.toBooleanStrictOrNull() ?: false,
                theme = kv["theme"]?.let { v ->
                    ThemeChoice.entries.firstOrNull { it.name.equals(v, ignoreCase = true) }
                } ?: ThemeChoice.LIGHT,
                // Clamped rather than trusted: a hand-edited 40.0 would render an
                // unusable window with no way back to Settings to fix it.
                textScale = kv["textScale"]?.toFloatOrNull()?.coerceIn(0.8f, 2.0f) ?: 1.0f,
                lastPhotoFolder = kv["lastPhotoFolder"]?.takeIf { it.isNotBlank() },
                keepHistory = kv["keepHistory"]?.toBooleanStrictOrNull() ?: false
            )
        }.getOrDefault(Settings())

        /** @return true if it was written. Failure is non-fatal and reported in the UI. */
        fun save(settings: Settings): Boolean = runCatching {
            val f = file()
            f.parentFile?.mkdirs()
            f.writeText(settings.serialise())
            true
        }.getOrDefault(false)
    }
}
