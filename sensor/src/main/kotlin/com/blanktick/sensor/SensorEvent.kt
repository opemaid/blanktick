package com.blanktick.sensor

/**
 * Who a process is acting as, as far as the sensor can tell.
 *
 * The privileged provider assigns this from process lineage and the AI/MCP
 * configuration the free tier already reads: a known model runner, or anything
 * launched by an MCP tool entry, is tagged [AI_AGENT] / [MCP_SERVER]. The engine
 * never guesses it — it consumes the tag — which is what lets the AI-layer rules
 * distinguish "a shell the user opened" from "a shell an agent spawned."
 */
enum class Actor { USER, SYSTEM, AI_AGENT, MCP_SERVER, UNKNOWN }

/** The families of process the behavioural rules care about, matched by image basename. */
object Images {
    val OFFICE = setOf(
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
        "msaccess.exe", "mspub.exe", "onenote.exe"
    )

    /**
     * Shells and the living-off-the-land binaries most abused to run a payload.
     * Not exhaustive; the resident sensor extends this from the on-disk
     * `detecting-living-off-the-land-attacks` reference over time.
     */
    val SHELLS_AND_LOLBINS = setOf(
        "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "rundll32.exe", "regsvr32.exe", "installutil.exe",
        "certutil.exe", "bitsadmin.exe", "bash.exe", "curl.exe"
    )

    const val LSASS = "lsass.exe"

    fun basename(image: String): String =
        image.lowercase().substringAfterLast('\\').substringAfterLast('/')

    fun isOffice(image: String): Boolean = basename(image) in OFFICE
    fun isShellOrLolbin(image: String): Boolean = basename(image) in SHELLS_AND_LOLBINS
    fun isLsass(image: String): Boolean = basename(image) == LSASS
}

/** The kind of change made to a file. */
enum class FileOp { WRITE, RENAME, ENCRYPT_SUSPECTED }

/** The engine that executed a script, as reported by AMSI. */
enum class ScriptEngine { POWERSHELL, VBA, JS, DOTNET, OTHER }

/**
 * A single thing the machine did, normalised away from whichever OS facility
 * observed it.
 *
 * Every event carries its own [at] (epoch millis) rather than reading a clock,
 * so a [BehaviorRule] stays a pure function of the events it is handed — the
 * same discipline the free tier's `Rule` follows against a snapshot. A replayed
 * stream and a live one are therefore indistinguishable to a rule, which is what
 * makes every rule below testable without Windows.
 */
sealed interface SensorEvent {
    /** When it happened, epoch millis. The only clock a rule ever sees. */
    val at: Long

    /** The process the event is attributed to. */
    val pid: Long

    /** That process's image (executable). Compared via [Images.basename]. */
    val image: String

    /** Who that process is acting as, per the provider's tagging. */
    val actor: Actor

    /** A process started, with the lineage that makes parent-child rules possible. */
    data class ProcessStart(
        override val at: Long,
        override val pid: Long,
        override val image: String,
        override val actor: Actor = Actor.UNKNOWN,
        val commandLine: String = "",
        val parentPid: Long = -1,
        val parentImage: String = ""
    ) : SensorEvent

    /** A file was written, renamed, or looks like it was encrypted. */
    data class FileModify(
        override val at: Long,
        override val pid: Long,
        override val image: String,
        override val actor: Actor = Actor.UNKNOWN,
        val path: String,
        val op: FileOp,
        /** The written content's entropy jumped into the range typical of ciphertext. */
        val highEntropy: Boolean = false
    ) : SensorEvent

    /** Volume shadow copies were deleted — the classic pre-ransomware move. */
    data class ShadowCopyDeletion(
        override val at: Long,
        override val pid: Long,
        override val image: String,
        override val actor: Actor = Actor.UNKNOWN,
        val commandLine: String = ""
    ) : SensorEvent

    /** A process opened a handle to another — the signal for credential theft from lsass. */
    data class HandleOpen(
        override val at: Long,
        override val pid: Long,
        override val image: String,
        override val actor: Actor = Actor.UNKNOWN,
        val targetImage: String,
        /** The access requested, e.g. `PROCESS_VM_READ`. */
        val access: String = ""
    ) : SensorEvent

    /** Script content at the moment of execution, as surfaced by AMSI. */
    data class ScriptExecution(
        override val at: Long,
        override val pid: Long,
        override val image: String,
        override val actor: Actor = Actor.UNKNOWN,
        val engine: ScriptEngine,
        val content: String
    ) : SensorEvent

    /**
     * A process pulled in content from outside the machine — a web page, a
     * mailbox, a document. The left half of the prompt-injection pairing: when
     * an agent acts right after one of these, that ordering is the tell.
     */
    data class ContentIntake(
        override val at: Long,
        override val pid: Long,
        override val image: String,
        override val actor: Actor = Actor.UNKNOWN,
        /** Where the content came from, e.g. a URL or `email`. */
        val source: String
    ) : SensorEvent

    /**
     * An outbound connection this machine made. The raw material for spotting a
     * beacon: the same process calling the same destination on a regular beat.
     */
    data class NetworkConnect(
        override val at: Long,
        override val pid: Long,
        override val image: String,
        override val actor: Actor = Actor.UNKNOWN,
        val remoteAddress: String,
        val remotePort: Int,
        val protocol: String = "TCP"
    ) : SensorEvent

    /**
     * A DNS name this machine resolved. Not attributed to a process when it comes
     * from the resolver cache (pid = -1); the ETW DNS-Client provider adds the
     * process. The name's shape alone reveals tunneling.
     */
    data class DnsQuery(
        override val at: Long,
        override val pid: Long,
        override val image: String,
        override val actor: Actor = Actor.UNKNOWN,
        val queryName: String
    ) : SensorEvent
}
