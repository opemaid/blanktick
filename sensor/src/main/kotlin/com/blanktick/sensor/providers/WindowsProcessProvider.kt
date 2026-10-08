package com.blanktick.sensor.providers

import com.blanktick.sensor.Actor
import com.blanktick.sensor.Images
import com.blanktick.sensor.SensorEvent

/**
 * Process starts read from Windows, in two fidelities behind one interface.
 *
 * [poll] is the elevation-free fallback: it runs a bundled PowerShell script
 * that polls `Win32_Process`, sees the current user's view, and can miss a
 * process that lived and died between two ticks.
 *
 * [etw] is the privileged upgrade: it subscribes to `Win32_ProcessStartTrace`,
 * the WMI surface of the NT kernel's process ETW trace — push-based (no poll
 * gap) and machine-wide. It needs administrator rights.
 *
 * Both emit the same tab-separated line and share one parser, so everything
 * above this class is identical whichever is running.
 */
class WindowsProcessProvider private constructor(
    scriptResource: String, name: String, privilege: Privilege, statusNote: String
) : ScriptTapProvider(scriptResource, name, privilege, statusNote) {

    /** Default: the elevation-free poll tap. */
    constructor() : this(POLL_SCRIPT, "windows-process (Win32_Process poll)", Privilege.USER, POLL_NOTE)

    /** Model runners we can name from the image alone; broader MCP-lineage tagging is the next step. */
    private val agentImages = setOf(
        "ollama.exe", "ollama app.exe", "lmstudio.exe", "lm studio.exe",
        "jan.exe", "gpt4all.exe", "llama-server.exe", "koboldcpp.exe", "localai.exe"
    )

    override fun parse(line: String): SensorEvent? = parseLine(line)

    /**
     * Parse one `at<TAB>pid<TAB>ppid<TAB>parentImage<TAB>image<TAB>commandLine` line.
     * Returns null on anything malformed rather than guessing.
     */
    internal fun parseLine(line: String): SensorEvent.ProcessStart? {
        val f = line.split('\t')
        if (f.size < 5) return null
        val at = f[0].toLongOrNull() ?: return null
        val pid = f[1].toLongOrNull() ?: return null
        val ppid = f[2].toLongOrNull() ?: -1L
        val parentImage = f[3]
        val image = f[4]
        val commandLine = if (f.size >= 6) f[5] else ""
        val actor = if (Images.basename(image) in agentImages) Actor.AI_AGENT else Actor.UNKNOWN
        return SensorEvent.ProcessStart(
            at = at, pid = pid, image = image, actor = actor,
            commandLine = commandLine, parentPid = ppid, parentImage = parentImage
        )
    }

    companion object {
        private const val POLL_SCRIPT = "/process-provider.ps1"
        private const val ETW_SCRIPT = "/process-provider-etw.ps1"
        private const val POLL_NOTE =
            "user-level Win32_Process poll; ETW Kernel-Process (admin) is the higher-fidelity upgrade"
        private const val ETW_NOTE =
            "privileged Win32_ProcessStartTrace (ETW-backed, machine-wide, event-driven)"

        /** The elevation-free poll tap. */
        fun poll(): WindowsProcessProvider = WindowsProcessProvider()

        /** The privileged, event-driven, machine-wide tap. Needs admin to produce events. */
        fun etw(): WindowsProcessProvider =
            WindowsProcessProvider(
                ETW_SCRIPT, "windows-process (Win32_ProcessStartTrace / ETW)", Privilege.ADMIN, ETW_NOTE
            )
    }
}
