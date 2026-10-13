package com.blanktick.sensor.providers

import com.blanktick.sensor.Actor
import com.blanktick.sensor.SensorEvent

/**
 * A coarse, honestly-labelled proxy for an AI agent pulling in outside content —
 * the left half of the prompt-injection pairing DYN-AI-003 correlates.
 *
 * ## This is a proxy, not true intake observation
 *
 * A user-level OS poll cannot watch an assistant read a local file or receive
 * content inside its own process. The one machine-visible signal it has is a new
 * outbound connection by a process whose *image* is a known model runner. So
 * this tap:
 *   - misses claude.exe, an MCP node/python helper, or any agent not named in
 *     the model-runner list;
 *   - cannot tell a model-weight download from a web fetch.
 * Real intake detection needs the MCP tool call itself instrumented
 * (securing-agentic-ai-tool-invocation), which is agent-side. A firing here is a
 * lead for DYN-AI-003 to correlate against a following action, not proof.
 *
 * Every event it emits is tagged [Actor.AI_AGENT] so the rule treats it as agent
 * intake. [Privilege.USER]; it opens no socket, it reads the local TCP table.
 */
class ContentIntakeProvider : ScriptTapProvider(
    "/content-intake-provider.ps1",
    "ai-content-intake (model-runner egress proxy)",
    Privilege.USER,
    "PROXY only: sees outbound connections by known model-runner images; misses claude/MCP " +
        "helpers and in-process or local-file intake. Real coverage needs MCP tool-call instrumentation"
) {
    override fun parse(line: String): SensorEvent? = parseLine(line)

    /** Parse `at<TAB>pid<TAB>image<TAB>source`. */
    internal fun parseLine(line: String): SensorEvent.ContentIntake? {
        if (line.startsWith("#") || line.isBlank()) return null
        val f = line.split('\t')
        if (f.size < 4) return null
        val at = f[0].toLongOrNull() ?: return null
        val pid = f[1].toLongOrNull() ?: -1L
        val image = f[2]
        val source = f[3]
        if (source.isBlank()) return null
        return SensorEvent.ContentIntake(
            at = at, pid = pid, image = image, actor = Actor.AI_AGENT, source = source
        )
    }
}
