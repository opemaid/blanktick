package com.blanktick.sensor.rules

import com.blanktick.core.model.Category
import com.blanktick.core.model.Finding
import com.blanktick.core.model.Severity
import com.blanktick.sensor.Actor
import com.blanktick.sensor.BehaviorRule
import com.blanktick.sensor.Detection
import com.blanktick.sensor.FileOp
import com.blanktick.sensor.Images
import com.blanktick.sensor.Response
import com.blanktick.sensor.RollingWindow
import com.blanktick.sensor.SensorEvent

/** Processes acting as the local AI layer, per the provider's tagging. */
private val AGENT_ACTORS = setOf(Actor.AI_AGENT, Actor.MCP_SERVER)

/** Legitimate readers of lsass; anything else opening it is the credential-theft tell. */
private val LSASS_LEGITIMATE_READERS = setOf("lsass.exe", "wininit.exe", "services.exe", "csrss.exe")

private fun det(
    ruleId: String,
    category: Category,
    severity: Severity,
    title: String,
    detail: String,
    remediation: String,
    subjectId: String,
    response: Response,
    evidence: Map<String, String>,
    targetPid: Long? = null
): Detection = Detection(
    Finding(
        ruleId = ruleId,
        category = category,
        severity = severity,
        title = title,
        detail = detail,
        remediation = remediation,
        subjectId = subjectId,
        evidence = evidence
    ),
    response,
    targetPid
)

/**
 * The classic behavioural detections (built to the on-disk `detecting-*`
 * references) plus the two that are Blanktick's own: defending the local AI/MCP
 * layer. All are pure functions of an event and the recent window.
 */
object DefaultBehaviorRules {

    /**
     * DYN-OFFICE-001 — an Office document spawned a shell or LOLBin.
     *
     * Word/Excel/Outlook launching powershell, mshta or rundll32 is the standard
     * shape of a malicious document detonating. Almost nothing legitimate does it.
     */
    val OfficeSpawnsShell = object : BehaviorRule {
        override val id = "DYN-OFFICE-001"
        override val category = Category.DEVICE_INTEGRITY
        override fun onEvent(e: SensorEvent, w: RollingWindow): List<Detection> {
            if (e !is SensorEvent.ProcessStart) return emptyList()
            if (!Images.isOffice(e.parentImage) || !Images.isShellOrLolbin(e.image)) return emptyList()
            return listOf(
                det(
                    ruleId = id, category = category, severity = Severity.HIGH, response = Response.KILL,
                    title = "An Office document just launched \"" + Images.basename(e.image) + "\"",
                    detail = Images.basename(e.parentImage) + " started " + Images.basename(e.image) +
                        " (" + e.commandLine + "). A document spawning a shell or scripting host is how a " +
                        "malicious attachment runs its payload; it is almost never something an ordinary " +
                        "document needs to do.",
                    remediation = "Close the document. If you did not expect it to run anything, treat the " +
                        "file as malicious and the account as exposed until checked.",
                    subjectId = "pid:" + e.pid,
                    targetPid = e.pid,
                    evidence = mapOf(
                        "parent" to e.parentImage, "child" to e.image, "commandLine" to e.commandLine
                    )
                )
            )
        }
    }

    /**
     * DYN-CRED-001 — a process that has no business doing so opened lsass.
     *
     * Reading lsass memory is how credentials are dumped. A short allow-list of
     * the OS processes that legitimately touch it keeps this from firing on
     * Windows itself.
     */
    val LsassHandleTheft = object : BehaviorRule {
        override val id = "DYN-CRED-001"
        override val category = Category.ACCOUNT_SECURITY
        override fun onEvent(e: SensorEvent, w: RollingWindow): List<Detection> {
            if (e !is SensorEvent.HandleOpen) return emptyList()
            if (!Images.isLsass(e.targetImage)) return emptyList()
            if (Images.basename(e.image) in LSASS_LEGITIMATE_READERS) return emptyList()
            return listOf(
                det(
                    ruleId = id, category = category, severity = Severity.CRITICAL, response = Response.SUSPEND,
                    title = "\"" + Images.basename(e.image) + "\" opened the process that holds your passwords",
                    detail = Images.basename(e.image) + " requested " + (e.access.ifBlank { "access" }) +
                        " to lsass, the process that keeps signed-in credentials in memory. Outside a handful " +
                        "of Windows components, that is what credential-stealing tools do.",
                    remediation = "Suspend the process and investigate it. Assume passwords and tokens used on " +
                        "this machine may have been read; rotate them.",
                    subjectId = "pid:" + e.pid,
                    targetPid = e.pid,
                    evidence = mapOf("process" to e.image, "target" to e.targetImage, "access" to e.access)
                )
            )
        }
    }

    /**
     * DYN-RANSOM-001 — mass encryption-shaped writes, or shadow-copy deletion.
     *
     * Two independent tells. Deleting volume shadow copies is a near-certain
     * pre-encryption move on its own. A burst of high-entropy writes from one
     * process in a few seconds is encryption in progress.
     */
    val RansomwareMassWrite = object : BehaviorRule {
        override val id = "DYN-RANSOM-001"
        override val category = Category.DEVICE_INTEGRITY
        private val burstWindowMillis = 5_000L
        private val burstThreshold = 12

        override fun onEvent(e: SensorEvent, w: RollingWindow): List<Detection> {
            if (e is SensorEvent.ShadowCopyDeletion) {
                return listOf(
                    det(
                        ruleId = id, category = category, severity = Severity.CRITICAL, response = Response.KILL,
                        title = "\"" + Images.basename(e.image) + "\" is deleting your backups",
                        detail = Images.basename(e.image) + " deleted volume shadow copies (" + e.commandLine +
                            "). This removes Windows' own ability to roll files back, and it is one of the last " +
                            "steps before ransomware encrypts.",
                        remediation = "Kill the process now and disconnect the machine from any shared storage.",
                        subjectId = "pid:" + e.pid,
                    targetPid = e.pid,
                        evidence = mapOf("process" to e.image, "commandLine" to e.commandLine)
                    )
                )
            }
            if (e !is SensorEvent.FileModify) return emptyList()
            if (!(e.highEntropy || e.op == FileOp.ENCRYPT_SUSPECTED)) return emptyList()

            val burst = w.within(e.at, burstWindowMillis).count {
                it is SensorEvent.FileModify && it.pid == e.pid &&
                    (it.highEntropy || it.op == FileOp.ENCRYPT_SUSPECTED)
            }
            if (burst < burstThreshold) return emptyList()
            return listOf(
                det(
                    ruleId = id, category = category, severity = Severity.CRITICAL, response = Response.KILL,
                    title = "\"" + Images.basename(e.image) + "\" is rewriting many files at once",
                    detail = Images.basename(e.image) + " rewrote " + burst + " files with encryption-shaped " +
                        "content in the last " + (burstWindowMillis / 1000) + " seconds. That pattern is " +
                        "ransomware encrypting your data.",
                    remediation = "Kill the process now and disconnect from shared storage. Recover affected " +
                        "files from a backup made before this started.",
                    subjectId = "pid:" + e.pid,
                    targetPid = e.pid,
                    evidence = mapOf("process" to e.image, "encryptedInWindow" to burst.toString())
                )
            )
        }
    }

    /**
     * DYN-AI-001 — an AI agent or MCP tool spawned a shell or LOLBin.
     *
     * Blanktick's own ground. When a process tagged as the local AI layer starts
     * cmd/powershell/mshta, either the agent was told to (by a user or by
     * injected content) or a tool call is being abused. Either way it is exactly
     * the moment the free tier's static DSK-AI rules warned could happen.
     */
    val AgentSpawnsShell = object : BehaviorRule {
        override val id = "DYN-AI-001"
        override val category = Category.APP_HYGIENE
        override fun onEvent(e: SensorEvent, w: RollingWindow): List<Detection> {
            if (e !is SensorEvent.ProcessStart) return emptyList()
            if (!Images.isShellOrLolbin(e.image)) return emptyList()
            val parentActor = w.latestProcessStart(e.parentPid)?.actor ?: e.actor
            if (parentActor !in AGENT_ACTORS) return emptyList()
            return listOf(
                det(
                    ruleId = id, category = category, severity = Severity.HIGH, response = Response.SUSPEND,
                    title = "An AI assistant just started \"" + Images.basename(e.image) + "\"",
                    detail = "A process acting as the local AI layer spawned " + Images.basename(e.image) +
                        " (" + e.commandLine + "). An assistant running a shell means it is executing " +
                        "commands as you — expected if you asked it to, and exactly what an injected " +
                        "instruction in content it read would also do.",
                    remediation = "If you did not ask for this, suspend it and review what the assistant was " +
                        "reading. Consider removing the tool that grants command execution.",
                    subjectId = "pid:" + e.pid,
                    targetPid = e.pid,
                    evidence = mapOf(
                        "child" to e.image, "commandLine" to e.commandLine,
                        "parentActor" to parentActor.name
                    )
                )
            )
        }
    }

    /**
     * DYN-AI-003 — an AI agent acted right after reading outside content.
     *
     * The dynamic form of the free tier's prompt-injection reach check. A file
     * write or process launch by an agent within seconds of it ingesting an
     * external page/email is the ordering an indirect prompt injection produces:
     * read attacker text, then act on it.
     */
    val AgentActsAfterIntake = object : BehaviorRule {
        override val id = "DYN-AI-003"
        override val category = Category.APP_HYGIENE
        private val reactWindowMillis = 10_000L

        override fun onEvent(e: SensorEvent, w: RollingWindow): List<Detection> {
            val actorHere = when (e) {
                is SensorEvent.FileModify -> e.actor
                is SensorEvent.ProcessStart -> w.latestProcessStart(e.parentPid)?.actor ?: e.actor
                else -> return emptyList()
            }
            if (actorHere !in AGENT_ACTORS) return emptyList()

            val recentIntake = w.within(e.at, reactWindowMillis)
                .filterIsInstance<SensorEvent.ContentIntake>()
                .lastOrNull { it.pid == e.pid || it.actor in AGENT_ACTORS }
                ?: return emptyList()

            val action = when (e) {
                is SensorEvent.FileModify -> "wrote " + e.path
                is SensorEvent.ProcessStart -> "started " + Images.basename(e.image)
                else -> "acted"
            }
            return listOf(
                det(
                    ruleId = id, category = category, severity = Severity.MEDIUM, response = Response.ALERT,
                    title = "An AI assistant acted right after reading outside content",
                    detail = "The assistant read content from " + recentIntake.source + ", then " + action +
                        " within " + (reactWindowMillis / 1000) + " seconds. That ordering — read outside " +
                        "content, then act — is what an indirect prompt injection looks like: instructions " +
                        "hidden in the content steering the tools the assistant can use.",
                    remediation = "Check what was read and whether the action was one you intended. If not, " +
                        "treat the source as hostile and separate the assistant's reading tools from its " +
                        "acting tools.",
                    subjectId = "pid:" + e.pid,
                    targetPid = e.pid,
                    evidence = mapOf("source" to recentIntake.source, "action" to action)
                )
            )
        }
    }

    /**
     * DYN-C2-001 — a process is calling one destination on a regular beat.
     *
     * Command-and-control beacons check in at a steady interval. This looks for
     * the same process connecting to the same address and port several times
     * with low jitter. It flags the *pattern* only: naming the destination as
     * known-bad needs a threat-intel bundle, which Blanktick imports offline
     * rather than fetching. So this is an ALERT to investigate, never a verdict
     * that the host is malicious.
     */
    val BeaconingC2 = object : BehaviorRule {
        override val id = "DYN-C2-001"
        override val category = Category.NETWORK
        private val minBeacons = 4
        private val maxJitterRatio = 0.5

        override fun onEvent(e: SensorEvent, w: RollingWindow): List<Detection> {
            if (e !is SensorEvent.NetworkConnect) return emptyList()
            val same = w.ofType<SensorEvent.NetworkConnect>().filter {
                it.pid == e.pid && it.remoteAddress == e.remoteAddress && it.remotePort == e.remotePort
            }
            if (same.size < minBeacons) return emptyList()

            val times = same.map { it.at }.sorted()
            val intervals = times.zipWithNext { a, b -> b - a }.filter { it > 0 }
            if (intervals.size < minBeacons - 1) return emptyList()
            val mean = intervals.average()
            if (mean <= 0.0) return emptyList()
            val jitter = (intervals.maxOrNull()!! - intervals.minOrNull()!!) / mean
            if (jitter > maxJitterRatio) return emptyList()

            val dest = e.remoteAddress + ":" + e.remotePort
            val everySec = (mean / 1000.0).toLong()
            return listOf(
                det(
                    ruleId = id, category = category, severity = Severity.MEDIUM, response = Response.ALERT,
                    title = "\"" + Images.basename(e.image) + "\" is calling " + dest + " on a regular beat",
                    detail = Images.basename(e.image) + " has connected to " + dest + " " + same.size +
                        " times at a roughly regular interval (about every " + everySec + "s). Steady, " +
                        "evenly spaced callbacks from one process are how a C2 beacon checks in. This flags " +
                        "the pattern; it cannot say the destination is malicious — that needs an imported " +
                        "threat-intel bundle, not a network call.",
                    remediation = "Check what " + Images.basename(e.image) + " is and whether it should be " +
                        "talking to " + dest + " on a timer. If you do not recognise it, cut its network " +
                        "access and investigate.",
                    subjectId = "beacon:" + e.pid + ":" + dest,
                    targetPid = e.pid,
                    evidence = mapOf(
                        "process" to e.image, "remote" to dest,
                        "connections" to same.size.toString(), "meanIntervalMs" to mean.toLong().toString()
                    )
                )
            )
        }
    }

    /**
     * DYN-DNS-001 — a DNS name shaped like it is carrying data.
     *
     * Tunneling and exfiltration over DNS encode bytes into the subdomain, so the
     * name is unusually long or has an unusually long single label. Some CDNs use
     * long names too, so this is worth knowing rather than proof — an ALERT, not
     * a verdict.
     */
    val DnsTunneling = object : BehaviorRule {
        override val id = "DYN-DNS-001"
        override val category = Category.NETWORK
        private val maxNormalTotal = 100
        private val maxNormalLabel = 40

        override fun onEvent(e: SensorEvent, w: RollingWindow): List<Detection> {
            if (e !is SensorEvent.DnsQuery) return emptyList()
            val name = e.queryName.trimEnd('.')
            if (name.isEmpty()) return emptyList()
            val longest = name.split('.').maxOfOrNull { it.length } ?: 0
            if (name.length < maxNormalTotal && longest < maxNormalLabel) return emptyList()

            val shown = if (name.length > 60) name.take(60) + "..." else name
            return listOf(
                det(
                    ruleId = id, category = category, severity = Severity.MEDIUM, response = Response.ALERT,
                    title = "An unusually long DNS name was looked up",
                    detail = "The name \"" + shown + "\" is " + name.length + " characters, with a " +
                        longest + "-character label. Names shaped like this are how data is smuggled out " +
                        "over DNS — each lookup carries encoded bytes in the subdomain. Some content " +
                        "networks use long names too, so treat this as worth checking rather than proof.",
                    remediation = "If you do not recognise the domain, find which process resolved it and " +
                        "treat it as possible data exfiltration over DNS.",
                    subjectId = "dns:" + name.take(80),
                    evidence = mapOf(
                        "name" to name.take(120), "length" to name.length.toString(),
                        "longestLabel" to longest.toString()
                    )
                )
            )
        }
    }

    val ALL: List<BehaviorRule> = listOf(
        OfficeSpawnsShell,
        LsassHandleTheft,
        RansomwareMassWrite,
        AgentSpawnsShell,
        AgentActsAfterIntake,
        BeaconingC2,
        DnsTunneling
    )
}
