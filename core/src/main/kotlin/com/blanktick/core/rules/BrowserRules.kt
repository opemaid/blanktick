package com.blanktick.core.rules

import com.blanktick.core.model.BrowserExtension
import com.blanktick.core.model.Category
import com.blanktick.core.model.DeviceSnapshot
import com.blanktick.core.model.Finding
import com.blanktick.core.model.Severity

/**
 * The browser-extension surface — what is riding inside Chrome, Edge, Firefox
 * and the Chromium forks.
 *
 * ## Why this is worth a rule of its own
 *
 * The coverage review found the whole product blind here, and it is the one
 * place a fully-clean posture audit can still miss the thing that actually
 * robs people. A malicious extension does not need administrator rights, does
 * not write a Run key, does not masquerade as a system process, and does not
 * show up in any of the persistence sources Blanktick already reads. It sits in
 * the browser, where the passwords, sessions and banking tabs are, and it got
 * there by one of two routes: the user installed it from a store, or something
 * placed it by hand.
 *
 * ## What is checkable offline, and what is not
 *
 * Everything here is read from local manifest files in each browser profile —
 * no network, no store lookup. So Blanktick can say *where an extension came
 * from* and *what it can reach*, both of which are properties of the machine.
 * It cannot say whether a specific store extension has since turned malicious;
 * that is a reputation question and needs the intel a network would carry.
 * These rules therefore score on provenance and access, never on a name.
 *
 * Desktop only. Returns [RuleOutcome.NotApplicable] where no browser profile
 * could be read, which the UI shows as "not checkable" — never as a pass.
 */
object BrowserRules {

    /** Provenance the browser itself vets: the store, and the browser's own built-ins. */
    private val VETTED_SOURCES = setOf("store", "component")

    /**
     * Non-store provenance, and how loudly to say it.
     *
     * `unpacked` (loaded from a folder in developer mode) and `sideload` have
     * essentially no innocent explanation on an ordinary machine, so they are
     * HIGH. `registry` / `external` / `policy` force-installs are the adware
     * route but are also how a managed laptop legitimately deploys extensions,
     * so they are MEDIUM and worded as "confirm you expected this".
     */
    private val SEVERITY_BY_SOURCE = mapOf(
        "unpacked" to Severity.HIGH,
        "sideload" to Severity.HIGH,
        "registry" to Severity.MEDIUM,
        "external" to Severity.MEDIUM,
        "policy" to Severity.MEDIUM
    )

    /** APIs that turn broad host access into "can read or redirect your traffic and data". */
    private val SENSITIVE_APIS = setOf(
        "webrequest", "webrequestblocking", "declarativenetrequest",
        "cookies", "debugger", "proxy", "nativemessaging", "history", "downloads"
    )

    private fun broadHostAccess(e: BrowserExtension): Boolean {
        val hosts = e.hostPermissions.map { it.trim().lowercase() }
        if (hosts.any { it == "<all_urls>" || it == "*://*/*" || it == "*://*/" }) return true
        val http = hosts.any { it.startsWith("http://*/") }
        val https = hosts.any { it.startsWith("https://*/") }
        return http && https
    }

    private fun sensitiveApis(e: BrowserExtension): List<String> =
        e.apiPermissions.map { it.trim().lowercase() }.filter { it in SENSITIVE_APIS }.distinct()

    /**
     * DSK-EXT-001 — an extension the browser's store did not deliver.
     *
     * The highest-confidence thing this file says, and the one that catches the
     * infostealer case: an extension loaded unpacked or written in by another
     * program is not a borderline judgement, it is a route that vetted software
     * does not take.
     */
    val StoreProvenance = object : BaseRule(
        id = "DSK-EXT-001",
        category = Category.APP_HYGIENE,
        description = "All browser extensions came from an official store",
        platforms = Platforms.DESKTOP_ONLY
    ) {
        override fun check(s: DeviceSnapshot) = requireObserved(s.desktop?.browserExtensions) { exts ->
            val offenders = exts.mapNotNull { e ->
                val source = e.installSource?.lowercase()
                val severity = SEVERITY_BY_SOURCE[source] ?: return@mapNotNull null
                Triple(e, source!!, severity)
            }
            if (offenders.isEmpty()) return@requireObserved RuleOutcome.Pass

            RuleOutcome.Fail(
                offenders.map { (e, source, severity) ->
                    val how = when (source) {
                        "unpacked" -> "was loaded from a folder in developer mode"
                        "sideload" -> "was side-loaded"
                        "registry", "external" -> "was installed by another program writing to the registry, not from the store"
                        "policy" -> "was force-installed by a policy on this machine"
                        else -> "did not come from the store"
                    }
                    Finding(
                        ruleId = id,
                        category = category,
                        severity = severity,
                        subjectId = "${e.browser}:${e.id}",
                        title = "\"${e.name}\" in ${e.browser} did not come from the store",
                        detail = "This ${e.browser} extension $how. Extensions that skip the store " +
                            "are not reviewed and do not update through it, and that is the usual " +
                            "way an extension that steals saved passwords or session cookies gets " +
                            "onto an otherwise-clean machine. It can read what you type and see on " +
                            "the sites its permissions cover." +
                            if (severity == Severity.MEDIUM) " On a work-managed computer this can be normal." else "",
                        remediation = "Open ${e.browser}'s extensions page, confirm you deliberately " +
                            "added \"${e.name}\", and remove it if you did not. If it is one you " +
                            "want, reinstall it from the official store so it is vetted and updates.",
                        evidence = mapOf(
                            "browser" to e.browser,
                            "id" to e.id,
                            "installSource" to source,
                            "enabled" to (e.enabled?.toString() ?: "unknown"),
                            "hostPermissions" to e.hostPermissions.joinToString(" ").take(200)
                        )
                    )
                }
            )
        }
    }

    /**
     * DSK-EXT-002 — enabled extensions that can read everything you browse.
     *
     * Deliberately INFO, not a deduction. A password manager and an ad blocker
     * legitimately hold exactly this combination, so scoring it would punish
     * healthy machines and train people to ignore the finding. The honest job
     * is to *show the surface* — the extensions that, if any one of them ever
     * turned, could read every page and session — and let the person decide.
     */
    val BroadAccess = object : BaseRule(
        id = "DSK-EXT-002",
        category = Category.APP_HYGIENE,
        description = "You know which extensions can read everything you browse",
        platforms = Platforms.DESKTOP_ONLY
    ) {
        override fun check(s: DeviceSnapshot) = requireObserved(s.desktop?.browserExtensions) { exts ->
            val broad = exts.filter { it.enabled != false && broadHostAccess(it) && sensitiveApis(it).isNotEmpty() }
            if (broad.isEmpty()) return@requireObserved RuleOutcome.Pass

            RuleOutcome.Fail(
                broad.map { e ->
                    val apis = sensitiveApis(e)
                    Finding(
                        ruleId = id,
                        category = category,
                        severity = Severity.INFO,
                        subjectId = "${e.browser}:${e.id}",
                        title = "\"${e.name}\" can read everything you do in ${e.browser}",
                        detail = "This extension has access to every site plus " +
                            apis.joinToString(", ") + ". That is normal for tools like password " +
                            "managers and ad blockers, and it also means this one extension could, " +
                            "if it ever turned, read your pages, traffic and signed-in sessions. " +
                            "Shown so you know what holds that reach — it is not a problem by itself.",
                        remediation = "",
                        evidence = mapOf(
                            "browser" to e.browser,
                            "id" to e.id,
                            "installSource" to (e.installSource ?: "unknown"),
                            "apis" to apis.joinToString(" ")
                        )
                    )
                }
            )
        }
    }

    val ALL: List<Rule> = listOf(StoreProvenance, BroadAccess)
}
