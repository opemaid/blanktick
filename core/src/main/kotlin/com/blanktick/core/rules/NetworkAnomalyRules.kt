package com.blanktick.core.rules

import com.blanktick.core.model.Category
import com.blanktick.core.model.DesktopFacts
import com.blanktick.core.model.DeviceSnapshot
import com.blanktick.core.model.Finding
import com.blanktick.core.model.Severity
import com.blanktick.core.model.WifiSecurity

/**
 * Network anomalies a computer can see about its own network WITHOUT making a
 * single connection: everything here is read from tables Windows already keeps
 * (the neighbour/ARP cache, the routing table, the hosts file, the list of
 * Wi-Fi networks the adapter can hear, the proxy settings).
 *
 * Same contract as every other rule: an input that was not read is
 * [RuleOutcome.NotApplicable] (not checkable); a verified "nothing to judge"
 * (not connected, not on Wi-Fi) is [RuleOutcome.DoesNotApply] with the reason.
 */
object NetworkAnomalyRules {

    private inline fun facts(s: DeviceSnapshot, body: (DesktopFacts) -> RuleOutcome): RuleOutcome =
        s.desktop?.let(body) ?: RuleOutcome.NotApplicable

    private fun offline(d: DesktopFacts): RuleOutcome? =
        if (d.networkConnected == false) RuleOutcome.DoesNotApply(
            "This computer was not connected to any network during the scan, so there was no network to inspect."
        ) else null

    /**
     * ARP spoofing: another device answering for the router. On-path attacks on
     * a shared network (café, office, hotel) start by telling every computer
     * "the router's address is my hardware address". The tell-tale is the
     * router's MAC also belonging to some other address in the neighbour table.
     */
    val RouterImpersonation = object : BaseRule(
        id = "DSK-NET-010",
        category = Category.NETWORK,
        description = "No other device on the network is claiming to be the router",
        platforms = Platforms.DESKTOP_ONLY
    ) {
        override fun check(s: DeviceSnapshot) = facts(s) { d ->
            offline(d)?.let { return@facts it }
            val shared = d.routerMacSharedWith ?: return@facts RuleOutcome.NotApplicable
            if (shared.isEmpty()) return@facts RuleOutcome.Pass
            RuleOutcome.Fail(
                Finding(
                    ruleId = id, category = category, severity = Severity.HIGH,
                    title = "Another device on this network is answering as the router",
                    detail = "The router's hardware address is also being used by " +
                        shared.take(3).joinToString(", ") +
                        (if (shared.size > 3) " and ${shared.size - 3} more" else "") +
                        ". That is how a device on the same network puts itself in the middle of your " +
                        "traffic (ARP spoofing). A few home routers and mesh systems legitimately answer " +
                        "on more than one address, so check before panicking — but on a public or shared " +
                        "network, treat this as an attack.",
                    remediation = "Disconnect from this network. Use mobile data or a trusted network, and if " +
                        "this is your own network, restart the router and check which device holds " +
                        shared.first() + ".",
                    evidence = mapOf("sharedWith" to shared.joinToString(","))
                )
            )
        }
    }

    /** Domains whose redirection is almost never innocent: updates, sign-in, banking, mail. */
    private val SENSITIVE = listOf(
        "microsoft", "windowsupdate", "windows.com", "live.com", "office", "outlook", "msftconnect",
        "google", "gmail", "apple", "icloud", "facebook", "instagram", "whatsapp", "amazon",
        "paypal", "bank", "fnb", "absa", "nedbank", "standardbank", "capitec", "investec",
        "defender", "avast", "avg", "kaspersky", "norton", "mcafee", "eset", "sophos", "malwarebytes"
    )

    /** Addresses a blocklist uses to make a name go nowhere — blocking, not redirecting. */
    private fun isSink(ip: String): Boolean =
        ip == "0.0.0.0" || ip == "::" || ip == "::1" || ip == "::0" || ip.startsWith("127.")

    /**
     * Hosts-file hijack: the oldest redirection trick there is, still used by
     * malware to send banking and update traffic to a look-alike, and to stop
     * security tools from updating. Blocklist entries (to 0.0.0.0 / 127.x) are
     * blocking, not redirecting, and are not reported.
     */
    val HostsRedirect = object : BaseRule(
        id = "DSK-NET-011",
        category = Category.NETWORK,
        description = "The hosts file does not redirect websites elsewhere",
        platforms = Platforms.DESKTOP_ONLY
    ) {
        override fun check(s: DeviceSnapshot) = facts(s) { d ->
            val entries = d.hostsEntries ?: return@facts RuleOutcome.NotApplicable
            val redirects = entries.filter { !isSink(it.ip) && !it.name.equals("localhost", true) }
            if (redirects.isEmpty()) return@facts RuleOutcome.Pass
            val (sensitive, other) = redirects.partition { e ->
                val n = e.name.lowercase(); SENSITIVE.any { n.contains(it) }
            }
            RuleOutcome.Fail(buildList {
                if (sensitive.isNotEmpty()) add(
                    Finding(
                        ruleId = id, category = category, severity = Severity.HIGH,
                        title = "The hosts file sends " + sensitive.first().name +
                            (if (sensitive.size > 1) " and ${sensitive.size - 1} other important site(s)" else "") +
                            " to a different address",
                        detail = "On this computer only, " + sensitive.take(3).joinToString("; ") { "${it.name} → ${it.ip}" } +
                            ". Redirecting sign-in, banking, update or security sites through the hosts " +
                            "file is a classic malware technique: you type the right address and land on " +
                            "someone else's server.",
                        remediation = "Open C:\\Windows\\System32\\drivers\\etc\\hosts as administrator and " +
                            "delete these lines unless you added them yourself. Then run a full antivirus scan.",
                        subjectId = "sensitive",
                        evidence = mapOf("entries" to sensitive.joinToString(",") { "${it.name}=${it.ip}" })
                    )
                )
                if (other.isNotEmpty()) add(
                    Finding(
                        ruleId = id, category = category, severity = Severity.LOW,
                        title = "${other.size} name(s) in the hosts file point to a fixed address",
                        detail = other.take(3).joinToString("; ") { "${it.name} → ${it.ip}" } +
                            ". Developers and some apps add these on purpose; it is listed so you can " +
                            "confirm each one is yours.",
                        remediation = "If you do not recognise an entry, remove it from " +
                            "C:\\Windows\\System32\\drivers\\etc\\hosts (as administrator).",
                        subjectId = "other",
                        evidence = mapOf("entries" to other.joinToString(",") { "${it.name}=${it.ip}" })
                    )
                )
            })
        }
    }

    private fun strength(sec: WifiSecurity): Int = when (sec) {
        WifiSecurity.OPEN -> 0
        WifiSecurity.WEP -> 1
        WifiSecurity.OWE, WifiSecurity.WPA -> 2
        WifiSecurity.WPA2 -> 3
        WifiSecurity.WPA3 -> 4
        WifiSecurity.UNKNOWN -> -1
    }

    /**
     * Evil twin: a hotspot broadcasting YOUR network's name with weaker (often
     * no) security, so devices that remember the name join it instead. Several
     * access points with the same name and the same security are normal (mesh,
     * offices); the same name with weaker security is not.
     */
    val EvilTwin = object : BaseRule(
        id = "DSK-NET-012",
        category = Category.NETWORK,
        description = "No look-alike copy of your Wi-Fi network is nearby",
        platforms = Platforms.DESKTOP_ONLY
    ) {
        override fun check(s: DeviceSnapshot) = facts(s) { d ->
            if (d.onWifi == false) return@facts RuleOutcome.DoesNotApply(
                "This computer is not connected to Wi-Fi, so there is no network for a look-alike to copy."
            )
            val mine = s.wifi ?: return@facts RuleOutcome.NotApplicable
            val ssid = mine.ssid ?: return@facts RuleOutcome.NotApplicable
            val nearby = d.nearbyWifi ?: return@facts RuleOutcome.NotApplicable
            val myStrength = strength(mine.security)
            if (myStrength < 0) return@facts RuleOutcome.NotApplicable
            val twins = nearby.filter { it.ssid == ssid && strength(it.security) in 0 until myStrength }
            if (twins.isEmpty()) return@facts RuleOutcome.Pass
            RuleOutcome.Fail(
                Finding(
                    ruleId = id, category = category, severity = Severity.HIGH,
                    title = "A copy of \"$ssid\" with weaker security is nearby",
                    detail = "Your network uses ${mine.security}, but something in range is broadcasting the " +
                        "same name with " + twins.joinToString(" / ") { it.security.name } + ". That is how " +
                        "an \"evil twin\" hotspot lures devices that remember the network's name, so it can " +
                        "read or tamper with their traffic.",
                    remediation = "Stay on the secured network and do not connect to the copy. If your device " +
                        "ever drops to it, forget the network and reconnect choosing the secured one; tell " +
                        "whoever runs the network.",
                    evidence = mapOf("ssid" to ssid, "lookalike" to twins.joinToString(",") { it.security.name })
                )
            )
        }
    }

    /**
     * Proxy auto-config (PAC) script: a single setting that can route every web
     * request through a server of someone's choosing. Common and legitimate in
     * managed workplaces (it is how many corporate web filters work) — and a
     * known malware persistence trick. Listed so it is never silent.
     */
    val AutoProxyScript = object : BaseRule(
        id = "DSK-NET-013",
        category = Category.NETWORK,
        description = "Web traffic is not routed through an automatic proxy script",
        platforms = Platforms.DESKTOP_ONLY
    ) {
        override fun check(s: DeviceSnapshot) = facts(s) { d ->
            if (d.proxySettingsRead != true) return@facts RuleOutcome.NotApplicable
            val url = d.autoProxyConfigUrl?.takeIf { it.isNotBlank() } ?: return@facts RuleOutcome.Pass
            val insecure = url.startsWith("http://", true) || url.startsWith("file:", true)
            RuleOutcome.Fail(
                Finding(
                    ruleId = id, category = category,
                    severity = if (insecure) Severity.MEDIUM else Severity.LOW,
                    title = "Web traffic is routed by a proxy script",
                    detail = "This computer asks $url which proxy to use for every website. If your " +
                        "workplace set this, it is normal. If not, whoever controls that script can see " +
                        "and redirect your browsing." +
                        (if (insecure) " The script itself is fetched without encryption, so anyone on " +
                            "the network path could swap it." else ""),
                    remediation = "If you did not set this and no employer manages this computer: Settings > " +
                        "Network & internet > Proxy, turn off \"Use setup script\".",
                    evidence = mapOf("pac" to url)
                )
            )
        }
    }

    val ALL: List<Rule> = listOf(RouterImpersonation, HostsRedirect, EvilTwin, AutoProxyScript)
}
