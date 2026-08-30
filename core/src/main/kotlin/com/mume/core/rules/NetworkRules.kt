package com.mume.core.rules

import com.mume.core.model.Category
import com.mume.core.model.DeviceSnapshot
import com.mume.core.model.Finding
import com.mume.core.model.Platform
import com.mume.core.model.Severity
import com.mume.core.model.WifiSecurity

/**
 * Network-position rules.
 *
 * ## Why these beat a cloud reputation check
 *
 * The kickoff plan had a "MITM probe": call our own pinned endpoint and see
 * whether the certificate chain was substituted. That test is defeated by any
 * interception proxy configured to pass our one hostname through untouched.
 *
 * The offline replacements below inspect the *device's own configuration* —
 * trust store, proxy settings, DNS servers, VPN ownership. An attacker cannot
 * hide a user-installed root CA from the device that is using it. Removing the
 * network made this category strictly stronger, not weaker.
 */
object NetworkRules {

    /**
     * A CA certificate the user (or malware, or an employer) added to the trust
     * store. This is the single highest-signal local indicator of active TLS
     * interception, and it is exactly what Burp Suite and mitmproxy require.
     */
    val UserInstalledCa = object : BaseRule(
        id = "NET-CA-001",
        category = Category.NETWORK,
        description = "No extra certificate authorities are trusted",
        platforms = Platforms.ANDROID_AND_DESKTOP
    ) {
        override fun check(s: DeviceSnapshot) = requireObserved(s.userInstalledCaCerts) { certs ->
            val nonMdm = certs.filterNot { it.mdmInstalled }
            when {
                certs.isEmpty() -> RuleOutcome.Pass

                nonMdm.isEmpty() -> RuleOutcome.Fail(
                    Finding(
                        ruleId = id,
                        category = category,
                        severity = Severity.INFO,
                        subjectId = "mdm",
                        title = "Your organisation can inspect this device's traffic",
                        detail = "${certs.size} certificate authority(ies) were installed by device " +
                            "management. This is normal on a work device and lets your employer see " +
                            "traffic that would otherwise be encrypted.",
                        remediation = "No action needed if this is a work device. If it is not, " +
                            "remove the profile in Settings."
                    )
                )

                else -> RuleOutcome.Fail(
                    nonMdm.map { cert ->
                        Finding(
                            ruleId = id,
                            category = category,
                            severity = Severity.CRITICAL,
                            subjectId = cert.sha256,
                            title = "An extra certificate authority is trusted",
                            detail = "\"${cert.subject}\" was added to this device's trust store and " +
                                "is not part of the operating system. A certificate authority can " +
                                "impersonate any website, so whoever controls this one can read " +
                                "traffic you believe is encrypted — including passwords.",
                            remediation = "Settings → Security → Encryption & credentials → Trusted " +
                                "credentials → User tab, and remove it unless you installed it " +
                                "deliberately for testing.",
                            evidence = mapOf(
                                "subject" to cert.subject,
                                "issuer" to cert.issuer,
                                "sha256" to cert.sha256
                            )
                        )
                    }
                )
            }
        }
    }

    /** A configured HTTP proxy routes traffic through a third party by design. */
    val ProxyConfigured = object : BaseRule(
        id = "NET-PROXY-001",
        category = Category.NETWORK,
        description = "No traffic proxy is configured",
        platforms = Platforms.EVERYWHERE
    ) {
        override fun check(s: DeviceSnapshot): RuleOutcome {
            val proxy = s.proxy ?: return RuleOutcome.Pass
            return RuleOutcome.Fail(
                Finding(
                    ruleId = id,
                    category = category,
                    severity = Severity.HIGH,
                    title = "Traffic is routed through a proxy",
                    detail = "This network sends your traffic via ${proxy.host}:${proxy.port} before " +
                        "it reaches the internet. Combined with a trusted extra certificate " +
                        "authority, this allows full interception.",
                    remediation = "Remove the proxy in the Wi-Fi network's advanced settings unless " +
                        "your organisation requires it.",
                    evidence = buildMap {
                        put("host", proxy.host)
                        put("port", proxy.port.toString())
                        proxy.pacUrl?.let { put("pac", it) }
                    }
                )
            )
        }
    }

    /** Open Wi-Fi: everything not already encrypted is readable by everyone nearby. */
    val OpenWifi = object : BaseRule(
        id = "NET-WIFI-001",
        category = Category.NETWORK,
        description = "Wi-Fi network is encrypted",
        platforms = Platforms.EVERYWHERE
    ) {
        override fun check(s: DeviceSnapshot) = requireObserved(s.wifi) { wifi ->
            val name = wifi.ssid?.let { "\"$it\"" } ?: "This network"
            when (wifi.security) {
                WifiSecurity.OPEN -> RuleOutcome.Fail(
                    Finding(
                        ruleId = id,
                        category = category,
                        severity = Severity.MEDIUM,
                        title = "$name has no encryption",
                        detail = "Anyone within range can see which sites you visit, and can read " +
                            "anything an app sends without its own encryption.",
                        remediation = "Avoid signing in to anything on this network. Use mobile data " +
                            "for anything sensitive.",
                        evidence = mapOf("ssid" to (wifi.ssid ?: ""), "security" to "OPEN")
                    )
                )

                WifiSecurity.WEP -> RuleOutcome.Fail(
                    Finding(
                        ruleId = id,
                        category = category,
                        severity = Severity.HIGH,
                        title = "$name uses obsolete WEP encryption",
                        detail = "WEP has been breakable in minutes since 2001. This network is " +
                            "effectively open, and its age suggests the router is unpatched too.",
                        remediation = "Do not use this network. If it is yours, change the router to WPA2 or WPA3.",
                        evidence = mapOf("ssid" to (wifi.ssid ?: ""), "security" to "WEP")
                    )
                )

                WifiSecurity.WPA -> RuleOutcome.Fail(
                    Finding(
                        ruleId = id,
                        category = category,
                        severity = Severity.LOW,
                        title = "$name uses outdated WPA encryption",
                        detail = "The original WPA has known weaknesses and has been superseded twice.",
                        remediation = "If this network is yours, switch the router to WPA2 or WPA3.",
                        evidence = mapOf("ssid" to (wifi.ssid ?: ""), "security" to "WPA")
                    )
                )

                WifiSecurity.UNKNOWN -> RuleOutcome.NotApplicable
                WifiSecurity.WPA2, WifiSecurity.WPA3, WifiSecurity.OWE -> RuleOutcome.Pass
            }
        }
    }

    /**
     * The gateway's MAC address changed for a network we have joined before.
     *
     * That is what an evil-twin access point looks like from the client side:
     * same SSID, same password prompt, different hardware. Purely local — it
     * needs only our own history of this SSID.
     */
    val EvilTwin = object : BaseRule(
        id = "NET-WIFI-002",
        category = Category.NETWORK,
        description = "Wi-Fi gateway matches the one seen previously"
    ) {
        override fun check(s: DeviceSnapshot): RuleOutcome {
            val wifi = s.wifi ?: return RuleOutcome.NotApplicable
            val changed = wifi.gatewayMacChanged ?: return RuleOutcome.NotApplicable
            if (!changed) return RuleOutcome.Pass
            return RuleOutcome.Fail(
                Finding(
                    ruleId = id,
                    category = category,
                    severity = Severity.HIGH,
                    title = "This network's router has changed",
                    detail = "\"${wifi.ssid ?: "This network"}\" is using different hardware than the " +
                        "last time you connected. That can mean the router was replaced — or that " +
                        "something nearby is impersonating it to capture traffic.",
                    remediation = "Disconnect and use mobile data until you can confirm the network " +
                        "equipment was genuinely changed.",
                    evidence = mapOf("ssid" to (wifi.ssid ?: ""))
                )
            )
        }
    }

    /**
     * DNS resolvers that are not the network's own and not a recognised public
     * resolver. DNS redirection is how a lot of on-path attacks start.
     */
    val SuspiciousDns = object : BaseRule(
        id = "NET-DNS-001",
        category = Category.NETWORK,
        description = "DNS resolvers look normal",
        platforms = Platforms.EVERYWHERE
    ) {
        /** Well-known public resolvers, bundled. Not exhaustive by design. */
        private val KNOWN_PUBLIC = setOf(
            "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
            "208.67.222.222", "208.67.220.220", "94.140.14.14", "94.140.15.15",
            "2606:4700:4700::1111", "2606:4700:4700::1001",
            "2001:4860:4860::8888", "2001:4860:4860::8844"
        )

        override fun check(s: DeviceSnapshot) = requireObserved(s.dnsServers) { servers ->
            if (servers.isEmpty()) return@requireObserved RuleOutcome.NotApplicable
            val external = servers.filterNot { isPrivate(it) || it in KNOWN_PUBLIC }
            if (external.isEmpty()) RuleOutcome.Pass else RuleOutcome.Fail(
                Finding(
                    ruleId = id,
                    category = category,
                    severity = Severity.MEDIUM,
                    title = "Name lookups go to an unrecognised server",
                    detail = "This network directs your DNS queries to ${external.joinToString(", ")}, " +
                        "which is neither your router nor a well-known public resolver. Whoever runs " +
                        "it sees every site you visit and can send you to the wrong one.",
                    remediation = "Turn on Private DNS with a resolver you trust, or leave this network.",
                    evidence = mapOf("servers" to external.joinToString(","))
                )
            )
        }

        private fun isPrivate(ip: String): Boolean {
            if (ip.startsWith("fe80:") || ip.startsWith("fd") || ip.startsWith("fc")) return true
            val parts = ip.split(".")
            if (parts.size != 4) return false
            val octets = parts.map { it.toIntOrNull() ?: return false }
            return when {
                octets[0] == 10 -> true
                octets[0] == 127 -> true
                octets[0] == 192 && octets[1] == 168 -> true
                octets[0] == 172 && octets[1] in 16..31 -> true
                octets[0] == 169 && octets[1] == 254 -> true
                else -> false
            }
        }
    }

    /** Private DNS off means lookups travel in clear text on every network. */
    val PrivateDnsOff = object : BaseRule(
        id = "NET-DNS-002",
        category = Category.NETWORK,
        description = "Encrypted DNS is enabled",
        platforms = setOf(Platform.ANDROID)
    ) {
        override fun check(s: DeviceSnapshot) = requireObserved(s.privateDnsMode) { mode ->
            if (mode != "off") RuleOutcome.Pass else RuleOutcome.Fail(
                Finding(
                    ruleId = id,
                    category = category,
                    severity = Severity.LOW,
                    title = "Encrypted DNS is turned off",
                    detail = "Your device asks for website addresses in clear text, so every network " +
                        "you join can log the sites you visit even when the sites themselves are " +
                        "encrypted.",
                    remediation = "Settings → Network & internet → Private DNS → Automatic, or set a " +
                        "provider hostname."
                )
            )
        }
    }

    /**
     * A VPN owned by an app we can name. Not automatically bad — but users are
     * frequently unaware which app is holding the tunnel, and free VPN apps are
     * a well-documented data-collection business.
     */
    val VpnOwner = object : BaseRule(
        id = "NET-VPN-001",
        category = Category.NETWORK,
        description = "Any active VPN is one you recognise",
        platforms = setOf(Platform.ANDROID)
    ) {
        override fun check(s: DeviceSnapshot): RuleOutcome {
            val active = s.vpnActive ?: return RuleOutcome.NotApplicable
            if (!active) return RuleOutcome.Pass
            val owner = s.vpnOwnerPackage ?: return RuleOutcome.NotApplicable
            return RuleOutcome.Fail(
                Finding(
                    ruleId = id,
                    category = category,
                    severity = Severity.INFO,
                    title = "All traffic is going through a VPN",
                    detail = "The app \"$owner\" is carrying every byte this device sends. That app " +
                        "can see everything a public Wi-Fi network would have seen.",
                    remediation = "Confirm you installed this VPN deliberately and that you trust its " +
                        "operator with your browsing.",
                    evidence = mapOf("owner" to owner)
                )
            )
        }
    }

    val ALL: List<Rule> = listOf(
        UserInstalledCa, ProxyConfigured, OpenWifi, EvilTwin,
        SuspiciousDns, PrivateDnsOff, VpnOwner
    )
}
