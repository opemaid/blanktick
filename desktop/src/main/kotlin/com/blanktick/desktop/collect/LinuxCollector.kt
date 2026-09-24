package com.blanktick.desktop.collect

import com.blanktick.core.model.AutoRunEntry
import com.blanktick.core.model.DesktopFacts
import com.blanktick.core.model.DesktopOs
import com.blanktick.core.model.ListeningPort
import com.blanktick.core.model.RemoteAccessService
import com.blanktick.core.model.ScreenLock
import java.io.File

/**
 * Reads Linux security posture.
 *
 * ## Status: written, exercised only under WSL
 *
 * This has been run under WSL, which is not a desktop Linux session: there is no
 * display manager, no screensaver, and systemd behaves differently. The parsers
 * are covered by tests against captured output, but the end-to-end path on a
 * real GNOME or KDE desktop is unverified. Said plainly for the same reason as
 * in [MacCollector].
 *
 * ## Why Linux answers "not checkable" more often than the other two
 *
 * There is no single Linux. The firewall may be ufw, firewalld, plain nftables
 * or a router; the screen lock belongs to whichever desktop environment is
 * installed; "the antivirus" usually does not exist and its absence is not a
 * finding. Every one of those is a genuine "I cannot tell", and this collector
 * says so rather than manufacturing a verdict — which means a Linux user sees a
 * shorter report than a Windows user, correctly.
 *
 * The one thing this file must never do is treat "I did not find a firewall
 * manager I recognise" as "there is no firewall". Those are different
 * statements and only the first is true.
 */
internal class LinuxCollector : PlatformCollector {

    override val os = DesktopOs.LINUX

    override fun osBuild(): String? =
        Shell.readFile("/etc/os-release")
            ?.lineSequence()
            ?.firstOrNull { it.startsWith("PRETTY_NAME=") }
            ?.substringAfter('=')
            ?.trim('"', ' ')
            ?.takeIf { it.isNotBlank() }

    override fun collect(intel: DesktopIntelSnapshot): DesktopFacts = DesktopFacts(
        os = os,
        osBuild = osBuild(),

        firewallEnabled = firewallEnabled(),
        firewallProfilesOff = null,

        // Consumer Linux ships no on-access scanner and does not need one in
        // the Windows sense. Reporting `false` would produce a permanent,
        // unfixable red card on every Linux machine, so this is null and the
        // rule stays silent.
        antivirusProduct = null,
        antivirusRealtimeEnabled = null,
        antivirusSignatureAgeDays = null,
        appReputationEnabled = null,

        secureBootEnabled = secureBootEnabled(),
        systemIntegrityProtectionEnabled = null,

        automaticUpdatesEnabled = unattendedUpgradesEnabled(),
        pendingSecurityUpdates = null,   // requires refreshing package metadata, i.e. network
        daysSinceLastUpdate = daysSinceLastUpdate(),

        sessionIsAdministrator = sessionIsAdministrator(),
        administratorAccounts = sudoGroupMembers(),
        passwordlessAccounts = passwordlessAccounts(),
        guestAccountEnabled = null,      // distro- and DM-specific; not reliably readable
        lockOnWakeEnabled = lockOnWakeEnabled(),

        remoteAccessServices = remoteAccessServices(),
        listeningPorts = listeningPorts(),

        autoRunEntries = autoRunEntries()
    )

    // ------------------------------------------------------------- firewall

    /**
     * @return `true`/`false` only when a firewall manager we understand is
     *   present and reports a state. When none is found the answer is `null`:
     *   nftables rules may well be loaded by something we did not look at.
     */
    private fun firewallEnabled(): Boolean? {
        Shell.stdout("ufw", "status")?.lowercase()?.let { out ->
            if (out.contains("status: active")) return true
            if (out.contains("status: inactive")) return false
        }

        Shell.stdout("systemctl", "is-active", "firewalld")?.trim()?.let { state ->
            if (state == "active") return true
            if (state == "inactive" || state == "failed") return false
        }

        // nftables with a non-empty ruleset counts as a firewall even though we
        // cannot judge whether the rules are any good.
        Shell.stdout("nft", "list", "ruleset")?.let { rules ->
            if (rules.isNotBlank()) return true
        }

        return null
    }

    private fun secureBootEnabled(): Boolean? {
        val out = Shell.stdout("mokutil", "--sb-state")?.lowercase() ?: return null
        return when {
            out.contains("secureboot enabled") -> true
            out.contains("secureboot disabled") -> false
            else -> null
        }
    }

    // -------------------------------------------------------------- updates

    private fun unattendedUpgradesEnabled(): Boolean? {
        // Debian/Ubuntu
        Shell.readFile("/etc/apt/apt.conf.d/20auto-upgrades")?.let { conf ->
            val enabled = conf.lineSequence()
                .firstOrNull { it.contains("Unattended-Upgrade") }
                ?.substringAfter("\"")?.substringBefore("\"")
            if (enabled != null) return enabled == "1"
        }
        // Fedora/RHEL
        Shell.stdout("systemctl", "is-enabled", "dnf-automatic.timer")?.trim()?.let { state ->
            if (state == "enabled") return true
            if (state == "disabled" || state == "masked") return false
        }
        return null
    }

    /** Age of the package database, as a proxy for when anything last changed. */
    private fun daysSinceLastUpdate(): Int? {
        val markers = listOf(
            "/var/lib/dpkg/status",
            "/var/lib/rpm/rpmdb.sqlite",
            "/var/lib/pacman/local"
        )
        val newest = markers.map(::File).filter { it.exists() }.maxOfOrNull { it.lastModified() }
            ?: return null
        val ageMillis = System.currentTimeMillis() - newest
        if (ageMillis < 0) return null
        return (ageMillis / 86_400_000L).toInt()
    }

    // ------------------------------------------------------------- accounts

    private fun sessionIsAdministrator(): Boolean? {
        // Root itself, or membership of a group that grants sudo.
        val uid = Shell.stdout("id", "-u")?.trim()?.toIntOrNull()
        if (uid == 0) return true
        val groups = Shell.stdout("id", "-Gn")?.trim() ?: return null
        return groups.split(' ').any { it == "sudo" || it == "wheel" || it == "admin" }
    }

    private fun sudoGroupMembers(): List<String>? {
        val group = Shell.readFile("/etc/group")
            ?.lineSequence()
            ?.firstOrNull { it.startsWith("sudo:") || it.startsWith("wheel:") }
            ?: return null
        return group.substringAfterLast(':')
            .split(',')
            .map { it.trim() }
            .filter { it.isNotBlank() }
            .takeIf { it.isNotEmpty() }
    }

    /**
     * Accounts with an empty password field in `/etc/shadow`.
     *
     * `/etc/shadow` is root-only, so unprivileged this returns `null` — which is
     * correct and is the common case. It is worth attempting because Blanktick may be
     * run as root on a single-user machine, and a passwordless login account is
     * a CRITICAL finding worth catching when we can.
     */
    private fun passwordlessAccounts(): List<String>? {
        val shadow = Shell.readFile("/etc/shadow") ?: return null
        return shadow.lineSequence()
            .mapNotNull { line ->
                val parts = line.split(':')
                if (parts.size < 2) return@mapNotNull null
                // "" means no password; "!" and "*" mean locked, which is fine.
                if (parts[1].isEmpty()) parts[0] else null
            }
            .toList()
    }

    /** GNOME's lock-on-idle setting. Other desktops report null. */
    private fun lockOnWakeEnabled(): Boolean? = Shell.parseBoolean(
        Shell.stdout("gsettings", "get", "org.gnome.desktop.screensaver", "lock-enabled")?.trim()
    )

    // -------------------------------------------------------- remote access

    private fun remoteAccessServices(): List<RemoteAccessService>? {
        val sshState = Shell.stdout("systemctl", "is-active", "sshd")?.trim()
            ?: Shell.stdout("systemctl", "is-active", "ssh")?.trim()
            ?: return null

        val enabled = sshState == "active"

        // Key-only authentication is what makes an exposed SSH port survivable.
        val passwordAuth = Shell.readFile("/etc/ssh/sshd_config")
            ?.lineSequence()
            ?.map { it.trim() }
            ?.firstOrNull { it.startsWith("PasswordAuthentication", ignoreCase = true) }
            ?.substringAfter(' ')?.trim()?.lowercase()

        val hardened = when (passwordAuth) {
            "no" -> true
            "yes" -> false
            else -> null
        }

        return listOf(RemoteAccessService("SSH", enabled = enabled, port = 22, hardened = hardened))
    }

    private fun listeningPorts(): List<ListeningPort>? {
        val raw = Shell.stdout("ss", "-ltnH", timeoutSeconds = 15) ?: return null

        return raw.lineSequence()
            .mapNotNull { line ->
                val cols = line.trim().split(Regex("\\s+"))
                // State Recv-Q Send-Q Local:Port Peer:Port [users:(...)]
                if (cols.size < 4) return@mapNotNull null
                val local = cols[3]
                val port = local.substringAfterLast(':').toIntOrNull() ?: return@mapNotNull null
                val address = local.substringBeforeLast(':')
                ListeningPort(
                    address = if (address == "*") "0.0.0.0" else address,
                    port = port,
                    process = cols.getOrNull(5)
                        ?.substringAfter("((\"", "")?.substringBefore("\"")
                        ?.takeIf { it.isNotBlank() }
                )
            }
            .toList()
    }

    // ---------------------------------------------------------- persistence

    /**
     * XDG autostart entries.
     *
     * `signedByKnownVendor` is `null` for every entry, always. Linux packages
     * are signed at the repository level, not per-executable, so there is
     * nothing here that corresponds to an Authenticode verdict — and reporting
     * every autostart entry as "unsigned" would flag a stock desktop a dozen
     * times over. `DSK-AUTO-001` consequently never fires on Linux, which is
     * the correct behaviour rather than a gap.
     */
    private fun autoRunEntries(): List<AutoRunEntry>? {
        val home = System.getProperty("user.home")
        val dirs = listOfNotNull(
            home?.let { "$it/.config/autostart" },
            "/etc/xdg/autostart"
        )
        if (dirs.none { File(it).isDirectory }) return null

        return dirs.flatMap { dir ->
            File(dir).takeIf { it.isDirectory }
                ?.listFiles { f -> f.isFile && f.name.endsWith(".desktop") }
                ?.map { AutoRunEntry(it.nameWithoutExtension, dir, signedByKnownVendor = null) }
                .orEmpty()
        }
    }

    // ------------------------------------------------ shared mobile-ish facts

    /**
     * Whether the root filesystem sits on a LUKS-backed device.
     *
     * `lsblk` shows the device tree; a `crypt` type anywhere in it means
     * something is encrypted. This deliberately does not try to prove that the
     * *root* filesystem in particular is the encrypted one — that needs a
     * device-mapper walk — so it can report `true` for a machine with only an
     * encrypted data disk. Flagged here rather than silently over-claimed.
     */
    override fun diskEncrypted(): Boolean? {
        val out = Shell.stdout("lsblk", "-o", "TYPE", "-n") ?: return null
        if (out.isBlank()) return null
        return out.lineSequence().any { it.trim() == "crypt" }
    }

    override fun screenLock(): ScreenLock? =
        if (lockOnWakeEnabled() != null) ScreenLock.UNKNOWN else null

    override fun screenLockTimeoutSeconds(): Int? =
        Shell.stdout("gsettings", "get", "org.gnome.desktop.session", "idle-delay")
            ?.substringAfterLast(' ')?.trim()?.toIntOrNull()?.takeIf { it > 0 }

    override fun dnsServers(): List<String>? {
        // systemd-resolved first: /etc/resolv.conf is a stub pointing at
        // 127.0.0.53 on most modern distributions, which would be a useless
        // and misleading answer.
        Shell.stdout("resolvectl", "dns")?.let { out ->
            val servers = Regex("""\b(\d{1,3}(?:\.\d{1,3}){3})\b""")
                .findAll(out).map { it.value }.distinct().toList()
            if (servers.isNotEmpty()) return servers
        }

        val resolv = Shell.readFile("/etc/resolv.conf") ?: return null
        return resolv.lineSequence()
            .filter { it.trim().startsWith("nameserver") }
            .mapNotNull { it.substringAfter("nameserver").trim().takeIf { s -> s.isNotBlank() } }
            .filterNot { it.startsWith("127.0.0.53") }
            .distinct()
            .toList()
            .takeIf { it.isNotEmpty() }
    }

    override fun proxyHostPort(): Pair<String, Int>? {
        val value = System.getenv("https_proxy") ?: System.getenv("HTTPS_PROXY")
            ?: System.getenv("http_proxy") ?: System.getenv("HTTP_PROXY") ?: return null
        val stripped = value.substringAfter("://").substringBefore('/')
        val host = stripped.substringBeforeLast(':').substringAfterLast('@')
            .takeIf { it.isNotBlank() } ?: return null
        val port = stripped.substringAfterLast(':').toIntOrNull() ?: return null
        return host to port
    }
}
