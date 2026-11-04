package com.blanktick.desktop.collect

import com.blanktick.desktop.Settings
import java.io.File
import java.util.Properties

/**
 * Remembers each Wi-Fi network's router hardware (MAC) address between scans,
 * so NET-WIFI-002 can say "this network's router is not the one it was".
 *
 * Stored next to the app's settings (`network-baseline.conf`), on this computer
 * only, as `network name = router MAC`. Nothing leaves the machine.
 *
 * After a change is reported once, the new router is remembered: a router that
 * was genuinely replaced does not alarm on every scan forever, and an
 * impersonation is still reported on the scan that sees it.
 */
internal object NetworkBaseline {

    data class Verdict(val changed: Boolean?, val firstSeen: Boolean)

    private fun file(): File = File(Settings.file().parentFile, "network-baseline.conf")

    /** `null` network or router MAC = nothing to compare (verdict unknown, nothing stored). */
    fun compareAndRemember(network: String?, routerMac: String?, store: File = file()): Verdict? {
        if (network.isNullOrBlank() || routerMac.isNullOrBlank()) return null
        val mac = routerMac.trim().uppercase()
        val props = Properties()
        runCatching { if (store.isFile) store.inputStream().use { props.load(it) } }
        val previous = props.getProperty(network)?.uppercase()
        if (previous == mac) return Verdict(changed = false, firstSeen = false)
        props.setProperty(network, mac)
        runCatching {
            store.parentFile?.mkdirs()
            store.outputStream().use { props.store(it, "Blanktick: router (gateway) MAC per Wi-Fi network. Local only.") }
        }
        return if (previous == null) Verdict(changed = null, firstSeen = true)
        else Verdict(changed = true, firstSeen = false)
    }
}
