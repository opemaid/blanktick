package com.mume.app

import java.io.File
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The source-manifest half of the no-network guarantee.
 *
 * The Gradle task `assertNoNetworkPermissionDebug` checks the *merged* manifest,
 * which is what actually ships and therefore the authoritative check. This test
 * exists as well because it runs in milliseconds during ordinary development
 * and fails immediately on the most likely mistake — someone adding the
 * permission by hand to make a "quick" feature work.
 */
class ManifestContractTest {

    private val manifest: String by lazy {
        val candidates = listOf(
            File("src/main/AndroidManifest.xml"),
            File("app/src/main/AndroidManifest.xml")
        )
        val found = candidates.firstOrNull { it.exists() }
        requireNotNull(found) {
            "AndroidManifest.xml not found from ${File(".").absolutePath}"
        }
        // Comments are stripped first. The manifest documents at length that it
        // does NOT declare INTERNET -- and a naive substring search matches that
        // prose, which is how this test caught itself on the first run.
        found.readText().replace(COMMENT, "")
    }

    private companion object {
        val COMMENT = Regex("<!--.*?-->", RegexOption.DOT_MATCHES_ALL)
    }

    @Test
    fun `the app declares no internet permission`() {
        assertFalse(
            manifest.contains("android.permission.INTERNET"),
            "Mume must ship with no network permission. This is the product's central " +
                "claim (ADR-002) and it is verifiable by anyone with aapt. If a feature " +
                "genuinely needs the network it does not belong in this app."
        )
    }

    @Test
    fun `no other network permission sneaks in`() {
        listOf(
            "android.permission.ACCESS_NETWORK_STATE",
            "android.permission.CHANGE_NETWORK_STATE",
            "android.permission.CHANGE_WIFI_STATE",
            "android.permission.BIND_VPN_SERVICE",
            "android.permission.NEARBY_WIFI_DEVICES"
        ).forEach {
            assertFalse(manifest.contains(it), "$it must not be declared")
        }
    }

    @Test
    fun `QUERY_ALL_PACKAGES is avoided in favour of a queries element`() {
        // Kickoff decision, Agenda Item 6: the restricted permission puts the
        // app into a Play review category the launcher-intent query avoids.
        assertFalse(
            manifest.contains("android.permission.QUERY_ALL_PACKAGES"),
            "use <queries> with a launcher intent filter instead"
        )
        assertTrue(manifest.contains("<queries>"), "package visibility still needs <queries>")
        assertTrue(manifest.contains("android.intent.category.LAUNCHER"))
    }

    @Test
    fun `the app registers no accessibility service of its own`() {
        // Reading which OTHER apps hold one is a core feature. Registering one
        // ourselves is a well-known Play ban vector for security apps.
        assertFalse(
            manifest.contains("android.accessibilityservice.AccessibilityService\" />\n" +
                "        </intent-filter>"),
            "Mume must never register an AccessibilityService"
        )
        assertFalse(manifest.contains("<service"), "v1 declares no services at all")
    }

    @Test
    fun `backups are disabled so findings cannot leave via the cloud`() {
        assertTrue(manifest.contains("android:allowBackup=\"false\""))
        assertTrue(manifest.contains("android:dataExtractionRules"))
    }

    @Test
    fun `cleartext traffic is disabled`() {
        // Belt and braces: with no INTERNET permission this is unreachable, but
        // APP-BUILD-001 flags exactly this in other apps and we hold ourselves
        // to the bar we set for them.
        assertTrue(manifest.contains("android:usesCleartextTraffic=\"false\""))
    }
}
