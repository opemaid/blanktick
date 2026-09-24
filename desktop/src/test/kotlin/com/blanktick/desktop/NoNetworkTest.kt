package com.blanktick.desktop

import java.net.Socket
import java.net.URI
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * The runtime network block, actually exercised.
 *
 * A block that is installed but does not block is worse than none: it produces a
 * tick on the About screen that nobody earned. So these tests attempt real
 * connections and require them to fail — and, just as importantly, require the
 * *local* protocols to keep working, because blocking `jar:` and `file:` would
 * break Compose's resource loading and the fix would be to remove the block.
 *
 * Nothing here reaches the network even when it passes: every target is a
 * reserved or loopback address, and the whole point is that the attempt dies
 * inside the JVM before a packet exists.
 */
class NoNetworkTest {

    init {
        // Idempotent, and the tests need it installed however they are ordered.
        NoNetwork.install()
    }

    @Test
    fun `install records what it could and could not do`() {
        assertTrue(NoNetwork.installed)
        // The NIO gap is unconditional and must always be declared. If this ever
        // disappears, the About screen is over-claiming.
        assertTrue(
            NoNetwork.gaps.any { it.contains("java.nio.channels") },
            "the NIO gap must always be reported, got: ${NoNetwork.gaps}"
        )
    }

    /**
     * A plain socket must not connect.
     *
     * `192.0.2.1` is TEST-NET-1 (RFC 5737) and is not routable, so "it threw"
     * would be an ambiguous result on its own. The assertion is therefore on
     * **our own message**, which only Blanktick's [java.net.SocketImpl] produces.
     *
     * Note the type is *not* asserted, and that is not laziness.
     * `Socket.createImpl()` catches any `IOException` from `SocketImpl.create()`
     * and re-throws it as `new SocketException(e.getMessage())` — the message
     * survives, the class does not. Asserting
     * `assertFailsWith<NoNetwork.BlockedException>` fails here even though the
     * block is working perfectly, which is exactly the sort of test that gets
     * "fixed" by deleting the assertion.
     */
    @Test
    fun `opening a socket is refused by Blanktick, not by the network`() {
        val thrown = runCatching { Socket("192.0.2.1", 80).use { } }.exceptionOrNull()

        assertTrue(thrown is java.net.SocketException, "expected a SocketException, got $thrown")
        assertTrue(
            thrown.message?.contains("Blanktick does not make network connections") == true,
            "the failure must come from Blanktick's block, not from the network. Got: ${thrown.message}"
        )
    }

    @Test
    fun `an http URL cannot be opened`() {
        val error = assertFailsWith<NoNetwork.BlockedException> {
            URI("http://192.0.2.1/anything").toURL().openConnection()
        }
        assertTrue(error.message!!.contains("does not fetch"))
    }

    @Test
    fun `an https URL cannot be opened`() {
        assertFailsWith<NoNetwork.BlockedException> {
            URI("https://192.0.2.1/anything").toURL().openConnection()
        }
    }

    /**
     * Local protocols must still work.
     *
     * Compose and Skiko load resources and native libraries through `file:` and
     * `jar:` URLs. A blanket block would break the app rather than secure it,
     * and the pressure to "just remove the block" would then be irresistible.
     */
    @Test
    fun `local protocols are untouched`() {
        val resource = NoNetworkTest::class.java.getResource("/intel/manifest.txt")
        if (resource != null) {
            // Reads out of the jar or the classes directory. No network involved.
            val text = resource.openStream().use { it.readBytes().decodeToString() }
            assertTrue(text.contains("builtOn="))
        }

        // A file: URL must at least be openable as a connection object.
        val tmp = kotlin.io.path.createTempFile("blanktick-nonetwork-", ".txt").toFile()
        try {
            tmp.writeText("ok")
            assertTrue(tmp.toURI().toURL().openConnection().getInputStream().use {
                it.readBytes().decodeToString()
            } == "ok")
        } finally {
            tmp.delete()
        }
    }
}
