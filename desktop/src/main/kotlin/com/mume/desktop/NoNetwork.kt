package com.mume.desktop

import java.net.InetAddress
import java.net.Socket
import java.net.SocketException
import java.net.SocketImpl
import java.net.SocketImplFactory
import java.net.URL
import java.net.URLConnection
import java.net.URLStreamHandler
import java.net.URLStreamHandlerFactory

/**
 * Runtime enforcement of the offline promise on desktop.
 *
 * ## Read this before trusting it
 *
 * On Android, "this app cannot reach the internet" is enforced by the kernel:
 * the APK does not hold `INTERNET`, so every socket call fails no matter what
 * code runs. **There is no equivalent on a desktop JVM.** A process started by
 * the user can open sockets, and nothing inside that process can make that
 * untrue.
 *
 * So what follows is a *lock on the doors we know about*, not a wall. It is
 * defence in depth behind the real guarantee, which is the static one:
 * `assertNoNetworkBytecode` in `desktop/build.gradle.kts` fails the build if any
 * Mume class so much as references a networking API. That check runs over
 * compiled bytecode, cannot be talked out of it, and is what the claim actually
 * rests on.
 *
 * ## Exactly what this covers, and what it does not
 *
 * | Path | Blocked here? |
 * |---|---|
 * | `java.net.Socket`, `ServerSocket` | yes — via [SocketImplFactory] |
 * | `URL.openConnection()` for http/https/ftp | yes — via [URLStreamHandlerFactory] |
 * | `java.nio.channels.SocketChannel` | **no** |
 * | JNI / native code opening a socket directly | **no** |
 * | A child process making its own connections | **no** |
 *
 * The two gaps are real and are stated rather than papered over. `SelectorProvider`
 * is resolved once at class-init and cannot be swapped afterwards, and native
 * code is by definition outside the JVM's reach. Anyone who needs a hard
 * guarantee should run Mume with an OS-level egress rule — the About screen says
 * so, and gives the command.
 *
 * ## Why not a SecurityManager
 *
 * It would close both gaps on JDK 17. It is also deprecated for removal,
 * `System.setSecurityManager` throws at runtime unless the JVM was started with
 * `-Djava.security.manager=allow`, and it is gone entirely from JDK 24. Building
 * the product's headline claim on a mechanism that disappears in the next LTS
 * would mean the claim quietly stops being true after a routine JDK bump, with
 * nothing failing to say so. A narrower guarantee that keeps working is worth
 * more than a broad one with an expiry date.
 */
object NoNetwork {

    /** Set once [install] has run, whatever the outcome. */
    @Volatile
    var installed: Boolean = false
        private set

    /** Mechanisms that could not be installed, for the About screen to display. */
    @Volatile
    var gaps: List<String> = emptyList()
        private set

    /**
     * Installs the blocks.
     *
     * Must be the first thing `main` does. Both JVM factories are one-shot: if
     * a library sets one first, ours cannot replace it, and the corresponding
     * entry appears in [gaps] rather than being silently skipped.
     */
    @Synchronized
    fun install() {
        if (installed) return
        val failures = mutableListOf<String>()

        try {
            Socket.setSocketImplFactory(BlockingSocketImplFactory)
        } catch (e: Exception) {
            failures += "java.net.Socket (${e::class.simpleName})"
        }

        try {
            URL.setURLStreamHandlerFactory(LocalOnlyUrlHandlerFactory)
        } catch (e: Exception) {
            failures += "java.net.URL (${e::class.simpleName})"
        }

        // NIO is not interceptable after startup; recorded so the About screen
        // can state the limit instead of implying total coverage.
        failures += "java.nio.channels (not interceptable at runtime)"

        gaps = failures
        installed = true
    }

    /**
     * Thrown when something in the process tries to open a connection.
     *
     * Extends [SocketException] deliberately: callers that expect network
     * failure will already handle it, so the block degrades into an ordinary
     * "connection failed" rather than an unfamiliar crash.
     *
     * Note that the type does not always survive. `Socket.createImpl()` catches
     * any `IOException` from `SocketImpl.create()` and re-throws it as a plain
     * `new SocketException(e.getMessage())`. The **message** is the reliable
     * marker, which is what `NoNetworkTest` asserts on.
     */
    class BlockedException(message: String) : SocketException(message)

    private object BlockingSocketImplFactory : SocketImplFactory {
        override fun createSocketImpl(): SocketImpl = BlockedSocketImpl
    }

    /**
     * A [SocketImpl] that refuses everything.
     *
     * Every override throws rather than returning a benign value, because a
     * socket that silently does nothing is far harder to notice than one that
     * fails loudly. If this ever fires in the wild it is a bug report, and the
     * message says so.
     */
    private object BlockedSocketImpl : SocketImpl() {
        private fun blocked(): Nothing = throw BlockedException(
            "Mume does not make network connections. Something in this process tried to " +
                "open a socket, which is a bug: please report it."
        )

        override fun create(stream: Boolean) = blocked()
        override fun connect(host: String?, port: Int) = blocked()
        override fun connect(address: InetAddress?, port: Int) = blocked()
        override fun connect(address: java.net.SocketAddress?, timeout: Int) = blocked()
        override fun bind(host: InetAddress?, port: Int) = blocked()
        override fun listen(backlog: Int) = blocked()
        override fun accept(s: SocketImpl?) = blocked()
        override fun getInputStream() = blocked()
        override fun getOutputStream() = blocked()
        override fun available() = blocked()
        override fun close() = Unit          // must not throw; called from finally blocks
        override fun sendUrgentData(data: Int) = blocked()
        override fun setOption(optID: Int, value: Any?) = Unit
        override fun getOption(optID: Int): Any = blocked()
    }

    /**
     * Refuses network URL protocols; leaves local ones alone.
     *
     * Returning `null` hands the protocol back to the JVM's built-in handler,
     * which is essential: Compose and Skiko load resources and native libraries
     * through `file:` and `jar:` URLs, and blocking those would break the app
     * rather than secure it.
     */
    private object LocalOnlyUrlHandlerFactory : URLStreamHandlerFactory {
        private val BLOCKED = setOf("http", "https", "ftp", "ftps", "ws", "wss", "mailto")

        override fun createURLStreamHandler(protocol: String): URLStreamHandler? =
            if (protocol.lowercase() in BLOCKED) BlockedUrlHandler else null
    }

    private object BlockedUrlHandler : URLStreamHandler() {
        override fun openConnection(u: URL?): URLConnection =
            throw BlockedException(
                "Mume does not fetch anything over the network. A component tried to open " +
                    "$u, which is a bug: please report it."
            )
    }
}
