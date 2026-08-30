import org.jetbrains.compose.desktop.application.dsl.TargetFormat
// Imported rather than fully qualified: inside a Kotlin DSL build script the
// identifier `java` resolves to the JavaPluginExtension, which shadows the
// package and makes `java.util.zip.ZipFile` fail to resolve.
import java.util.zip.ZipFile

plugins {
    kotlin("jvm")
    id("org.jetbrains.kotlin.plugin.compose")
    id("org.jetbrains.compose")
}

kotlin {
    jvmToolchain(17)
}

/*
 * Dependency policy.
 *
 * Compose Multiplatform and our own :core, and nothing else. No HTTP client, no
 * JSON library, no logging framework, no crash reporter, no telemetry -- the
 * desktop equivalent of decision D-03. `auditDependencyNetworkSurface` below
 * fails the build if the set of jars containing networking code changes, which
 * is what stops one of those arriving as a transitive dependency.
 */
dependencies {
    implementation(project(":core"))
    implementation(compose.desktop.currentOs)
    implementation(compose.material3)

    testImplementation(kotlin("test"))
}

compose.desktop {
    application {
        mainClass = "com.mume.desktop.MainKt"

        nativeDistributions {
            targetFormats(TargetFormat.Msi, TargetFormat.Dmg, TargetFormat.Deb)
            packageName = "Mume"
            packageVersion = "0.1.0"
            description = "Offline security check for this computer"
            vendor = "Mume"

            // macOS installer versions must start at a major > 0, so the DMG
            // carries 1.0.0 while the app itself is still 0.1.0. Keeping the
            // two in sync would mean lying about maturity in one place or the
            // other; this way the app's own About screen stays truthful.
            macOS { packageVersion = "1.0.0" }
        }
    }
}

tasks.test {
    useJUnitPlatform()
    testLogging { events("passed", "skipped", "failed") }
}

/* ------------------------------------------------------------------------- *
 * The guarantee, enforced.
 *
 * On Android the promise is enforced by the OS: the APK holds no INTERNET
 * permission, so the kernel refuses every socket. A desktop JVM has no such
 * gate -- so the equivalent here is static, and it runs over compiled bytecode
 * rather than source, which means it cannot be evaded by string concatenation
 * or a Kotlin construct nobody thought to grep for.
 *
 * Two separate checks, because they answer two different questions:
 *
 *   assertNoNetworkBytecode       "does OUR code reference a networking API?"
 *                                 Zero tolerance. This is the actual claim.
 *
 *   auditDependencyNetworkSurface "which third-party jars contain networking
 *                                 code at all?" We cannot honestly say Compose
 *                                 and Skiko contain none. We CAN pin the set,
 *                                 so it is reviewed and cannot grow silently.
 *
 * Both are wired into `check`.
 * ------------------------------------------------------------------------- */

/**
 * Internal names of the APIs that constitute reaching the network.
 *
 * Matched as raw bytes against the class file, which catches constant-pool
 * class references, method descriptors and string literals alike. Erring
 * towards over-matching is deliberate: a false positive costs a conversation, a
 * false negative costs the only claim this product really makes.
 */
val networkApiSignatures = listOf(
    "java/net/Socket",
    "java/net/ServerSocket",
    "java/net/DatagramSocket",
    "java/net/URLConnection",
    "java/net/HttpURLConnection",
    "java/net/InetAddress",
    "java/net/InetSocketAddress",
    "java/net/Proxy",
    "java/nio/channels/SocketChannel",
    "java/nio/channels/ServerSocketChannel",
    "java/nio/channels/DatagramChannel",
    "java/net/http/HttpClient",
    "javax/net/ssl/SSLSocket",
    "okhttp3/",
    "io/ktor/client"
)

/**
 * The only classes permitted to name a socket type.
 *
 * NoNetwork exists to break connections, so it necessarily references the
 * classes it blocks. Allowed by exact name rather than by package prefix, so
 * that a second class cannot quietly join it.
 */
val networkExemptClasses = setOf(
    "com/mume/desktop/NoNetwork.class",
    "com/mume/desktop/NoNetwork\$BlockedSocketImpl.class",
    "com/mume/desktop/NoNetwork\$BlockingSocketImplFactory.class",
    "com/mume/desktop/NoNetwork\$BlockedUrlHandler.class",
    "com/mume/desktop/NoNetwork\$LocalOnlyUrlHandlerFactory.class",
    "com/mume/desktop/NoNetwork\$BlockedException.class"
)

val assertNoNetworkBytecode = tasks.register("assertNoNetworkBytecode") {
    group = "verification"
    description = "Fails if any Mume class references a networking API."

    // Captured as plain values so the task body touches nothing reachable from
    // Project, which is what keeps it usable under the configuration cache.
    val classDirs = files(
        layout.buildDirectory.dir("classes/kotlin/main"),
        project(":core").layout.buildDirectory.dir("classes/kotlin/main")
    )
    val signatures = networkApiSignatures

    /*
     * Self-test.
     *
     * A scanner that finds nothing and a scanner that is broken produce the
     * same output, and this one currently reports zero across 43 dependency
     * jars -- a result worth distrusting until proven. Running
     *
     *     gradlew :desktop:assertNoNetworkBytecode -PmumeNetworkGateSelfTest
     *
     * drops the exemption for NoNetwork, which definitionally DOES reference
     * java.net.Socket. The gate must then fail. If it passes, the gate is dead
     * and its silence means nothing.
     */
    val selfTest = providers.gradleProperty("mumeNetworkGateSelfTest").isPresent
    val exempt = if (selfTest) emptySet<String>() else networkExemptClasses

    dependsOn(tasks.named("classes"), project(":core").tasks.named("classes"))
    inputs.files(classDirs).withPropertyName("mumeClasses")
    outputs.upToDateWhen { false }

    doLast {
        val offenders = mutableListOf<String>()

        classDirs.asFileTree.matching { include("**/*.class") }.forEach { file ->
            val relative = file.absolutePath
                .replace('\\', '/')
                .substringAfter("/classes/kotlin/main/")
            if (relative in exempt) return@forEach

            // ISO_8859_1 is a byte-preserving decode: every byte maps to one
            // char, so a substring search over it is a search over the bytes.
            val text = file.readBytes().toString(Charsets.ISO_8859_1)
            val hits = signatures.filter { text.contains(it) }
            if (hits.isNotEmpty()) offenders += "$relative -> ${hits.joinToString(", ")}"
        }

        if (offenders.isNotEmpty()) {
            throw GradleException(
                buildString {
                    appendLine("Mume must contain no networking code, but these compiled classes")
                    appendLine("reference a network API:")
                    appendLine()
                    offenders.forEach { appendLine("    $it") }
                    appendLine()
                    appendLine("If this is the NoNetwork blocker gaining a nested class, add it to")
                    appendLine("`networkExemptClasses` by exact name, never by package prefix.")
                    appendLine()
                    appendLine("If it is anything else, Mume cannot ship it. The offline guarantee")
                    appendLine("is the product, not a feature of it.")
                }
            )
        }

        if (exempt.isEmpty()) {
            throw GradleException(
                "SELF-TEST FAILED: with NoNetwork unexempted, the gate found nothing. The " +
                    "scanner is broken and its clean verdict is worthless."
            )
        }
        logger.lifecycle("  Mume: no Mume class references a networking API.")
    }
}

/**
 * Inventory of which third-party jars contain networking code.
 *
 * This does NOT claim the dependencies are network-free. They are not, and
 * saying otherwise would be exactly the kind of unmeasured claim this project
 * treats as its worst possible bug. It pins the set instead: the build fails
 * when a jar joins or leaves it, so a new transitive dependency that ships an
 * HTTP client has to be looked at by a person before it can land.
 */
val auditDependencyNetworkSurface = tasks.register("auditDependencyNetworkSurface") {
    group = "verification"
    description = "Pins every third-party jar on the runtime classpath, flagging those with networking code."

    // Captured as a FileCollection, not as the Configuration provider: the
    // configuration cache can serialise the former and not the latter.
    val runtimeJars: FileCollection = configurations.getByName("runtimeClasspath")
    val signatures = networkApiSignatures
    val expectedFile = layout.projectDirectory.file("network-surface.txt")
    val actualFile = layout.buildDirectory.file("reports/network-surface.txt")

    inputs.files(runtimeJars).withPropertyName("runtimeClasspath")
    outputs.file(actualFile)

    doLast {
        val rows = sortedSetOf<String>()

        runtimeJars.files.filter { it.name.endsWith(".jar") }.forEach { jar ->
            var hits = 0
            ZipFile(jar).use { zip ->
                zip.entries().asSequence()
                    .filter { !it.isDirectory && it.name.endsWith(".class") }
                    .forEach { entry ->
                        val text = zip.getInputStream(entry).use { s -> s.readBytes() }
                            .toString(Charsets.ISO_8859_1)
                        if (signatures.any { text.contains(it) }) hits++
                    }
            }
            // EVERY jar is recorded, not only those containing networking code.
            // The first version recorded only `hits > 0`, so a new dependency
            // with no networking code produced an identical file and passed
            // silently -- meaning "the gate will catch it" was a false assurance
            // for exactly the case a human should look at. The written
            // dependency policy is the real enforcement; this makes the gate
            // match it instead of appearing to be it.
            //
            // Version numbers are stripped so a routine bump does not fail the
            // build, but a NEW artifact must.
            val name = jar.name.replace(Regex("-\\d[\\w.\\-]*\\.jar$"), "")
            rows += if (hits > 0) "$name  [contains networking code]" else name
        }

        val scanned = runtimeJars.files.count { it.name.endsWith(".jar") }
        val withNetworking = rows.count { it.contains("[contains networking code]") }
        logger.lifecycle(
            "  Mume: pinned $scanned runtime jars, $withNetworking contain networking code."
        )

        val actual = actualFile.get().asFile
        actual.parentFile.mkdirs()
        actual.writeText(rows.joinToString("\n", postfix = "\n"))

        val expected = expectedFile.asFile
        if (!expected.exists()) {
            expected.writeText(rows.joinToString("\n", postfix = "\n"))
            logger.lifecycle("  Mume: wrote initial network-surface.txt (${rows.size} jars). Review it.")
            return@doLast
        }

        val pinned = expected.readLines()
            .map { it.substringBefore('#').trim() }
            .filter { it.isNotEmpty() }
            .toSortedSet()
        val added = rows - pinned
        val removed = pinned - rows

        if (added.isNotEmpty() || removed.isNotEmpty()) {
            throw GradleException(
                buildString {
                    appendLine("The set of dependencies containing networking code has changed.")
                    appendLine()
                    if (added.isNotEmpty()) {
                        appendLine("  NEW (a person must review these):")
                        added.forEach { appendLine("    + $it") }
                    }
                    if (removed.isNotEmpty()) {
                        appendLine("  GONE (good news, but update the pin):")
                        removed.forEach { appendLine("    - $it") }
                    }
                    appendLine()
                    appendLine("A jar appearing here does not mean it makes connections. Compose and")
                    appendLine("Skiko reference java.net to load resources. It means nobody has")
                    appendLine("looked at this particular one yet.")
                    appendLine()
                    appendLine("Once reviewed, copy build/reports/network-surface.txt over")
                    appendLine("desktop/network-surface.txt and record in the commit message what")
                    appendLine("was checked.")
                }
            )
        }

        logger.lifecycle("  Mume: dependency network surface unchanged (${rows.size} jars).")
    }
}

tasks.named("check").configure {
    dependsOn(assertNoNetworkBytecode, auditDependencyNetworkSurface)
}

// An installer must never be produced without the gate having run.
tasks.matching { it.name.startsWith("package") }.configureEach {
    finalizedBy(assertNoNetworkBytecode)
}

/**
 * Writes the runtime classpath to a file, so the app can be launched directly
 * with `java -cp` for the `--probe` and `--script` modes.
 *
 * Gradle's run task swallows stdout in some configurations, which makes it a
 * poor host for a tool whose entire purpose is printing what it found.
 */
tasks.register("writeRuntimeClasspath") {
    group = "verification"
    val runtime: FileCollection = configurations.getByName("runtimeClasspath")
    val classesDir = layout.buildDirectory.dir("classes/kotlin/main")
    val resourcesDir = layout.buildDirectory.dir("resources/main")
    val outFile = layout.buildDirectory.file("mume-classpath.txt")

    dependsOn(tasks.named("classes"))
    inputs.files(runtime)
    outputs.file(outFile)

    doLast {
        val entries = listOf(classesDir.get().asFile, resourcesDir.get().asFile) + runtime.files
        val file = outFile.get().asFile
        file.parentFile.mkdirs()
        file.writeText(entries.joinToString(File.pathSeparator) { it.absolutePath })
        logger.lifecycle("  Mume: classpath written to ${file.absolutePath}")
    }
}
