plugins {
    kotlin("jvm")
}

/*
 * Blanktick Pro — the resident behavioural sensor.
 *
 * This module is the *engine*: a pure, deterministic core that reasons over a
 * stream of normalised [com.blanktick.sensor.SensorEvent]s. It has no Windows
 * dependency and opens no socket, so it is unit-testable without a machine to
 * attack and it stays inside the no-network gate exactly as `core` does.
 *
 * The privileged OS taps (ETW, AMSI, WMI) that FEED this engine live behind
 * [com.blanktick.sensor.providers.EventProvider] and are built and verified on
 * real elevated hardware — see docs/design-ai-attack-defense-2026-09-30.md.
 * The engine's correctness does not wait on them.
 */
kotlin {
    jvmToolchain(17)
    compilerOptions {
        allWarningsAsErrors.set(true)
    }
}

dependencies {
    // The shared verdict model (Finding/Category/Severity). core is pure and
    // offline, so depending on it keeps this module inside the same gate.
    implementation(project(":core"))
    testImplementation(kotlin("test"))
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("passed", "skipped", "failed")
        showStandardStreams = false
    }
}

/**
 * Live harness: wire the user-level process tap into the engine and print what
 * it sees. `gradlew :sensor:runSensor -Dblanktick.sensor.seconds=12` runs it for
 * a fixed window. This is user-level; ETW-grade capture needs an elevated run.
 */
tasks.register<JavaExec>("runSensor") {
    group = "application"
    description = "Run the live sensor harness (user-level process tap)."
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("com.blanktick.sensor.SensorMainKt")
    listOf("blanktick.sensor.seconds", "blanktick.sensor.demo").forEach { key ->
        val v = providers.systemProperty(key)
        if (v.isPresent) systemProperty(key, v.get())
    }
}
