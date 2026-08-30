plugins {
    kotlin("jvm")
}

kotlin {
    jvmToolchain(17)
    compilerOptions {
        // The core module is the normative implementation of the scoring spec.
        // Warnings here are bugs waiting to happen.
        allWarningsAsErrors.set(true)
    }
}

dependencies {
    testImplementation(kotlin("test"))
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("passed", "skipped", "failed")
        showStandardStreams = false
    }
}
