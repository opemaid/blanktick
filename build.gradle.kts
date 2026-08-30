plugins {
    kotlin("jvm") version "2.2.20" apply false
    id("com.android.application") version "8.13.0" apply false
    id("org.jetbrains.kotlin.android") version "2.2.20" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.2.20" apply false
    // Compose Multiplatform, for the desktop build only. 1.9.x is the first
    // line that targets Kotlin 2.2; the Android app keeps using Google's
    // androidx.compose, which is a different artifact set.
    id("org.jetbrains.compose") version "1.9.0" apply false
}
