plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.mume.app"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.mume.app"
        // Android 10. Matches the floor our own APP-SDK-001 rule enforces on
        // other apps -- it would be poor form to ship below the bar we set.
        minSdk = 29
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
        debug {
            // Never `isDebuggable = true` on a build we might hand to anyone:
            // APP-BUILD-001 flags exactly this in other apps.
            applicationIdSuffix = ".debug"
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures { compose = true }

    packaging {
        resources.excludes += "/META-INF/{AL2.0,LGPL2.1}"
        // Intel bundles must stay uncompressed so they can be mmap-ed straight
        // out of the APK rather than copied onto the heap at 20 MB a time.
        jniLibs.useLegacyPackaging = false
    }

    androidResources {
        noCompress += listOf("mub", "mus")
    }

    testOptions {
        unitTests.isIncludeAndroidResources = true
    }
}

kotlin {
    jvmToolchain(17)
}

/*
 * Dependency policy.
 *
 * Every entry below is either Google's own UI toolkit or our own pure-Kotlin
 * core. There is deliberately no Hilt, no Room, no image loader, no analytics,
 * no crash reporter and no networking library -- decision D-03.
 *
 * This is not minimalism for its own sake. Each third-party SDK is code we
 * cannot audit shipping inside a security app that reads the user's installed
 * app list. `assertNoUnexpectedDependencies` in the test suite fails the build
 * if anything new appears on the runtime classpath.
 */
dependencies {
    implementation(project(":core"))

    val composeBom = platform("androidx.compose:compose-bom:2025.06.00")
    implementation(composeBom)
    androidTestImplementation(composeBom)

    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.activity:activity-compose:1.10.1")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.9.1")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.9.1")
    implementation("androidx.core:core-ktx:1.16.0")
    implementation("androidx.exifinterface:exifinterface:1.4.1")

    debugImplementation("androidx.compose.ui:ui-tooling")
    implementation("androidx.compose.ui:ui-tooling-preview")

    testImplementation(kotlin("test"))
    testImplementation("junit:junit:4.13.2")
}

tasks.withType<Test>().configureEach {
    useJUnitPlatform()
}

/* ------------------------------------------------------------------------- *
 * The guarantee, enforced.
 *
 * Mume's central claim is that the app has no network permission (ADR-002).
 * Checking our own AndroidManifest.xml is not enough: manifest merging means
 * any dependency, at any depth, can inject `<uses-permission INTERNET/>` into
 * the shipped APK without a line of our source changing.
 *
 * So this inspects the MERGED manifest -- the one that actually gets packaged
 * -- and fails the build if a forbidden permission appears. It is wired into
 * `check`, so it runs in CI and cannot be forgotten.
 * ------------------------------------------------------------------------- */
val forbiddenPermissions = listOf(
    "android.permission.INTERNET",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.CHANGE_NETWORK_STATE",
    "android.permission.BIND_VPN_SERVICE"
)

androidComponents {
    onVariants { variant ->
        // Everything the task body needs is captured here as a plain value.
        // Referencing `variant` (or anything reachable from Project) inside
        // doLast makes the task un-cacheable under the configuration cache.
        val variantName: String = variant.name
        val capitalised = variantName.replaceFirstChar { it.uppercase() }
        val mergedManifest =
            variant.artifacts.get(com.android.build.api.artifact.SingleArtifact.MERGED_MANIFEST)
        val forbidden: List<String> = forbiddenPermissions

        val task = tasks.register("assertNoNetworkPermission$capitalised") {
            group = "verification"
            description = "Fails if the merged manifest declares any network permission."
            inputs.file(mergedManifest)

            doLast {
                // Strip comments: the manifest documents at length that it does
                // NOT declare these, and a substring search matches that prose.
                val text = mergedManifest.get().asFile.readText()
                    .replace(Regex("<!--.*?-->", RegexOption.DOT_MATCHES_ALL), "")
                val offenders = forbidden.filter { text.contains("\"$it\"") }
                if (offenders.isNotEmpty()) {
                    throw GradleException(
                        buildString {
                            appendLine("Mume must ship with no network permission, but the merged")
                            appendLine("manifest for '$variantName' declares:")
                            offenders.forEach { appendLine("    $it") }
                            appendLine()
                            appendLine("This is almost always a transitive dependency, not our source.")
                            appendLine("Run: gradle :app:dependencies --configuration ${variantName}RuntimeClasspath")
                            appendLine()
                            appendLine("Do not resolve this with tools:node=\"remove\". If a dependency")
                            appendLine("needs the network, Mume cannot ship it -- that is the product.")
                        }
                    )
                }
                logger.lifecycle(
                    "  Mume: merged manifest for '$variantName' declares no network permission."
                )
            }
        }

        tasks.named("check").configure { dependsOn(task) }
        tasks.matching { it.name == "assemble$capitalised" }.configureEach { finalizedBy(task) }
    }
}
