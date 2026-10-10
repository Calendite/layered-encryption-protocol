plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.androidLibrary)
    `maven-publish`
}

group = "org.layeredencryption"
version = "0.1.0"

val lepNativeOutput = layout.buildDirectory.dir("lep-native/macosArm64")

kotlin {
    androidTarget {
        publishLibraryVariants("release")
    }
    jvm()
    iosX64()
    iosArm64()
    iosSimulatorArm64()

    // Calendite's background daemons run on the Mac as Kotlin/Native. The provider binds vendored
    // C (ML-KEM, ML-DSA, Ed25519, SHA-3) and CryptoKit (the AEADs, X25519), built by
    // native/build.sh; see native/README.md for why each primitive comes from where it does.
    macosArm64 {
        compilations.getByName("main").cinterops.create("lepnative") {
            defFile(file("src/nativeInterop/cinterop/lepnative.def"))
            includeDirs(file("native/include"))
            extraOpts("-libraryPath", lepNativeOutput.get().asFile.path)
            // cinterop asks `xcodebuild -version` only to check the Xcode version; the Command
            // Line Tools have everything it actually uses, and no xcodebuild.
            extraOpts("-Xoverride-konan-properties", "ignoreXcodeVersionCheck=true")
        }
    }

    @OptIn(org.jetbrains.kotlin.gradle.ExperimentalWasmDsl::class)
    wasmJs { browser() }

    // Android and JVM share one Bouncy Castle implementation: the primitives it needs
    // (ML-KEM-768, X25519, Ed25519) are absent from the JDK and identical on both.
    applyDefaultHierarchyTemplate()
    sourceSets {
        val jvmCommonMain by creating { dependsOn(commonMain.get()) }
        androidMain.get().dependsOn(jvmCommonMain)
        jvmMain.get().dependsOn(jvmCommonMain)

        // Production code has NO dependencies beyond the Kotlin stdlib, per-JVM-family Bouncy
        // Castle, and diagnostics-core — every dependency in a crypto library's main source set
        // is attack surface, so additions need a use, not the other way around (LEP-08d).
        // diagnostics-core qualifies because it carries nothing: zero transitive dependencies,
        // inert until an application installs a sink, and lambda-gated so no message is ever
        // built when nothing is listening. It is what turns the protocol from a black box into
        // something the app's log viewer can follow.
        commonMain.dependencies {
            implementation("dev.diagnostics:diagnostics-core:0.1.0")
        }
        commonTest.dependencies {
            implementation(kotlin("test"))
        }
        // Bouncy Castle supplies the primitives the JDK does not ship: ML-KEM-768, X25519 raw
        // agreement, Ed25519. Shared by the Android and JVM targets so the suite can run without
        // a device.
        jvmCommonMain.dependencies { implementation(libs.bouncycastle.provider) }
        // The browser provider binds the noble libraries: pure-JS, synchronous (the CryptoProvider
        // interface is synchronous, which rules out Promise-only WebCrypto), one maintainer,
        // hashes/ciphers/curves independently audited. See CryptoProvider.wasmJs.kt.
        wasmJsMain.dependencies {
            implementation(npm("@noble/hashes", "2.3.0"))
            implementation(npm("@noble/ciphers", "2.3.0"))
            implementation(npm("@noble/curves", "2.3.0"))
            implementation(npm("@noble/post-quantum", "0.7.0"))
        }
        val jvmTest by getting {
            dependencies {
                implementation(kotlin("test"))
                implementation(libs.kotlinx.coroutines.test)
            }
        }
    }
}

// The native libraries cinterop embeds. Registered on a Mac only: elsewhere Kotlin/Native skips
// the Apple targets anyway, and xcrun does not exist.
if (System.getProperty("os.name").startsWith("Mac")) {
    val buildLepNative = tasks.register<Exec>("buildLepNativeMacosArm64") {
        description = "Builds the vendored C and CryptoKit wrappers the macOS CryptoProvider binds."
        val native = layout.projectDirectory.dir("native")
        inputs.dir(native).withPropertyName("nativeSources")
        outputs.dir(lepNativeOutput).withPropertyName("nativeLibraries")
        commandLine(native.file("build.sh").asFile.path, lepNativeOutput.get().asFile.path)
    }
    tasks.named("cinteropLepnativeMacosArm64") {
        // cinterop copies the static libraries into its klib but does not count them as inputs,
        // so without this a rebuilt library is silently linked as the previous one.
        inputs.files(buildLepNative).withPropertyName("nativeLibraries")
    }
}

// Bouncy Castle parity vectors (test-vectors/README.md): written and guarded by the JVM tests,
// replayed against every other provider. -Plep.parity.regenerate rewrites the file.
val parityVectors = layout.projectDirectory.file("test-vectors/bouncycastle-parity.txt")
tasks.named<Test>("jvmTest") {
    systemProperty("lep.parity.vectors", parityVectors.asFile.path)
    if (providers.gradleProperty("lep.parity.regenerate").isPresent) systemProperty("lep.parity.regenerate", "true")
    inputs.files(parityVectors).withPropertyName("parityVectors")
}
tasks.withType<org.jetbrains.kotlin.gradle.targets.native.tasks.KotlinNativeTest>().configureEach {
    environment("LEP_PARITY_VECTORS", parityVectors.asFile.path)
    inputs.files(parityVectors).withPropertyName("parityVectors")
}

android {
    namespace = "org.layeredencryption"
    compileSdk = libs.versions.androidCompileSdk.get().toInt()
    defaultConfig { minSdk = libs.versions.androidMinSdk.get().toInt() }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
}

publishing {
    // Local by default; a real remote is added when the API settles. Consumers can use a Gradle
    // composite build (`includeBuild`) meanwhile, which substitutes this project for the
    // coordinates below without anything being published at all.
    repositories {
        maven {
            name = "local"
            url = uri(layout.buildDirectory.dir("maven"))
        }
    }
}
