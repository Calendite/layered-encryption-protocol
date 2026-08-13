plugins {
    kotlin("jvm")
    application
}

// A demonstration, not part of the library: it depends on lep the way any consumer would, which
// is also the point — if the public API is awkward, this is where that shows up first.
dependencies {
    implementation(project(":lep"))
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.0")
    testImplementation(kotlin("test"))
}

tasks.test { useJUnitPlatform() }

kotlin { jvmToolchain(21) }

application {
    mainClass.set("org.layeredencryption.playground.PlaygroundKt")
}
