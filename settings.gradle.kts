rootProject.name = "layered-encryption-protocol"

pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
    }
}

// Diagnostics come from the zero-dependency core of kmp-diagnostics — a composite build, like
// the app's inclusion of this repo, so the library is developed against real sources and swaps
// to published coordinates by deleting these lines. A sibling checkout locally; CI checks the
// repo out nested (see ci.yml). Failing loudly beats resolving nothing.
val diagnostics = listOf("../kmp-diagnostics", "kmp-diagnostics").firstOrNull { file(it).exists() }
    ?: error(
        "kmp-diagnostics not found: clone github.com/Calendite/kmp-diagnostics next to this " +
            "repository (or into ./kmp-diagnostics)",
    )
includeBuild(diagnostics)

include(":lep")
include(":playground")
include(":fuzz")
