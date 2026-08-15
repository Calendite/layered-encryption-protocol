import com.github.benmanes.gradle.versions.updates.DependencyUpdatesTask

plugins {
    alias(libs.plugins.kotlinJvm) apply false
    alias(libs.plugins.kotlinMultiplatform) apply false
    alias(libs.plugins.androidLibrary) apply false
    alias(libs.plugins.versions)
    alias(libs.plugins.versionCatalogUpdate)
}

// The dependency-refresh pipeline (LEP-08h): `versionCatalogUpdate` rewrites
// gradle/libs.versions.toml to the latest *stable* releases; the deps-refresh workflow runs it on
// a schedule, regenerates the dependency-verification metadata, and opens a pull request only
// after the full test suite has passed against the fresh versions. Pre-release versions are
// rejected here so an alpha can never ride in on the automation.
fun isStable(version: String): Boolean {
    val stableKeyword = listOf("RELEASE", "FINAL", "GA").any { version.uppercase().contains(it) }
    return stableKeyword || "^[0-9,.v-]+(-r)?$".toRegex().matches(version)
}

tasks.withType<DependencyUpdatesTask>().configureEach {
    rejectVersionIf { !isStable(candidate.version) && isStable(currentVersion) }
}

versionCatalogUpdate {
    // The catalog's grouping and comments are load-bearing documentation; do not re-sort it.
    sortByKey = false
}
