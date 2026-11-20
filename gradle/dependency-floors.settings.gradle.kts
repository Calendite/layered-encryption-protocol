// ── Security floors ──────────────────────────────────────────────────────────────────────────────
//
// The lowest version of a library this build will resolve, anywhere. Each entry is the first
// release that fixes a Dependabot alert on this repository. A request below its floor is raised to
// it; a request at or above it is left alone, so a floor never holds a library back.
//
// None of these is a dependency of the library itself, whose production code depends on nothing
// but the Kotlin stdlib and Bouncy Castle. They arrive through tooling: AGP's unified test
// platform (Netty, httpclient, Bouncy Castle 1.79) and the build classpath (Guava, jose4j, jdom2,
// commons-lang3). They sit in configurations those plugins create for themselves, which no catalog
// entry can reach, but the dependency graph Dependabot reads includes them. A floor covers every
// configuration in every project, build scripts included, so it closes the alert instead of
// explaining it away. Calendite-KMP carries the same file; keep the two in step.
//
// Bouncy Castle stays on 1.85 here. All three of its jars must move together, and 1.86 relocates
// ML-DSA out of org.bouncycastle.pqc.crypto.mldsa, which BouncyCastleCryptoProvider still imports
// from. The library's own Bouncy Castle is the catalog's 1.85.2, which a floor of 1.85 leaves alone.
//
// These override other plugins' own pinning. Re-check them when AGP or Kotlin moves, and delete
// any floor that every resolution already clears: a floor left behind after it stops being needed
// misdescribes what the build depends on.

val securityFloors: Map<String, String> = mapOf(
    "org.bouncycastle:bcprov-jdk18on" to "1.85",
    "org.bouncycastle:bcpkix-jdk18on" to "1.85",
    "org.bouncycastle:bcutil-jdk18on" to "1.85",
    "com.google.guava:guava" to "33.7.2",
    "org.freemarker:freemarker" to "2.3.35",
    "org.bitbucket.b_c:jose4j" to "0.9.6",
    "org.jdom:jdom2" to "2.0.6.1",
    "org.apache.commons:commons-lang3" to "3.18.0",
    "org.apache.httpcomponents:httpclient" to "4.5.14",
    "io.opentelemetry:opentelemetry-api" to "1.67.0",
    "io.opentelemetry:opentelemetry-context" to "1.67.0",
)

// Every Netty 4.1 module shares one version, so they all rise together to the release that clears
// the newest Netty alert. Netty 4.2 is a different line and is left alone.
val nettyFloor = "4.1.141.Final"

fun versionNumbers(version: String): List<Int> =
    Regex("\\d+").findAll(version).map { it.value.toInt() }.toList()

fun isBelow(version: String, floor: String): Boolean {
    val have = versionNumbers(version)
    val want = versionNumbers(floor)
    for (i in 0 until maxOf(have.size, want.size)) {
        val diff = have.getOrElse(i) { 0 } - want.getOrElse(i) { 0 }
        if (diff != 0) return diff < 0
    }
    return false
}

// Guava publishes only flavoured versions (33.7.2-android, 33.7.2-jre), so a raise keeps the
// flavour asked for. A request with no flavour gets -jre: since 32.1 Guava's variant metadata
// picks the Android or JRE jar from the consumer's attributes, whatever the version string says.
fun guavaFlavourOf(requested: String): String =
    requested.substringAfter('-', "").ifEmpty { "jre" }

fun isNetty41(group: String, version: String): Boolean =
    group == "io.netty" && version.startsWith("4.1.")

fun floorFor(group: String, name: String, version: String): String? {
    if (isNetty41(group, version)) return nettyFloor
    val floor = securityFloors["$group:$name"] ?: return null
    if (group == "com.google.guava" && name == "guava") return "$floor-${guavaFlavourOf(version)}"
    return floor
}

fun Configuration.raiseToSecurityFloors() {
    resolutionStrategy.eachDependency {
        val version = requested.version ?: return@eachDependency
        val floor = floorFor(requested.group, requested.name, version) ?: return@eachDependency
        if (!isBelow(version, floor)) return@eachDependency
        useVersion(floor)
        because("security floor, see gradle/dependency-floors.settings.gradle.kts")
    }
}

gradle.beforeProject {
    buildscript.configurations.configureEach { raiseToSecurityFloors() }
    configurations.configureEach { raiseToSecurityFloors() }
}
