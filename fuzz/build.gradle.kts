// Coverage-guided fuzzing for the wire decoders (LEP-08g), isolated in its own JVM module so the
// main test suites keep their JUnit 4 / kotlin.test setup untouched.
//
// Two modes, one set of targets:
//  - `./gradlew :fuzz:test`             — regression mode: each @FuzzTest runs its committed
//                                         corpus (plus a default input) as ordinary JUnit tests.
//  - `JAZZER_FUZZ=1 ./gradlew :fuzz:test` — real coverage-guided campaigns; discovered crashers
//                                         land in `src/test/resources/.../<Target>Inputs/` and
//                                         become permanent regression cases. CI wiring is LEP-08h.
plugins {
    kotlin("jvm")
}

dependencies {
    implementation(project(":lep"))
    testImplementation("com.code-intelligence:jazzer-junit:0.30.0")
    testImplementation("org.junit.jupiter:junit-jupiter:5.11.4")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.test {
    useJUnitPlatform()
}
