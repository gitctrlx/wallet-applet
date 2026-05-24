// SPDX-FileCopyrightText: 2026 meowl.social contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Tests run against jcardsim inside a normal JVM — they do not load the CAP.
// The applet sources are reused from `:applet`.

plugins {
    `java-library`
}

description = "meowl-applet — unit + simulator tests (real-card tests opt-in)"

java {
    toolchain.languageVersion =
        JavaLanguageVersion.of(
            libs.versions.jdk
                .get()
                .toInt(),
        )
}

dependencies {
    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    // JUnit 6 requires the launcher to be declared explicitly on the runtime
    // classpath (it is no longer pulled in transitively by `junit-jupiter`).
    testRuntimeOnly(libs.junit.platform.launcher)

    // jcardsim brings its own javacard.framework.* — it MUST come before any
    // SDK jar on the classpath; we deliberately do NOT depend on api_classic.
    testImplementation(libs.jcardsim)
    testImplementation(libs.bouncycastle.prov)
    testImplementation(libs.slf4j.api)
    testRuntimeOnly(libs.slf4j.simple)

    // Reuse applet sources for the simulator.
    testImplementation(project(":applet"))
}

// Default `test` task: pure unit tests + simulator-safe tests only. Tests tagged
// `real-card` are excluded because the J3R180-aligned applet (Fp25519Inv RSA-only,
// EcPoint transient-only EC keys) cannot install on jcardsim — those tests must
// run against actual silicon. See `realCardTest` below.
tasks.test {
    useJUnitPlatform {
        excludeTags("real-card")
    }
    testLogging {
        events("passed", "failed", "skipped")
        showStandardStreams = true
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}

// Opt-in `realCardTest` task: runs the integration tests tagged `real-card`. Today
// these still wire jcardsim's `CardSimulator` and therefore fail (the simulator
// cannot satisfy the J3R180-only key types); the task is a placeholder for the
// upcoming `CardClient` abstraction + `RealCardClient` PCSC backend epic. Once
// that lands, run with `./gradlew :tests:realCardTest -Preader=ACR1552U-MF`.
tasks.register<Test>("realCardTest") {
    description = "Runs integration tests against a real card (currently a placeholder — see README)."
    group = "verification"
    testClassesDirs = sourceSets["test"].output.classesDirs
    classpath = sourceSets["test"].runtimeClasspath
    useJUnitPlatform {
        includeTags("real-card")
    }
    testLogging {
        events("passed", "failed", "skipped")
        showStandardStreams = true
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
    // Forward -Dbench=true to the forked test JVM so BenchmarkSuite (gated on the
    // system property *and* `real-card` tag) runs only when explicitly requested.
    System.getProperty("bench")?.let { systemProperty("bench", it) }
    // Reserved hooks for the future real-card backend.
    project.findProperty("reader")?.let { systemProperty("cardReader", it.toString()) }
}
