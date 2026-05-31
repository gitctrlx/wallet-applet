// SPDX-FileCopyrightText: 2026 meowl.social contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Unit tests run in a normal JVM; jcardsim supplies the javacard.* runtime so the
// applet's arithmetic/helper classes can be exercised directly without loading the CAP.

plugins {
    `java-library`
}

description = "meowl-applet — unit tests (real-card tests opt-in)"

java {
    toolchain.languageVersion =
        JavaLanguageVersion.of(
            libs.versions.jdk
                .get()
                .toInt(),
        )
}

// The PCSC-backed integration suites live in their own `realCard` source set so they stay both
// physically and compile-isolated from the jcardsim-backed unit tests in `src/test`. The unit tests
// need package-private access to applet internals (hence they share package `social.meowl.wallet`),
// whereas the integration suites are pure black-box APDU drivers in `social.meowl.wallet.realcard`.
val realCard: SourceSet by sourceSets.creating

configurations["realCardImplementation"].extendsFrom(configurations["testImplementation"])
configurations["realCardRuntimeOnly"].extendsFrom(configurations["testRuntimeOnly"])

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

    // Reuse applet sources so unit tests can call the applet classes directly.
    testImplementation(project(":wallet"))
}

// Default `test` task: the jcardsim-backed unit suites in `src/test`. The PCSC integration suites
// live in the separate `realCard` source set (see `realCardTest`), so no tag filtering is needed —
// the two test kinds are split by source set, not by annotation.
tasks.test {
    useJUnitPlatform()
    testLogging {
        events("passed", "failed", "skipped")
        showStandardStreams = true
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}

// Opt-in `realCardTest` task: compiles and runs the `realCard` source set against a physical J3R180
// via PCSC. Drives `RealCardClient` from `social.meowl.wallet.realcard.support`, which talks to
// `javax.smartcardio` over whatever PCSC reader the environment surfaces. The applet must already be
// installed on the card.
//
// Usage:
//   ./gradlew :tests:realCardTest                # first PCSC terminal found
//   ./gradlew :tests:realCardTest -Preader=NAME  # explicit reader by name
tasks.register<Test>("realCardTest") {
    description = "Runs the real-card integration suites (src/realCard) against a J3R180 via PCSC."
    group = "verification"
    testClassesDirs = realCard.output.classesDirs
    classpath = realCard.runtimeClasspath
    useJUnitPlatform()
    testLogging {
        events("passed", "failed", "skipped")
        showStandardStreams = true
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
    // Reader name flows through to RealCardClient.connect when set.
    project.findProperty("reader")?.let { systemProperty("cardReader", it.toString()) }
}
