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
    testImplementation(project(":applet"))
}

// Default `test` task: pure unit tests only. Tests tagged `real-card` are excluded
// because the J3R180-aligned applet (Fp25519Inv RSA-only, EcPoint transient-only EC
// keys) cannot install on jcardsim — those tests must run against actual silicon. See
// `realCardTest` below.
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

// Opt-in `realCardTest` task: runs the @Tag("real-card") suites against a physical
// J3R180 via PCSC. Drives `RealCardClient` from `social.meowl.applet.cardclient`,
// which talks to `javax.smartcardio` over whatever PCSC reader the environment
// surfaces. The applet must already be installed on the card.
//
// Usage:
//   ./gradlew :tests:realCardTest                # first PCSC terminal found
//   ./gradlew :tests:realCardTest -Preader=NAME  # explicit reader by name
tasks.register<Test>("realCardTest") {
    description = "Runs @Tag(\"real-card\") integration tests against a real J3R180 via PCSC."
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
    // Reader name flows through to RealCardClient.connect when set.
    project.findProperty("reader")?.let { systemProperty("cardReader", it.toString()) }
}
