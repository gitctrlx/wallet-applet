// SPDX-FileCopyrightText: 2026 meowl.social contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Test harness running the applet inside JCardSim (no physical card required).
// The applet sources are shared with `:applet` so that the simulator JVM compiles
// them with normal JDK bytecode (it does NOT load the CAP file).

plugins {
    `java-library`
}

description = "meowl-applet — JCardSim integration tests"

java {
    toolchain.languageVersion = JavaLanguageVersion.of(libs.versions.jdk.get().toInt())
}

dependencies {
    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)

    // JCardSim brings its own javacard.framework.* — must come BEFORE any SDK jar
    // in the classpath. We deliberately do NOT add api_classic.jar here.
    testImplementation(libs.jcardsim)
    testImplementation(libs.bouncycastle.prov)
    testImplementation(libs.slf4j.api)
    testRuntimeOnly(libs.slf4j.simple)

    // Reuse applet sources for the simulator.
    testImplementation(project(":applet"))
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("passed", "failed", "skipped")
        showStandardStreams = true
    }
    // JCardSim still benefits from disabling the verifier on older JDKs.
    // For JDK 13+ -noverify is a no-op but harmless.
    jvmArgs("-noverify")
}
