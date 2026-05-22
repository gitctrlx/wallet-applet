// SPDX-FileCopyrightText: 2026 meowl.social contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Tests run against jcardsim inside a normal JVM — they do not load the CAP.
// The applet sources are reused from `:applet`.

plugins {
    `java-library`
}

description = "meowl-applet — jcardsim integration tests"

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

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("passed", "failed", "skipped")
        showStandardStreams = true
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
    // Forward selected -D properties to the forked test JVM. The benchmark suite
    // (BenchmarkSuite.java) is gated by `@EnabledIfSystemProperty(named="bench")`
    // so it stays inert in normal CI but runs on demand with `-Dbench=true`.
    System.getProperty("bench")?.let { systemProperty("bench", it) }
}
