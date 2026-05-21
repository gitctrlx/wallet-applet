// SPDX-FileCopyrightText: 2026 meowl.social contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// `meowl` — host-side CLI for the meowl-applet.
//
// A modern picocli command tree on top of:
//   * apdu4j 26.x          — BIBO transport, decorators, MockBIBO replay
//   * GlobalPlatformPro    — library-level GP install / uninstall / list
//   * BouncyCastle         — host-side secp256k1 / AES / HMAC for the MEAP-2
//                            Secure Channel client
//   * JLine 3              — interactive shell (`meowl shell`)
//   * jackson-jr           — JSON output mode (`--json`)
//
// Run with `./gradlew :tools:run --args="..."`, install a launcher with
// `./gradlew :tools:installDist`, or (later) compile to a native binary with
// `./gradlew :tools:nativeCompile` once the GraalVM Buildtools plugin is wired
// up. The picocli annotation processor already emits reflection / resource
// descriptors under `META-INF/native-image/social.meowl/meowl/` so a native
// build is a one-line addition rather than a refactor.

plugins {
    application
    `java-library`
}

description = "meowl-applet — host-side CLI (`meowl`)"

java {
    toolchain.languageVersion =
        JavaLanguageVersion.of(
            libs.versions.jdk
                .get()
                .toInt(),
        )
}

dependencies {
    // CLI framework + GraalVM-friendly annotation processor.
    implementation(libs.picocli)
    annotationProcessor(libs.picocli.codegen)

    // Smart-card transport.
    implementation(libs.apdu4j.pcsc)
    implementation(libs.apdu4j.core)

    // GlobalPlatformPro — library use, not a forked process.
    implementation(libs.gppro)

    // Host-side crypto for the MEAP-2 Secure Channel client.
    implementation(libs.bouncycastle.prov)

    // Interactive shell.
    implementation(libs.jline)

    // JSON output (`--json`); a tiny binding-only Jackson without ObjectMapper.
    implementation(libs.jackson.jr)

    // Logging façade + concrete backend.
    implementation(libs.slf4j.api)
    runtimeOnly(libs.slf4j.simple)

    // Tests.
    testImplementation(platform(libs.junit.bom))
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.platform.launcher)
    testImplementation(libs.apdu4j.core) // MockBIBO for replay tests
    testImplementation(libs.bouncycastle.prov)
}

application {
    mainClass = "social.meowl.tools.Main"
    applicationName = "meowl"
}

// Picocli annotation processor: namespace the generated GraalVM resources by
// `<group>/<name>` so multiple picocli apps can coexist on a single classpath.
tasks.withType<JavaCompile>().configureEach {
    options.encoding = "UTF-8"
    options.compilerArgs.add("-Aproject=${project.group}/${project.name}")
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("passed", "failed", "skipped")
        showStandardStreams = true
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}

// `installCap` is reintroduced once the picocli `meowl gp install` subcommand
// lands (see Phase 2 of the tools redesign). The previous JavaExec-based
// implementation has been removed: it called the now-superseded
// `pro.javacard.gp.GPTool` entry-point through process boundaries, which
// swallowed structured errors. The replacement will reuse the in-process
// GpFacade that backs the `meowl gp install` command.
