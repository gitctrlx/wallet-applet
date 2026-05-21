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

    // Optional integration tests against the real applet running in JCardSim. Tools'
    // SecureChannelClient is verified end-to-end here against the same applet that ships in
    // the CAP — no separate "host-only" reference implementation is allowed to drift.
    testImplementation(libs.jcardsim)
    testImplementation(project(":applet"))
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

// ============================================================================
// `installCap` task — wires `:applet:buildCap` to `meowl gp install`
// ============================================================================
//
// The previous JavaExec-based implementation called `pro.javacard.gp.GPTool`
// through a forked process, which swallowed structured errors. The replacement
// shells out to the launcher script produced by `installDist`, which in turn
// calls the in-process GpFacade — the same code path the `meowl gp install`
// subcommand uses interactively.
tasks.register<Exec>("installCap") {
    group = "javacard"
    description = "Builds the meowl CAP and installs it via `meowl gp install` (default GP keys)."
    dependsOn(":applet:buildCap", "installDist")

    val capProvider =
        rootProject.layout.projectDirectory
            .dir("applet/build/cap")
            .file("meowl-applet.cap")
    inputs.file(capProvider)

    val launcherDir = layout.buildDirectory.dir("install/meowl/bin")
    val launcherFile =
        if (org.gradle.internal.os.OperatingSystem
                .current()
                .isWindows
        ) {
            "meowl.bat"
        } else {
            "meowl"
        }

    doFirst {
        val cap = capProvider.asFile
        check(cap.isFile) { "CAP file not found at $cap. Run :applet:buildCap first." }
        commandLine(
            launcherDir
                .get()
                .asFile
                .resolve(launcherFile)
                .absolutePath,
            "gp",
            "install",
            cap.absolutePath,
        )
    }
}

// ============================================================================
// GraalVM native image — opt-in
// ============================================================================
//
// The `picocli-codegen` annotation processor already emits reflection and
// resource descriptors under `META-INF/native-image/social.meowl/meowl/`, so
// adopting GraalVM is a one-time, additive change rather than a refactor.
//
// To enable on a developer machine that has GraalVM installed:
//
//   1. Add the Gradle plugin to settings.gradle.kts pluginManagement (or to the
//      `plugins {}` block above) at version 0.10.6+:
//          id("org.graalvm.buildtools.native") version "0.10.6"
//   2. Append the following block at the end of this file:
//          graalvmNative {
//              binaries {
//                  named("main") {
//                      imageName = "meowl"
//                      mainClass.set("social.meowl.tools.Main")
//                      buildArgs.addAll("--no-fallback", "-H:+UnlockExperimentalVMOptions")
//                  }
//              }
//          }
//   3. Build with `./gradlew :tools:nativeCompile`.
//
// The block is omitted by default so the JVM build does not depend on
// GraalVM Buildtools — most contributors will never need it, and the launcher
// produced by `installDist` already works on any JDK 25 install.
