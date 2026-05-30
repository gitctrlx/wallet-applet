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
// Run with `./gradlew :tools:run --args="..."` or install a launcher with
// `./gradlew :tools:installDist`.

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

tasks.named<JavaExec>("run") {
    workingDir = rootProject.projectDir
}

// Picocli annotation processor: namespace the generated GraalVM resources by
// `<group>/<name>` so multiple picocli apps can coexist on a single classpath.
tasks.withType<JavaCompile>().configureEach {
    options.encoding = "UTF-8"
    options.compilerArgs.add("-Aproject=${project.group}/${project.name}")
}

// Default `test` task: pure unit tests + simulator-safe assertions only. Tests
// tagged `real-card` (notably `SecureChannelClientIT`) are excluded because the
// post-Phase-1 applet cannot install on jcardsim. See `:tests:realCardTest` and
// `:tools:realCardTest` for the on-card execution path.
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

// Opt-in `realCardTest`: runs the `@Tag("real-card")` integration tests against a physical
// J3R180 via PCSC. Mirrors `:tests:realCardTest` but lives here because SecureChannelClientIT
// belongs to the `tools` module (it exercises `SecureChannelClient`).
//
// Usage:
//   ./gradlew :tools:realCardTest                     # first PCSC terminal found
//   ./gradlew :tools:realCardTest -Preader=NAME       # explicit reader by name
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
    project.findProperty("reader")?.let { systemProperty("cardReader", it.toString()) }
}

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
