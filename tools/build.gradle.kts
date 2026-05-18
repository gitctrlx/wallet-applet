// SPDX-FileCopyrightText: 2026 meowl.social contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Host-side companion tools:
//   * `gp`         — runs GlobalPlatformPro (list / install / delete applets).
//   * `installCap` — builds the CAP then installs it via GP with default keys.
//   * `meowl` (run)— APDU CLI talking to a real PC/SC card via apdu4j.

plugins {
    application
}

description = "meowl-applet — host-side tooling (gp wrapper + APDU CLI)"

java {
    toolchain.languageVersion =
        JavaLanguageVersion.of(
            libs.versions.jdk
                .get()
                .toInt(),
        )
}

// Isolated classpath: keeps GlobalPlatformPro out of the application's runtime.
val gpCli: Configuration by configurations.creating

dependencies {
    implementation(libs.apdu4j.pcsc)
    implementation(libs.apdu4j.core)
    implementation(libs.slf4j.api)
    runtimeOnly(libs.slf4j.simple)

    gpCli(libs.gppro) { isTransitive = true }
}

application {
    mainClass = "social.meowl.tools.Cli"
    applicationName = "meowl"
}

private val gpToolMain = "pro.javacard.gp.GPTool"

tasks.register<JavaExec>("gp") {
    group = "javacard"
    description = "Runs GlobalPlatformPro (pass GP args via `-Pargs=\"...\"`)."
    classpath = gpCli
    mainClass = gpToolMain
    standardInput = System.`in`

    val gpArgs = providers.gradleProperty("args").getOrElse("--help")
    argumentProviders.add { gpArgs.split(' ').filter { it.isNotBlank() } }
}

tasks.register<JavaExec>("installCap") {
    group = "javacard"
    description = "Installs the freshly built CAP onto a connected card via GP (default keys)."
    dependsOn(":applet:buildCap")

    val capProvider =
        rootProject.layout.projectDirectory
            .dir("applet/build/cap")
            .file("meowl-applet.cap")

    inputs.file(capProvider)

    classpath = gpCli
    mainClass = gpToolMain
    standardInput = System.`in`

    argumentProviders.add {
        val cap = capProvider.asFile
        check(cap.isFile) { "CAP file not found at $cap. Run :applet:buildCap first." }
        listOf("--install", cap.absolutePath, "--default")
    }
}
