// SPDX-FileCopyrightText: 2026 meowl.social contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Host-side companion tools:
//   * `gp`        — runs GlobalPlatformPro from the project (load / list / delete applets).
//   * `meowl`     — minimal APDU CLI talking to a real card via apdu4j.

plugins {
    application
}

description = "meowl-applet — host-side tooling (gp wrapper + APDU CLI)"

java {
    toolchain.languageVersion = JavaLanguageVersion.of(libs.versions.jdk.get().toInt())
}

// GP is consumed at runtime via the `gp` task — isolated configuration so it
// does not pollute the application classpath.
val gpCli: Configuration by configurations.creating

dependencies {
    implementation(libs.apdu4j.pcsc)
    implementation(libs.apdu4j.core)
    implementation(libs.slf4j.api)
    runtimeOnly(libs.slf4j.simple)

    gpCli(libs.globalplatformpro) { isTransitive = true }
}

application {
    mainClass = "social.meowl.tools.Cli"
}

tasks.register<JavaExec>("gp") {
    group = "javacard"
    description = "Runs GlobalPlatformPro (pass GP args via -Pargs=\"...\")."
    classpath = gpCli
    mainClass = "pro.javacard.gp.GPTool"
    val gpArgs = providers.gradleProperty("args").getOrElse("--help")
    args = gpArgs.split(" ").filter { it.isNotBlank() }
    standardInput = System.`in`
}

tasks.register("installCap") {
    group = "javacard"
    description = "Installs the freshly built CAP to a connected card via GlobalPlatformPro."
    dependsOn(":applet:buildCap")
    doLast {
        val cap = rootProject.layout.projectDirectory.dir("applet/build/cap").file("meowl-applet.cap").asFile
        check(cap.isFile) { "CAP file not found at $cap. Run :applet:buildCap first." }
        javaexec {
            classpath = gpCli
            mainClass = "pro.javacard.gp.GPTool"
            args("--install", cap.absolutePath, "--default")
            standardInput = System.`in`
        }
    }
}
