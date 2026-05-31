// SPDX-FileCopyrightText: 2026 meowl.social contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Builds the meowl backup CAP — a BIP-39 seed-backup card. A standalone package
// that injects the :shared Secure Channel + primitives at build time (package
// rewritten to social.meowl.backup), mirroring :wallet. See :shared for why the
// code is injected rather than linked (JC 3.0.5 one-package/one-firewall CAPs).

import java.io.File

plugins {
    `java-library`
    alias(libs.plugins.cyclonedx)
}

description = "meowl-applet — backup applet (CAP build)"

// JDK 25 toolchain — Gradle will provision via foojay if missing. The applet
// itself targets Java 8 bytecode so the JCDK v26.0 converter accepts it.
java {
    toolchain.languageVersion =
        JavaLanguageVersion.of(
            libs.versions.jdk
                .get()
                .toInt(),
        )
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

tasks.withType<JavaCompile>().configureEach {
    options.compilerArgs.addAll(listOf("-Xlint:-options", "-Xlint:-classfile"))
    options.encoding = "UTF-8"
}

// SDK locations and target version.
private val jcKit =
    libs.versions.javacard.sdk
        .get()
private val targetSdk =
    libs.versions.javacard.target
        .get()
private val jcKitDir = rootProject.layout.projectDirectory.dir("sdks/$jcKit")
private val jcApiJar = rootProject.layout.projectDirectory.file("sdks/$jcKit/lib/api_classic-$targetSdk.jar")

// Isolated configuration: ant-javacard.jar should not leak into compileClasspath.
val antJavaCard: Configuration by configurations.creating

dependencies {
    antJavaCard(libs.ant.javacard)
    // JavaCard API stub — IDE-only; the runtime lives on the card.
    compileOnly(files(jcApiJar))
}

// Shared source injection — copies :shared sources with the package rewritten
// from social.meowl.shared to social.meowl.backup; feeds compileJava and the CAP
// build (multi-path sources). See wallet/build.gradle.kts for the rationale.
private val sharedSrcDir =
    rootProject.layout.projectDirectory.dir("shared/src/main/java/social/meowl/shared")
private val generatedSharedDir = layout.buildDirectory.dir("generated/shared/java")

val injectShared by tasks.registering(Sync::class) {
    from(sharedSrcDir)
    into(generatedSharedDir.map { it.dir("social/meowl/backup") })
    filteringCharset = "UTF-8"
    filter { line -> line.replace("social.meowl.shared", "social.meowl.backup") }
}

sourceSets.named("main") {
    java.srcDir(generatedSharedDir)
}

tasks.named("compileJava") {
    dependsOn(injectShared)
}

// Applet identifiers (override via `-Pbackup.xxx=...`). Distinct package AID from
// the wallet (F06D656F776C) and NDEF (…03), so this is a separate CAP.
private val packageAid = providers.gradleProperty("backup.packageAid").getOrElse("F06D656F776C02")
private val appletAid = providers.gradleProperty("backup.appletAid").getOrElse("F06D656F776C0201")
private val appletClass = providers.gradleProperty("backup.class").getOrElse("social.meowl.backup.BackupApplet")
private val packageName = providers.gradleProperty("backup.packageName").getOrElse("social.meowl.backup")
// CAP package version is MAJOR.MINOR (bytes); separate from project version.
private val capVersion = providers.gradleProperty("backup.capVersion").getOrElse("0.1")

private val capOutputDir = layout.buildDirectory.dir("cap")

val buildCap by tasks.registering {
    group = "javacard"
    description = "Builds the meowl backup applet CAP file using ant-javacard."

    dependsOn(tasks.named("compileJava"), injectShared)

    inputs.files(antJavaCard).withPropertyName("antJavaCard")
    inputs.dir(layout.projectDirectory.dir("src/main/java")).withPropertyName("sources")
    inputs.dir(generatedSharedDir).withPropertyName("sharedSources")
    inputs.dir(jcKitDir).withPropertyName("jckit")
    inputs.property("packageAid", packageAid)
    inputs.property("appletAid", appletAid)
    inputs.property("appletClass", appletClass)
    inputs.property("packageName", packageName)
    inputs.property("targetSdk", targetSdk)
    inputs.property("capVersion", capVersion)

    outputs.dir(capOutputDir).withPropertyName("capOutput")

    val outDir = capOutputDir.get().asFile
    val outCap = capOutputDir.get().file("meowl-backup.cap").asFile
    val sourcesDir = layout.projectDirectory.dir("src/main/java").asFile
    val sharedSourcesDir = generatedSharedDir.get().asFile
    val jcKitDirFile = jcKitDir.asFile
    val antClasspath = antJavaCard.asPath

    doFirst {
        check(jcKitDirFile.isDirectory) {
            "JavaCard SDK not found at $jcKitDirFile. Run `git submodule update --init` first."
        }
        outDir.mkdirs()
    }

    doLast {
        ant.withGroovyBuilder {
            "taskdef"(
                "name" to "javacard",
                "classname" to "pro.javacard.ant.JavaCard",
                "classpath" to antClasspath,
            )
            "javacard"("jckit" to jcKitDirFile.absolutePath) {
                "cap"(
                    "targetsdk" to targetSdk,
                    "aid" to packageAid,
                    "package" to packageName,
                    "version" to capVersion,
                    "output" to outCap.absolutePath,
                    "export" to outDir.absolutePath,
                    "sources" to
                        listOf(sourcesDir.absolutePath, sharedSourcesDir.absolutePath)
                            .joinToString(File.pathSeparator),
                    "verify" to "true",
                    "debug" to "false",
                    "ints" to "false",
                ) {
                    "applet"(
                        "class" to appletClass,
                        "aid" to appletAid,
                    )
                }
            }
        }
    }
}

tasks.named("assemble") { dependsOn(buildCap) }

// CycloneDX SBOM for the build classpath that produces the CAP.
tasks.cyclonedxDirectBom {
    projectType = org.cyclonedx.model.Component.Type.APPLICATION
    componentName = "meowl-backup"
    includeConfigs = listOf("antJavaCard", "compileClasspath")
    skipConfigs = listOf(".*[Tt]est.*")
    includeBuildSystem = true
    jsonOutput =
        layout.buildDirectory
            .file("reports/meowl-backup-sbom.cdx.json")
            .get()
            .asFile
    xmlOutput.unsetConvention()
}
