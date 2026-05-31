// SPDX-FileCopyrightText: 2026 meowl.social contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Builds the meowl NDEF Type 4 tag CAP via ant-javacard. A standalone package
// (no shared meowl code) so a card can carry the NFC discovery tag independently
// of the wallet and backup applets. Mirrors :wallet:buildCap.

plugins {
    `java-library`
    alias(libs.plugins.cyclonedx)
}

description = "meowl-applet — NDEF Type 4 tag applet (CAP build)"

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
    // Silence JDK 25's "source 8 is obsolete" warning. The applet MUST stay on
    // Java 8 bytecode for the JavaCard converter.
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

// Applet identifiers (override via `-Pndef.xxx=...`). Distinct package AID from
// the wallet (F06D656F776C) so this is a separate CAP. The declared applet AID
// is meowl-namespaced; the GP install step instantiates it under the NFC Forum
// Type 4 well-known AID D2760000850101 for phone auto-discovery.
private val packageAid = providers.gradleProperty("ndef.packageAid").getOrElse("F06D656F776C03")
private val appletAid = providers.gradleProperty("ndef.appletAid").getOrElse("F06D656F776C0301")
private val appletClass = providers.gradleProperty("ndef.class").getOrElse("social.meowl.ndef.NdefApplet")
private val packageName = providers.gradleProperty("ndef.packageName").getOrElse("social.meowl.ndef")
// CAP package version is MAJOR.MINOR (bytes); separate from project version.
private val capVersion = providers.gradleProperty("ndef.capVersion").getOrElse("0.1")

private val capOutputDir = layout.buildDirectory.dir("cap")

val buildCap by tasks.registering {
    group = "javacard"
    description = "Builds the meowl NDEF applet CAP file using ant-javacard."

    dependsOn(tasks.named("compileJava"))

    inputs.files(antJavaCard).withPropertyName("antJavaCard")
    inputs.dir(layout.projectDirectory.dir("src/main/java")).withPropertyName("sources")
    inputs.dir(jcKitDir).withPropertyName("jckit")
    inputs.property("packageAid", packageAid)
    inputs.property("appletAid", appletAid)
    inputs.property("appletClass", appletClass)
    inputs.property("packageName", packageName)
    inputs.property("targetSdk", targetSdk)
    inputs.property("capVersion", capVersion)

    outputs.dir(capOutputDir).withPropertyName("capOutput")

    val outDir = capOutputDir.get().asFile
    val outCap = capOutputDir.get().file("meowl-ndef.cap").asFile
    val sourcesDir = layout.projectDirectory.dir("src/main/java").asFile
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
                    "sources" to sourcesDir.absolutePath,
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

// CycloneDX SBOM for the build classpath that produces the CAP. The runtime
// classpath is empty (the applet runs on the card), so the SBOM describes
// what was used to build the artefact. JSON-only; schema defaults to v1.6.
tasks.cyclonedxDirectBom {
    projectType = org.cyclonedx.model.Component.Type.APPLICATION
    componentName = "meowl-ndef"
    includeConfigs = listOf("antJavaCard", "compileClasspath")
    skipConfigs = listOf(".*[Tt]est.*")
    includeBuildSystem = true
    jsonOutput =
        layout.buildDirectory
            .file("reports/meowl-ndef-sbom.cdx.json")
            .get()
            .asFile
    xmlOutput.unsetConvention()
}
