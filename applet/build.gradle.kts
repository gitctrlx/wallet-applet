// SPDX-FileCopyrightText: 2026 meowl.social contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Builds the JavaCard CAP file by invoking ant-javacard directly (no third-party
// Gradle plugin needed). Sources must remain JavaCard-compatible: only the
// bytecodes/features supported by the Converter for the chosen targetsdk.

plugins {
    base
    `java-library` // exposes compiled classes for `:tests` to consume via simulator
}

description = "meowl-applet — JavaCard applet (CAP build)"

// Resolve ant-javacard.jar via Maven coordinates, isolated from runtime classpath.
val antJavaCard: Configuration by configurations.creating

dependencies {
    antJavaCard(libs.ant.javacard)
    // Re-declare the JavaCard API jar from the SDK kit so the IDE sees the
    // classes; do NOT package or ship it (provided by the card).
    compileOnly(
        files(rootProject.layout.projectDirectory.dir("sdks/${libs.versions.javacard.sdk.get()}/lib/api_classic.jar")),
    )
}

java {
    // JavaCard class file format limit: JDK 10 (class v54) per JCDK 25.0+.
    // We compile to Java 7 bytecode to also stay safe for older JC kits.
    sourceCompatibility = JavaVersion.VERSION_1_7
    targetCompatibility = JavaVersion.VERSION_1_7
}

// ---- ant-javacard configuration --------------------------------------------

val sdkDir = rootProject.layout.projectDirectory.dir("sdks").asFile
val jcKit = libs.versions.javacard.sdk.get()
val jcKitDir = File(sdkDir, jcKit)
val targetSdk = libs.versions.javacard.target.get()

val packageAid = providers.gradleProperty("applet.packageAid").getOrElse("F06D656F776C")          // "F0" + "meowl"
val appletAid = providers.gradleProperty("applet.appletAid").getOrElse("F06D656F776C01")         //  + index 01
val appletClass = providers.gradleProperty("applet.class").getOrElse("social.meowl.applet.MeowlApplet")
val packageName = providers.gradleProperty("applet.packageName").getOrElse("social.meowl.applet")

val capOutputDir: Provider<Directory> = layout.buildDirectory.dir("cap")

val buildCap by tasks.registering {
    group = "javacard"
    description = "Builds the meowl applet CAP file using ant-javacard."

    dependsOn(tasks.named("compileJava"))

    inputs.files(antJavaCard).withPropertyName("antJavaCard")
    inputs.dir("src/main/java").withPropertyName("sources")
    inputs.dir(jcKitDir).withPropertyName("jckit")
    inputs.property("packageAid", packageAid)
    inputs.property("appletAid", appletAid)
    inputs.property("appletClass", appletClass)
    inputs.property("packageName", packageName)
    inputs.property("targetSdk", targetSdk)
    inputs.property("version", project.version.toString())

    outputs.dir(capOutputDir).withPropertyName("capOutput")

    doFirst {
        check(jcKitDir.isDirectory) {
            "JavaCard SDK not found at $jcKitDir. Did you run `git submodule update --init`?"
        }
        capOutputDir.get().asFile.mkdirs()
    }

    doLast {
        ant.withGroovyBuilder {
            "taskdef"(
                "name" to "javacard",
                "classname" to "pro.javacard.ant.JavaCard",
                "classpath" to antJavaCard.asPath,
            )
            "javacard"("jckit" to jcKitDir.absolutePath) {
                "cap"(
                    "targetsdk" to targetSdk,
                    "aid" to packageAid,
                    "package" to packageName,
                    "version" to project.version.toString(),
                    "output" to capOutputDir.get().file("meowl-applet.cap").asFile.absolutePath,
                    "export" to capOutputDir.get().asFile.absolutePath,
                    "sources" to file("src/main/java").absolutePath,
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
