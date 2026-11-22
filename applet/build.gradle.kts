import java.time.LocalDateTime
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

plugins {
    java
    alias(libs.plugins.cyclonedx)
}

description = "qntx card applet (one CAP, package org.qntx.card)"

val jcKitDir = rootProject.layout.projectDirectory.dir("sdks/${libs.versions.javacard.sdk.get()}")
val targetSdk =
    libs.versions.javacard.target
        .get()

val antJavaCard: Configuration by configurations.creating

dependencies {
    antJavaCard(libs.ant.javacard)
    compileOnly(files(jcKitDir.file("lib/api_classic-$targetSdk.jar")))
}

tasks.compileJava {
    options.release = 8
    options.compilerArgs.addAll(listOf("-Xlint:all", "-Xlint:-options", "-Werror"))
}

/**
 * Rewrites the converter's CAP with fixed entry times and without the build-time manifest
 * attributes, so that two builds of the same sources give the same SHA-256 (architecture §7).
 * Entry order and every component byte are kept.
 */
fun normalizeCap(cap: File) {
    val volatile = setOf("Created-By", "Java-Card-CAP-Creation-Time")
    val fixed = LocalDateTime.of(1980, 2, 1, 0, 0)
    val tmp = File(cap.parentFile, cap.name + ".tmp")
    ZipFile(cap).use { zip ->
        ZipOutputStream(tmp.outputStream()).use { out ->
            for (e in zip.entries()) {
                var data = zip.getInputStream(e).readBytes()
                if (e.name == "META-INF/MANIFEST.MF") {
                    data =
                        String(data, Charsets.UTF_8)
                            .split("\r\n")
                            .filterNot { line -> volatile.any { line.startsWith("$it:") } }
                            .joinToString("\r\n")
                            .toByteArray(Charsets.UTF_8)
                }
                val n = ZipEntry(e.name)
                n.timeLocal = fixed
                if (e.method == ZipEntry.STORED) {
                    n.method = ZipEntry.STORED
                    n.size = data.size.toLong()
                    n.compressedSize = data.size.toLong()
                    n.crc = CRC32().apply { update(data) }.value
                }
                out.putNextEntry(n)
                out.write(data)
                out.closeEntry()
            }
        }
    }
    check(tmp.renameTo(cap)) { "cannot replace $cap" }
}

val packageAid = "F0716E747800"
val walletAid = "F0716E74780101"
val ndefAid = "F0716E74780201"
val capFile = layout.buildDirectory.file("cap/qntx-card.cap")

val cap by tasks.registering {
    group = "build"
    description = "Converts the applet package into qntx-card.cap with the JCDK converter."
    val sources = layout.projectDirectory.dir("src/main/java")
    val kit = jcKitDir.asFile
    val antClasspath = antJavaCard
    inputs.files(antClasspath).withPropertyName("antJavaCard")
    inputs.dir(sources).withPropertyName("sources")
    inputs.dir(jcKitDir).withPropertyName("jckit")
    outputs.file(capFile)
    dependsOn(tasks.compileJava)
    doLast {
        val out = capFile.get().asFile
        out.parentFile.mkdirs()
        check(kit.isDirectory) { "JavaCard SDK missing at $kit: run `git submodule update --init`" }
        ant.withGroovyBuilder {
            "taskdef"("name" to "javacard", "classname" to "pro.javacard.ant.JavaCard", "classpath" to antClasspath.asPath)
            "javacard"("jckit" to kit.absolutePath) {
                "cap"(
                    "targetsdk" to targetSdk,
                    "aid" to packageAid,
                    "package" to "org.qntx.card",
                    "version" to "1.0",
                    "output" to out.absolutePath,
                    "sources" to sources.asFile.absolutePath,
                    "verify" to "true",
                    "debug" to "false",
                    "ints" to "false",
                ) {
                    "applet"("class" to "org.qntx.card.WalletApplet", "aid" to walletAid)
                    "applet"("class" to "org.qntx.card.NdefApplet", "aid" to ndefAid)
                }
            }
        }
        normalizeCap(out)
    }
}

tasks.assemble { dependsOn(cap) }

tasks.cyclonedxDirectBom {
    projectType = org.cyclonedx.model.Component.Type.FIRMWARE
    componentName = "qntx-card"
    includeConfigs = listOf("antJavaCard", "compileClasspath")
    jsonOutput =
        layout.buildDirectory
            .file("reports/qntx-card.cdx.json")
            .get()
            .asFile
    xmlOutput.unsetConvention()
}
