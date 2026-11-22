plugins {
    alias(libs.plugins.spotless)
}

val gjfVersion = libs.versions.google.java.format.get()
val ktlintVersion = libs.versions.ktlint.get()

fun spdxHeader(license: String) = "// SPDX-FileCopyrightText: 2026 QuantX\n// SPDX-License-Identifier: $license\n"

allprojects {
    group = "org.qntx.card"
}

spotless {
    java {
        target("spec/vectors/gen/java/**/*.java")
        googleJavaFormat(gjfVersion).aosp()
        licenseHeader(spdxHeader("MIT OR Apache-2.0"))
    }
    kotlinGradle {
        target("*.gradle.kts")
        ktlint(ktlintVersion)
    }
}

subprojects {
    apply(plugin = "com.diffplug.spotless")

    extensions.configure<com.diffplug.gradle.spotless.SpotlessExtension> {
        java {
            target("src/**/*.java")
            googleJavaFormat(gjfVersion).aosp()
            removeUnusedImports()
            licenseHeader(spdxHeader("AGPL-3.0-or-later"))
        }
        kotlinGradle {
            target("*.gradle.kts")
            ktlint(ktlintVersion)
        }
    }

    plugins.withId("java") {
        extensions.configure<JavaPluginExtension> {
            toolchain.languageVersion = JavaLanguageVersion.of(libs.versions.jdk.get().toInt())
        }
        tasks.withType<JavaCompile>().configureEach {
            options.encoding = "UTF-8"
        }
        tasks.withType<AbstractArchiveTask>().configureEach {
            isPreserveFileTimestamps = false
            isReproducibleFileOrder = true
        }
    }
}
