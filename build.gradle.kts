plugins {
    alias(libs.plugins.spotless) apply false
}

val gjfVersion = libs.versions.google.java.format.get()
val ktlintVersion = libs.versions.ktlint.get()
val licenseHeader = rootProject.file("config/spotless/java.license.txt")
val appletVersion = providers.gradleProperty("appletVersion").getOrElse("0.1.0-SNAPSHOT")

allprojects {
    group = "social.meowl"
    version = appletVersion
}

subprojects {
    apply(plugin = "com.diffplug.spotless")

    extensions.configure<com.diffplug.gradle.spotless.SpotlessExtension> {
        java {
            target("src/**/*.java")
            googleJavaFormat(gjfVersion).aosp().reflowLongStrings()
            removeUnusedImports()
            formatAnnotations()
            trimTrailingWhitespace()
            endWithNewline()
            licenseHeaderFile(licenseHeader)
        }
        kotlinGradle {
            ktlint(ktlintVersion)
            target("*.gradle.kts")
        }
    }
}
