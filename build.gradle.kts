plugins {
    alias(libs.plugins.spotless) apply false
}

group = "social.meowl"
version = providers.gradleProperty("appletVersion").getOrElse("0.1.0-SNAPSHOT")

subprojects {
    apply(plugin = "com.diffplug.spotless")

    extensions.configure<com.diffplug.gradle.spotless.SpotlessExtension> {
        java {
            target("src/**/*.java")
            googleJavaFormat("1.27.0").aosp().reflowLongStrings()
            removeUnusedImports()
            trimTrailingWhitespace()
            endWithNewline()
            licenseHeaderFile(rootProject.file("config/spotless/java.license.txt"))
        }
        kotlinGradle {
            ktlint("1.5.0")
            target("*.gradle.kts")
        }
    }
}
