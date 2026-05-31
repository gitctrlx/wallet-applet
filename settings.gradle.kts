pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositoriesMode = RepositoriesMode.FAIL_ON_PROJECT_REPOS
    repositories {
        mavenCentral()
        // Martin Paljak's JavaCard ecosystem (ant-javacard, apdu4j, gppro, …).
        maven("https://mvn.javacard.pro/maven/") {
            name = "javacard.pro"
            content { includeGroupByRegex("com\\.github\\.martinpaljak(?:\\..*)?|pro\\.javacard(?:\\..*)?") }
        }
    }
}

plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}

rootProject.name = "meowl-applet"

include("shared", "wallet", "backup", "ndef", "tests", "tools")

