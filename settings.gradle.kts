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
        maven("https://mvn.javacard.pro/maven/") {
            name = "javacard.pro"
            content { includeGroupByRegex("com\\.github\\.martinpaljak.*|pro\\.javacard.*") }
        }
    }
}

plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "0.10.0"
}

rootProject.name = "meowl-applet"

include("applet", "tests", "tools")
