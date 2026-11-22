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
            content { includeGroup("com.github.martinpaljak") }
        }
    }
}

plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}

rootProject.name = "wallet-applet"

include("applet", "sim", "host", "tests", "tools")
