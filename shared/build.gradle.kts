// SPDX-FileCopyrightText: 2026 meowl.social contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Single source of truth for meowl applet code shared across CAPs: the Secure
// Channel, KDF, authentikey, PIN manager, lifecycle FSM, reset trigger and the
// common byte/curve primitives.
//
// This module is deliberately NOT a CAP. JavaCard 3.0.5 classic CAPs are
// one-package / one-firewall, so a class cannot be shared across the wallet and
// backup packages at runtime. Instead each applet module INJECTS these sources
// at `buildCap` time with the package rewritten to its own (see the
// `injectShared` task in `wallet/build.gradle.kts` and `backup/build.gradle.kts`).
//
// The project exists only to (a) compile-check that the shared closure is
// self-contained and (b) host the sources under the same Spotless contract as
// the rest of the tree.

plugins {
    `java-library`
}

description = "meowl-applet — shared applet sources (compile-checked; injected into CAPs)"

// JDK 25 toolchain — provisioned via foojay if missing. Sources target Java 8
// bytecode so the JavaCard converter accepts the injected copies downstream.
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

// JavaCard API stub — IDE/compile-only; the runtime lives on the card.
private val jcKit =
    libs.versions.javacard.sdk
        .get()
private val targetSdk =
    libs.versions.javacard.target
        .get()
private val jcApiJar = rootProject.layout.projectDirectory.file("sdks/$jcKit/lib/api_classic-$targetSdk.jar")

dependencies {
    compileOnly(files(jcApiJar))
}
