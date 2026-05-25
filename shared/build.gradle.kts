// SPDX-FileCopyrightText: 2026 meowl.social contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// `shared` — pure-Java protocol constants shared across the applet, host CLI
// and integration test modules.
//
// Why a separate module?
//   * The applet (`:applet`) compiles against the JC 3.0.5 API stub and emits
//     Java 8 bytecode for the JavaCard converter. The host CLI (`:tools`) and
//     test harness (`:tests`) compile against modern JDK 25.
//   * Until this module landed, every cross-cutting protocol constant
//     (`CLA_MEOWL`, `PKI_CERT_CHUNK_MAX_LEN`, `SEED_MAX_LEN`, `HD_MAX_DEPTH`,
//     `RESET_REQUIRED_INVOCATIONS`, …) was mirrored in both modules by hand.
//     The mirror drift was tracked as audit findings AUDIT-013, AUDIT-014,
//     NEWAUDIT-011, NEWAUDIT-012.
//   * `shared` collapses the mirror: it is pure JC-agnostic Java, depended on
//     by all three modules. The applet picks it up via project compile-only
//     dependency so the constants get inlined into the CAP at convert time;
//     `tools` and `tests` consume it as a normal `implementation` dep.
//
// This module MUST NOT import any JavaCard API (`javacard.*`, `javacardx.*`).
// It MUST NOT pull in third-party runtime dependencies — the surface is
// deliberately a constants-only contract.

plugins {
    `java-library`
}

description = "meowl-applet — protocol constants shared across applet, tools, tests"

java {
    toolchain.languageVersion =
        JavaLanguageVersion.of(
            libs.versions.jdk
                .get()
                .toInt(),
        )
    // Java 8 bytecode so the JavaCard converter can ingest the resulting class
    // files when the applet pulls this module in via compileOnly.
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

tasks.withType<JavaCompile>().configureEach {
    options.compilerArgs.addAll(listOf("-Xlint:-options"))
    options.encoding = "UTF-8"
}
