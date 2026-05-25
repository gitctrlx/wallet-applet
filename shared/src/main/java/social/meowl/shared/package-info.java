/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * Single source of truth for protocol constants shared between the applet, host CLI and integration
 * tests.
 *
 * <p>This package contains only compile-time constants and pure value types. It MUST NOT depend on
 * the JavaCard API, BouncyCastle, picocli, JUnit or any other runtime library — the goal is to have
 * one canonical contract that all three modules can pick up cheaply.
 *
 * <p>The applet ({@code :applet}) consumes this module via {@code compileOnly} so the JavaCard
 * converter inlines the {@code static final} fields into the CAP. Host modules ({@code :tools},
 * {@code :tests}) consume it via normal {@code implementation} so the same byte values flow through
 * the host SDK.
 */
package social.meowl.shared;
