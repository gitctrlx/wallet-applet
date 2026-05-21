/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.transport;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Tests for {@link ReaderPreferences} resolution and validation. */
class ReaderPreferencesTest {

    @Test
    @DisplayName("defaults() produces an unconstrained T=1 configuration")
    void defaults() {
        ReaderPreferences prefs = ReaderPreferences.defaults();
        assertEquals("", prefs.readerName());
        assertEquals("", prefs.readerIgnore());
        assertEquals("T=1", prefs.protocol());
        assertEquals(Optional.empty(), prefs.dumpFile());
        assertFalse(prefs.trace());
        assertFalse(prefs.requireExclusive());
        assertFalse(prefs.hasReaderConstraint());
        assertFalse(prefs.hasIgnoreFilter());
    }

    @Test
    @DisplayName("CLI inputs take precedence over the environment fallback")
    void cliOverEnv() {
        // Note: we cannot mutate System.getenv() within the JVM, so we exercise the CLI-supplied
        // path by passing explicit non-empty values; the env-fallback path is exercised by
        // forcing both CLI inputs to empty in `envFallback`.
        ReaderPreferences prefs =
                ReaderPreferences.fromEnvironment(
                        "ACR1252",
                        "VirtualSC",
                        Optional.of("T=0"),
                        Optional.of(Path.of("session.dump")),
                        Optional.of(true),
                        Optional.of(true));

        assertEquals("ACR1252", prefs.readerName());
        assertEquals("VirtualSC", prefs.readerIgnore());
        assertEquals("T=0", prefs.protocol());
        assertEquals(Path.of("session.dump"), prefs.dumpFile().orElseThrow());
        assertTrue(prefs.trace());
        assertTrue(prefs.requireExclusive());
        assertTrue(prefs.hasReaderConstraint());
        assertTrue(prefs.hasIgnoreFilter());
    }

    @Test
    @DisplayName("blank CLI inputs fall back to an empty (no-constraint) state")
    void envFallbackWhenCliBlank() {
        ReaderPreferences prefs =
                ReaderPreferences.fromEnvironment(
                        "",
                        " ",
                        Optional.empty(),
                        Optional.empty(),
                        Optional.empty(),
                        Optional.empty());

        // No environment is asserted here (CI environments differ); we only verify that the
        // fallback path does not crash and yields a coherent state.
        assertEquals(Optional.empty(), prefs.dumpFile());
        assertFalse(prefs.trace());
        assertFalse(prefs.requireExclusive());
        assertEquals("T=1", prefs.protocol());
    }

    @Test
    @DisplayName("blank protocol is rejected at construction time")
    void blankProtocolRejected() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new ReaderPreferences("", "", "", Optional.empty(), false, false));
        assertThrows(
                IllegalArgumentException.class,
                () -> new ReaderPreferences("", "", "   ", Optional.empty(), false, false));
    }
}
