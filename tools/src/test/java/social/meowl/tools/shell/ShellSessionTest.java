/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.shell;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import apdu4j.core.APDUBIBO;
import apdu4j.core.MockBIBO;
import java.io.ByteArrayOutputStream;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Tests for the {@link ShellSession} engine — exercises the line-dispatcher logic without involving
 * JLine. The full JLine REPL is verified at the integration level (manual smoke test during
 * release; automated coverage is left to a future pty-driven test).
 */
class ShellSessionTest {

    @Test
    @DisplayName("prompt reflects the current state (disconnected → selected → sc)")
    void promptReflectsState() throws Exception {
        // Card answers SELECT (00A4040007F06D656F776C01) with 9000.
        MockBIBO mock = MockBIBO.with("00A4040007F06D656F776C01", "9000");
        ShellSession session = newSession(mock);

        assertEquals("meowl[disconnected]> ", session.prompt());
        session.execute("select");
        assertEquals("meowl> ", session.prompt());
    }

    @Test
    @DisplayName("`info` prints every TLV tag from the GET_INFO blob")
    void infoCommand() throws Exception {
        // TLV: 01 02 0100 (proto v1.0) | 02 02 0001 (applet v0.1)
        //    | 03 01 00 (lifecycle UNINITIALIZED) | 04 02 0080 (caps bit 7)
        //    | 05 03 33DEAD (synthetic short pubkey for test rendering)
        // followed by SW 9000.
        MockBIBO mock =
                MockBIBO.with("00A4040007F06D656F776C01", "9000")
                        .then("80010000", "010201000202000103010104020080050333DEAD9000");

        ByteArrayOutputStream sink = new ByteArrayOutputStream();
        ShellSession session = newSession(mock, sink);
        session.execute("select");
        session.execute("info");

        String rendered = sink.toString(StandardCharsets.UTF_8);
        assertTrue(rendered.contains("tag 0x01"), rendered);
        assertTrue(rendered.contains("tag 0x05"), rendered);
        assertTrue(rendered.contains("33DEAD"), rendered);
    }

    @Test
    @DisplayName("`authentikey` prints the GET_AUTHENTIKEY response")
    void authentikeyCommand() throws Exception {
        // 33-byte authentikey response: 0x02 followed by 32 × 0x11, plus SW 9000.
        StringBuilder ak = new StringBuilder("02");
        for (int i = 0; i < 32; i++) ak.append("11");
        ak.append("9000");
        MockBIBO mock =
                MockBIBO.with("00A4040007F06D656F776C01", "9000").then("80020000", ak.toString());

        ByteArrayOutputStream sink = new ByteArrayOutputStream();
        ShellSession session = newSession(mock, sink);
        session.execute("select");
        session.execute("authentikey");

        String text = sink.toString(StandardCharsets.UTF_8);
        assertTrue(text.contains("0x021111"), text);
    }

    @Test
    @DisplayName("`apdu` echoes the response data and SW description")
    void apduCommand() throws Exception {
        MockBIBO mock =
                MockBIBO.with("00A4040007F06D656F776C01", "9000").then("80AB0000", "DEADBEEF9000");

        ByteArrayOutputStream sink = new ByteArrayOutputStream();
        ShellSession session = newSession(mock, sink);
        session.execute("select");
        session.execute("apdu 80AB0000");

        String text = sink.toString(StandardCharsets.UTF_8);
        assertTrue(text.contains("DEADBEEF"), text);
        assertTrue(text.contains("SW=9000"), text);
        assertTrue(text.contains("Success"), text);
    }

    @Test
    @DisplayName("unknown commands report a friendly error to stderr")
    void unknownCommand() throws Exception {
        MockBIBO mock = MockBIBO.with("00A4040007F06D656F776C01", "9000");
        ByteArrayOutputStream stdout = new ByteArrayOutputStream();
        ByteArrayOutputStream stderr = new ByteArrayOutputStream();

        APDUBIBO bibo = new APDUBIBO(mock);
        ShellSession session =
                new ShellSession(
                        bibo,
                        new PrintWriter(stdout, true, StandardCharsets.UTF_8),
                        new PrintWriter(stderr, true, StandardCharsets.UTF_8));
        session.execute("not-a-real-command");
        assertTrue(stderr.toString(StandardCharsets.UTF_8).contains("unknown command"));
    }

    @Test
    @DisplayName("blank input is a no-op (does not even SELECT)")
    void blankIsNoOp() throws Exception {
        MockBIBO mock = MockBIBO.with("80FFFFFF", "6F009000"); // unrelated APDU; should not be hit
        ByteArrayOutputStream sink = new ByteArrayOutputStream();
        ShellSession session = newSession(mock, sink);
        session.execute("");
        session.execute("   ");
        assertEquals(0, sink.size());
    }

    @Test
    @DisplayName("`sc send` without prior `sc handshake` reports a friendly error")
    void scSendWithoutHandshake() throws Exception {
        MockBIBO mock = MockBIBO.with("00A4040007F06D656F776C01", "9000");
        ByteArrayOutputStream stdout = new ByteArrayOutputStream();
        ByteArrayOutputStream stderr = new ByteArrayOutputStream();

        APDUBIBO bibo = new APDUBIBO(mock);
        ShellSession session =
                new ShellSession(
                        bibo,
                        new PrintWriter(stdout, true, StandardCharsets.UTF_8),
                        new PrintWriter(stderr, true, StandardCharsets.UTF_8));
        session.execute("select");
        session.execute("sc send 80300000");

        assertTrue(stderr.toString(StandardCharsets.UTF_8).contains("no Secure Channel"));
        assertFalse(stdout.toString(StandardCharsets.UTF_8).contains("<--"));
    }

    @Test
    @DisplayName("`reset` refuses non-countdown status words")
    void resetRefusesNonCountdownStatusWords() {
        MockBIBO mock = MockBIBO.with("00A4040007F06D656F776C01", "9000").then("80030000", "6D00");
        ByteArrayOutputStream sink = new ByteArrayOutputStream();
        ShellSession session = newSession(mock, sink);

        ShellSession.ShellException ex =
                assertThrows(ShellSession.ShellException.class, () -> session.execute("reset"));

        assertTrue(ex.getMessage().contains("RESET_TO_FACTORY step 1"), ex.getMessage());
        assertFalse(sink.toString(StandardCharsets.UTF_8).contains("factory reset complete"));
    }

    @Test
    @DisplayName("`reset` requires the final countdown status to be 6FA0")
    void resetRequiresFinalCountdownZero() {
        MockBIBO mock =
                MockBIBO.with("00A4040007F06D656F776C01", "9000")
                        .then("80030000", "6FA3")
                        .then("80030000", "6FA2")
                        .then("80030000", "6FA1")
                        .then("80030000", "6FA1");
        ByteArrayOutputStream sink = new ByteArrayOutputStream();
        ShellSession session = newSession(mock, sink);

        ShellSession.ShellException ex =
                assertThrows(ShellSession.ShellException.class, () -> session.execute("reset"));

        assertTrue(ex.getMessage().contains("did not complete"), ex.getMessage());
        assertFalse(sink.toString(StandardCharsets.UTF_8).contains("factory reset complete"));
    }

    @Test
    @DisplayName("`help` lists every documented command")
    void helpListsCommands() throws Exception {
        MockBIBO mock = MockBIBO.of();
        ByteArrayOutputStream sink = new ByteArrayOutputStream();
        ShellSession session = newSession(mock, sink);
        session.execute("help");
        String text = sink.toString(StandardCharsets.UTF_8);
        for (String verb :
                new String[] {
                    "select",
                    "info",
                    "authentikey",
                    "apdu",
                    "sc handshake",
                    "sc send",
                    "reset",
                    "exit",
                }) {
            assertTrue(text.contains(verb), "help should mention '" + verb + "', got: " + text);
        }
    }

    @Test
    @DisplayName("`exit` and `quit` are silently swallowed by execute() — main loop terminates")
    void exitNotDispatched() throws Exception {
        MockBIBO mock = MockBIBO.of();
        ByteArrayOutputStream stdout = new ByteArrayOutputStream();
        ByteArrayOutputStream stderr = new ByteArrayOutputStream();
        APDUBIBO bibo = new APDUBIBO(mock);
        ShellSession session =
                new ShellSession(
                        bibo,
                        new PrintWriter(stdout, true, StandardCharsets.UTF_8),
                        new PrintWriter(stderr, true, StandardCharsets.UTF_8));
        session.execute("exit");
        session.execute("quit");
        // Neither produces output; the JLine main loop is responsible for breaking the read loop.
        assertEquals(0, stdout.size());
        assertEquals(0, stderr.size());
    }

    private static ShellSession newSession(MockBIBO mock) {
        return newSession(mock, new ByteArrayOutputStream());
    }

    private static ShellSession newSession(MockBIBO mock, ByteArrayOutputStream sink) {
        APDUBIBO bibo = new APDUBIBO(mock);
        PrintWriter writer = new PrintWriter(sink, true, StandardCharsets.UTF_8);
        return new ShellSession(bibo, writer, writer);
    }
}
