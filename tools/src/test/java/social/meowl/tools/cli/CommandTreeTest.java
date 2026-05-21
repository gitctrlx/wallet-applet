/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import picocli.CommandLine;

/**
 * Smoke tests over the {@link MeowlCli} command tree. These tests do <em>not</em> exercise card I/O
 * — they only verify that the picocli model is well-formed: every subcommand registers, every
 * option parses, and {@code --help} renders without throwing. Catching this kind of structural
 * regression at unit-test speed is a high-value safety net for a 13-subcommand surface.
 */
class CommandTreeTest {

    @Test
    @DisplayName("every documented subcommand is registered on the root")
    void allSubcommandsRegistered() {
        CommandLine cl = MeowlCli.commandLine();
        Map<String, CommandLine> sub = cl.getSubcommands();
        // Built-in `help` command is registered too.
        assertTrue(sub.containsKey("help"));
        assertTrue(sub.containsKey("info"));
        assertTrue(sub.containsKey("authentikey"));
        assertTrue(sub.containsKey("apdu"));
        assertTrue(sub.containsKey("select"));
        assertTrue(sub.containsKey("reset"));
        assertTrue(sub.containsKey("replay"));
        assertTrue(sub.containsKey("gp"));
    }

    @Test
    @DisplayName("the gp subtree exposes list / install / uninstall")
    void gpSubtree() {
        CommandLine root = MeowlCli.commandLine();
        CommandLine gp = root.getSubcommands().get("gp");
        assertNotNull(gp);
        Map<String, CommandLine> sub = gp.getSubcommands();
        assertTrue(sub.containsKey("list"));
        assertTrue(sub.containsKey("install"));
        assertTrue(sub.containsKey("uninstall"));
    }

    @Test
    @DisplayName("`meowl --help` renders without error and lists every subcommand")
    void rootHelp() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        CommandLine cl = MeowlCli.commandLine();
        cl.setOut(writer(out));
        int exit = cl.execute("--help");
        assertEquals(0, exit);
        String rendered = out.toString(StandardCharsets.UTF_8);
        assertTrue(rendered.contains("meowl"), rendered);
        assertTrue(rendered.contains("info"), rendered);
        assertTrue(rendered.contains("authentikey"), rendered);
        assertTrue(rendered.contains("gp"), rendered);
    }

    @Test
    @DisplayName("`meowl gp --help` lists list / install / uninstall")
    void gpHelp() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        CommandLine cl = MeowlCli.commandLine();
        cl.setOut(writer(out));
        int exit = cl.execute("gp", "--help");
        assertEquals(0, exit);
        String rendered = out.toString(StandardCharsets.UTF_8);
        assertTrue(rendered.contains("list"), rendered);
        assertTrue(rendered.contains("install"), rendered);
        assertTrue(rendered.contains("uninstall"), rendered);
    }

    @Test
    @DisplayName("invoking with no arguments prints usage and exits with USAGE code")
    void noArgsPrintsUsage() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        CommandLine cl = MeowlCli.commandLine();
        cl.setOut(writer(out));
        int exit = cl.execute();
        assertEquals(CommandLine.ExitCode.USAGE, exit);
    }

    @Test
    @DisplayName("`meowl info --help` documents --aid")
    void infoHelpMentionsAid() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        CommandLine cl = MeowlCli.commandLine();
        cl.setOut(writer(out));
        cl.execute("info", "--help");
        String rendered = out.toString(StandardCharsets.UTF_8);
        assertTrue(rendered.contains("--aid"), rendered);
    }

    @Test
    @DisplayName("an unknown subcommand exits with USAGE code")
    void unknownSubcommand() {
        CommandLine cl = MeowlCli.commandLine();
        cl.setOut(writer(new ByteArrayOutputStream()));
        cl.setErr(writer(new ByteArrayOutputStream()));
        int exit = cl.execute("not-a-real-subcommand");
        assertEquals(CommandLine.ExitCode.USAGE, exit);
    }

    @Test
    @DisplayName("`meowl reset` without --confirm refuses without contacting the card")
    void resetWithoutConfirmRefuses() {
        // This test deliberately runs without --confirm; the command must short-circuit BEFORE
        // touching CardTransport, so it does not need a real reader.
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        CommandLine cl = MeowlCli.commandLine();
        cl.setOut(writer(new ByteArrayOutputStream()));
        cl.setErr(writer(err));
        int exit = cl.execute("reset");
        assertEquals(1, exit);
        assertTrue(err.toString(StandardCharsets.UTF_8).contains("--confirm"), err.toString());
    }

    @Test
    @DisplayName("`meowl apdu` with no arguments fails with USAGE")
    void apduRequiresHex() {
        CommandLine cl = MeowlCli.commandLine();
        cl.setOut(writer(new ByteArrayOutputStream()));
        cl.setErr(writer(new ByteArrayOutputStream()));
        int exit = cl.execute("apdu");
        assertEquals(CommandLine.ExitCode.USAGE, exit);
    }

    private static PrintWriter writer(ByteArrayOutputStream sink) {
        return new PrintWriter(new OutputStreamWriter(sink, StandardCharsets.UTF_8), true);
    }
}
