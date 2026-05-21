/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.cli;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import picocli.CommandLine;

/** Lightweight tests for the picocli wiring of {@link ShellCommand}. */
class ShellCommandTest {

    @Test
    @DisplayName("`shell` is registered on the root command")
    void registered() {
        CommandLine root = MeowlCli.commandLine();
        CommandLine shell = root.getSubcommands().get("shell");
        assertNotNull(shell);
    }

    @Test
    @DisplayName("verbs() lists every documented top-level command")
    void verbsListed() {
        List<String> verbs = ShellCommand.verbs();
        for (String expected :
                new String[] {
                    "select", "info", "authentikey", "apdu", "sc", "reset", "help", "exit", "quit"
                }) {
            assertTrue(verbs.contains(expected), "missing verb: " + expected);
        }
    }
}
