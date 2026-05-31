/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.cli;

import java.util.concurrent.Callable;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Spec;

/**
 * {@code meowl sc ...} — namespace for Secure Channel subcommands.
 *
 * <p>Two leaves are exposed:
 *
 * <ul>
 *   <li>{@code sc handshake} — run {@code INIT_SECURE_CHANNEL} alone, verify the authentikey
 *       signature, and print the derived state. Useful for protocol diagnostics.
 *   <li>{@code sc send <hex>} — run a complete handshake-and-envelope round-trip: open the Secure
 *       Channel and send the supplied inner APDU through it. The card's response is decrypted and
 *       printed. This is the primary way to invoke any inner-band INS from the CLI.
 * </ul>
 *
 * <p>Both commands open a fresh PC/SC connection per invocation; the card deselects on close, so a
 * session created by {@code sc handshake} cannot survive into the next CLI call. The shell REPL
 * (Phase 4) will keep the connection alive across commands and is the right tool when a persistent
 * session is required.
 */
@Command(
        name = "sc",
        mixinStandardHelpOptions = true,
        description = "Secure Channel subcommands (handshake / send).",
        synopsisSubcommandLabel = "COMMAND",
        subcommands = {
            CommandLine.HelpCommand.class,
            ScHandshakeCommand.class,
            ScSendCommand.class,
        })
public final class ScCommand implements Callable<Integer> {

    @Spec public CommandLine.Model.CommandSpec spec;

    @Override
    public Integer call() {
        spec.commandLine().usage(System.out);
        return CommandLine.ExitCode.USAGE;
    }

    /**
     * The root {@link MeowlCli}, so leaf subcommands can reach the shared {@link GlobalOptions}.
     */
    MeowlCli root() {
        return (MeowlCli) spec.commandLine().getParent().getCommand();
    }
}
