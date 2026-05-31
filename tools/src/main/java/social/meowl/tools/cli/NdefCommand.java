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
 * {@code meowl ndef ...} — namespace for reading and writing the meowl NDEF Type 4 tag.
 *
 * <p>This is a non-leaf command: invoking {@code meowl ndef} alone prints the usage banner of the
 * {@code ndef} subtree. The tag is openly readable and writable, so these commands need no keys or
 * Secure Channel — handy for provisioning a card's profile link or inspecting what it serves.
 */
@Command(
        name = "ndef",
        mixinStandardHelpOptions = true,
        description = "NFC Forum Type 4 tag subcommands (read / write-uri).",
        synopsisSubcommandLabel = "COMMAND",
        subcommands = {
            CommandLine.HelpCommand.class,
            NdefReadCommand.class,
            NdefWriteCommand.class,
        })
public final class NdefCommand implements Callable<Integer> {

    @Spec public CommandLine.Model.CommandSpec spec;

    @Override
    public Integer call() {
        spec.commandLine().usage(System.out);
        return CommandLine.ExitCode.USAGE;
    }
}
