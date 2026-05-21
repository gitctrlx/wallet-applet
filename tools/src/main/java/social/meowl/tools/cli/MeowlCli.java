/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.cli;

import java.util.concurrent.Callable;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.HelpCommand;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Spec;

/**
 * Root command for the {@code meowl} CLI.
 *
 * <p>Owns the subcommand tree and the {@link GlobalOptions} mixin that every subcommand inherits.
 * Calling {@code meowl} without a subcommand prints the usage banner and exits with the picocli
 * "missing command" exit code, matching POSIX conventions.
 *
 * <p>Subcommands are explicitly enumerated rather than auto-discovered: explicit registration is
 * GraalVM-native-image-friendly (no service-loader scan at startup) and surfaces command name
 * collisions at compile time rather than at first invocation.
 */
@Command(
        name = "meowl",
        mixinStandardHelpOptions = true,
        version = "meowl 0.1.0-SNAPSHOT",
        description =
                "Host-side CLI for the meowl-applet — APDU debugging, GlobalPlatform"
                        + " applet management, MEAP-2 Secure Channel client and an interactive"
                        + " shell.",
        synopsisSubcommandLabel = "COMMAND",
        subcommands = {
            HelpCommand.class,
            InfoCommand.class,
            AuthentikeyCommand.class,
            ApduCommand.class,
            SelectCommand.class,
            ResetCommand.class,
            ReplayCommand.class,
            GpCommand.class,
            ScCommand.class,
            ShellCommand.class,
        })
public final class MeowlCli implements Callable<Integer> {

    @Mixin public GlobalOptions globalOptions = new GlobalOptions();

    @Spec public CommandLine.Model.CommandSpec spec;

    /**
     * Default behaviour when invoked without a subcommand: print the usage banner so users learn
     * the available verbs without having to type {@code meowl --help}.
     */
    @Override
    public Integer call() {
        spec.commandLine().usage(System.out);
        return CommandLine.ExitCode.USAGE;
    }

    /** Constructs a {@link CommandLine} configured with the meowl exit-code policy. */
    public static CommandLine commandLine() {
        return new CommandLine(new MeowlCli())
                .setCaseInsensitiveEnumValuesAllowed(true)
                .setExecutionExceptionHandler(MeowlExecutionExceptionHandler.INSTANCE);
    }
}
