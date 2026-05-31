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
 * Root command for the {@code meowl} CLI. Owns the subcommand tree and the {@link GlobalOptions}
 * mixin every subcommand inherits.
 *
 * <p>Subcommands are explicitly enumerated for GraalVM native-image compatibility (no
 * service-loader scan at startup) and to surface command-name collisions at compile time.
 */
@Command(
        name = "meowl",
        mixinStandardHelpOptions = true,
        version = "meowl 0.1.0-SNAPSHOT",
        description =
                "Host-side CLI for the meowl-applet — APDU debugging, GlobalPlatform"
                        + " applet management, Secure Channel client and an interactive"
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
            BenchCommand.class,
            BootstrapCommand.class,
            GpCommand.class,
            ScCommand.class,
            NdefCommand.class,
            ShellCommand.class,
        })
public final class MeowlCli implements Callable<Integer> {

    @Mixin public GlobalOptions globalOptions = new GlobalOptions();

    @Spec public CommandLine.Model.CommandSpec spec;

    /** Default behaviour when invoked without a subcommand: print the usage banner. */
    @Override
    public Integer call() {
        spec.commandLine().usage(System.out);
        return CommandLine.ExitCode.USAGE;
    }

    /** Constructs a {@link CommandLine} configured with the meowl exit-code policy. */
    public static CommandLine commandLine() {
        return new CommandLine(new MeowlCli())
                .setExecutionExceptionHandler(MeowlExecutionExceptionHandler.INSTANCE);
    }
}
