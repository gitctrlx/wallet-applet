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
 * {@code meowl gp ...} — namespace for GlobalPlatform card-management subcommands.
 *
 * <p>This is a non-leaf command: invoking {@code meowl gp} alone prints the usage banner of the
 * {@code gp} subtree, matching how {@code git} or {@code kubectl} render their nested groups.
 */
@Command(
        name = "gp",
        mixinStandardHelpOptions = true,
        description = "GlobalPlatform card-management subcommands (list / install / uninstall).",
        synopsisSubcommandLabel = "COMMAND",
        subcommands = {
            CommandLine.HelpCommand.class,
            GpListCommand.class,
            GpInstallCommand.class,
            GpUninstallCommand.class,
        })
public final class GpCommand implements Callable<Integer> {

    @Spec public CommandLine.Model.CommandSpec spec;

    @Override
    public Integer call() {
        spec.commandLine().usage(System.out);
        return CommandLine.ExitCode.USAGE;
    }
}
