/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.cli;

import java.nio.file.Path;
import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.ParentCommand;
import pro.javacard.gp.keys.PlaintextKeys;
import social.meowl.tools.gp.GpFacade;

/**
 * {@code meowl gp install <cap-file>} — installs (or replaces) a CAP file on the connected card.
 *
 * <p>Authenticates with the GlobalPlatform default test keys ({@code 4040…4F}). Production
 * deployments should rotate to per-card keys; the CLI does not yet expose a key flag, but the
 * underlying {@link GpFacade} is parameterised on {@link pro.javacard.gp.GPCardKeys} so the option
 * can be added without rewriting the install pipeline.
 */
@Command(
        name = "install",
        mixinStandardHelpOptions = true,
        description =
                "Installs (or replaces) the given CAP file on the connected card using the"
                        + " GlobalPlatform default test keys.")
public final class GpInstallCommand implements Callable<Integer> {

    @ParentCommand private GpCommand parent;

    @Parameters(arity = "1", paramLabel = "CAP", description = "Path to the CAP file to install.")
    public Path capFile;

    @Override
    public Integer call() {
        MeowlCli root = (MeowlCli) parent.spec.commandLine().getParent().getCommand();
        GpFacade facade =
                new GpFacade(root.globalOptions.toReaderPreferences(), PlaintextKeys.defaultKey());
        GpFacade.InstallResult result = facade.install(capFile);

        if (root.globalOptions.json) {
            JsonOutput.writeMap(
                    System.out,
                    "package_aid",
                    result.packageAid().toString(),
                    "class_aid",
                    result.classAid().toString(),
                    "instance_aid",
                    result.instanceAid().toString());
        } else {
            System.out.printf("OK installed %s%n", result.instanceAid());
        }
        return 0;
    }
}
