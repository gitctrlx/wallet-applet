/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.cli;

import java.nio.file.Path;
import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.ParentCommand;
import social.meowl.tools.gp.GpFacade;

/**
 * {@code meowl gp install <cap-file>} — installs (or replaces) a CAP file on the connected card.
 *
 * <p>By default authenticates with the GlobalPlatform development static keys ({@code 4040…4F}).
 * Pass {@code --key-master} or the {@code --key-enc / --key-mac / --key-kek} triple to use the
 * vendor-supplied or production-rotated ISD keys instead; see {@link GpKeysOption} for the full
 * surface.
 */
@Command(
        name = "install",
        mixinStandardHelpOptions = true,
        description =
                "Installs (or replaces) the given CAP file on the connected card. ISD keys default"
                        + " to the GP development static set; override with --key-master or"
                        + " --key-enc/--key-mac/--key-kek.")
public final class GpInstallCommand implements Callable<Integer> {

    @ParentCommand private GpCommand parent;

    @Mixin public GpKeysOption keys = new GpKeysOption();

    @Parameters(arity = "1", paramLabel = "CAP", description = "Path to the CAP file to install.")
    public Path capFile;

    @Override
    public Integer call() {
        MeowlCli root = (MeowlCli) parent.spec.commandLine().getParent().getCommand();
        GpFacade facade = new GpFacade(root.globalOptions.toReaderPreferences(), keys.toCardKeys());
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
