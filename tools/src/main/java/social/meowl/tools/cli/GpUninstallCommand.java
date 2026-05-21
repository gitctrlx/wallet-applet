/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.cli;

import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Option;
import picocli.CommandLine.ParentCommand;
import pro.javacard.gp.keys.PlaintextKeys;
import social.meowl.tools.gp.GpFacade;

/**
 * {@code meowl gp uninstall [--aid HEX] [--no-deps]} — removes an applet (and, by default, its
 * containing package) from the card.
 */
@Command(
        name = "uninstall",
        mixinStandardHelpOptions = true,
        description =
                "Removes the meowl applet (and its package, by default) from the connected card.")
public final class GpUninstallCommand implements Callable<Integer> {

    @ParentCommand private GpCommand parent;

    @Mixin public AidOption aid = new AidOption();

    @Option(
            names = "--no-deps",
            description = "Delete only the AID itself, not its dependent package or instances.")
    public boolean noDeps = false;

    @Override
    public Integer call() {
        MeowlCli root = (MeowlCli) parent.spec.commandLine().getParent().getCommand();
        GpFacade facade =
                new GpFacade(root.globalOptions.toReaderPreferences(), PlaintextKeys.defaultKey());
        facade.uninstall(aid.bytes(), !noDeps);

        if (root.globalOptions.json) {
            JsonOutput.writeMap(
                    System.out, "deleted", true, "aid", aid.aid, "delete_dependencies", !noDeps);
        } else {
            System.out.printf("OK deleted %s%n", aid.aid);
        }
        return 0;
    }
}
