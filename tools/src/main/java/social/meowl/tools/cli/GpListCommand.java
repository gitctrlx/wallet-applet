/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.cli;

import java.util.List;
import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.ParentCommand;
import pro.javacard.gp.keys.PlaintextKeys;
import social.meowl.tools.gp.GpFacade;

/**
 * {@code meowl gp list} — opens a Secure Channel against the card manager (default ISD keys) and
 * prints every installed package, applet, and security domain.
 */
@Command(
        name = "list",
        mixinStandardHelpOptions = true,
        description = "Lists all installed packages, applets and security domains on the card.")
public final class GpListCommand implements Callable<Integer> {

    @ParentCommand private GpCommand parent;

    @Override
    public Integer call() {
        MeowlCli root = root();
        GpFacade facade =
                new GpFacade(root.globalOptions.toReaderPreferences(), PlaintextKeys.defaultKey());
        GpFacade.InventoryReport report = facade.list();

        if (root.globalOptions.json) {
            JsonOutput.writeMap(
                    System.out,
                    "applets",
                    report.applets(),
                    "packages",
                    report.packages(),
                    "domains",
                    report.domains());
        } else {
            renderSection("Applets", report.applets());
            renderSection("Packages", report.packages());
            renderSection("Domains", report.domains());
        }
        return 0;
    }

    private MeowlCli root() {
        return (MeowlCli) parent.spec.commandLine().getParent().getCommand();
    }

    private static void renderSection(String label, List<GpFacade.Entry> entries) {
        System.out.println(label + ":");
        if (entries.isEmpty()) {
            System.out.println("  (none)");
            return;
        }
        for (GpFacade.Entry e : entries) {
            System.out.printf("  %-20s %s%n", e.kind(), e.aid());
        }
    }
}
