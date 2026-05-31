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
import social.meowl.tools.card.MeowlCard;
import social.meowl.tools.transport.CardTransport;

/**
 * {@code meowl backup factory-reset} — wipes the backup card via the {@code RESET_TO_FACTORY}
 * countdown ({@value social.meowl.tools.card.MeowlCard#RESET_REQUIRED_INVOCATIONS} consecutive
 * invocations). No PIN is required by design, so a holder who forgot the PIN can still reclaim the
 * card; the seed, PIN and label are all destroyed. Requires {@code --confirm}.
 */
@Command(
        name = "factory-reset",
        mixinStandardHelpOptions = true,
        description =
                "Wipes the backup card (seed + PIN + label) via the RESET_TO_FACTORY countdown.")
public final class BackupFactoryResetCommand implements Callable<Integer> {

    @ParentCommand private BackupCommand parent;

    @Mixin public BackupAidOption aid = new BackupAidOption();

    @Option(
            names = "--confirm",
            description = "Required acknowledgement that this irreversibly wipes the card.")
    public boolean confirm;

    @Override
    public Integer call() {
        if (!confirm) {
            throw new IllegalArgumentException(
                    "factory-reset is destructive; re-run with --confirm to proceed");
        }
        MeowlCli root = (MeowlCli) parent.spec.commandLine().getParent().getCommand();
        byte[] aidBytes = aid.bytes();

        CardTransport.run(
                root.globalOptions.toReaderPreferences(),
                bibo -> new MeowlCard(bibo, aidBytes).resetToFactory());

        if (!root.globalOptions.json) {
            System.out.println("OK card wiped to factory state.");
        } else {
            JsonOutput.writeMap(System.out, "wiped", true);
        }
        return 0;
    }
}
