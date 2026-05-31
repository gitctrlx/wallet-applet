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
import social.meowl.tools.core.MeowlSw;
import social.meowl.tools.transport.CardTransport;

/**
 * {@code meowl reset --confirm} — drives the {@code RESET_TO_FACTORY} countdown to completion,
 * wiping every secret on the card.
 *
 * <p>The applet requires {@code RESET_REQUIRED_INVOCATIONS} (= 4) consecutive un-interleaved {@code
 * RESET_TO_FACTORY} invocations before performing the wipe. Each step returns a counted-down status
 * word ({@code 6FA3 → 6FA2 → 6FA1 → 6FA0}); the final {@code 6FA0} signals that the wipe completed.
 *
 * <p>Because the operation is destructive and irreversible, it is gated behind {@code --confirm}.
 * Without it the command prints a refusal and exits non-zero so an operator who pastes the command
 * by mistake (or whose shell expanded a glob) does not lose key material.
 */
@Command(
        name = "reset",
        mixinStandardHelpOptions = true,
        description =
                "Wipes all secrets on the card by walking the RESET_TO_FACTORY countdown to"
                        + " completion. Requires --confirm.")
public final class ResetCommand implements Callable<Integer> {

    @ParentCommand private MeowlCli parent;

    @Mixin public AidOption aid = new AidOption();

    @Option(
            names = "--confirm",
            description =
                    "Required acknowledgement that the wipe is intentional. Without it this"
                            + " command refuses to run.")
    public boolean confirm = false;

    @Override
    public Integer call() {
        if (!confirm) {
            parent.spec
                    .commandLine()
                    .getErr()
                    .println(
                            "refusing to wipe: pass --confirm to acknowledge that all secrets on"
                                    + " the card will be irretrievably destroyed.");
            return 1;
        }

        int[] sequence =
                CardTransport.run(
                        parent.globalOptions.toReaderPreferences(),
                        bibo -> new MeowlCard(bibo, aid.bytes()).resetToFactory());

        if (parent.globalOptions.json) {
            JsonOutput.writeMap(
                    System.out,
                    "wiped",
                    true,
                    "step_status_words",
                    java.util.Arrays.stream(sequence).mapToObj("0x%04X"::formatted).toList());
        } else {
            for (int sw : sequence) {
                System.out.println("  " + MeowlSw.describe(sw));
            }
            System.out.println("OK (factory reset complete)");
        }
        return 0;
    }
}
