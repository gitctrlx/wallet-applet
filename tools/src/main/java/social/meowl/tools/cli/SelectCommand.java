/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.cli;

import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.ParentCommand;
import social.meowl.tools.core.Hex;
import social.meowl.tools.transport.CardTransport;

/**
 * {@code meowl select [--aid HEX]} — issues a SELECT BY DF NAME for the applet AID and prints the
 * FCI bytes the card returned.
 *
 * <p>Useful as a smoke test (verifies a card is present, the applet is installed, the AID is
 * routable) without sending any meowl-specific INS.
 */
@Command(
        name = "select",
        mixinStandardHelpOptions = true,
        description = "SELECTs the meowl applet and prints the returned FCI bytes.")
public final class SelectCommand implements Callable<Integer> {

    @ParentCommand private MeowlCli parent;

    @Mixin public AidOption aid = new AidOption();

    @Override
    public Integer call() {
        byte[] fci =
                CardTransport.run(
                        parent.globalOptions.toReaderPreferences(),
                        bibo -> MeowlSession.select(bibo, aid.bytes()));

        if (parent.globalOptions.json) {
            JsonOutput.writeMap(
                    System.out,
                    "aid",
                    "0x" + Hex.encode(aid.bytes()),
                    "fci",
                    "0x" + Hex.encode(fci),
                    "fci_length",
                    fci.length);
        } else {
            if (fci.length == 0) {
                System.out.println("OK (empty FCI)");
            } else {
                System.out.printf("OK FCI=0x%s%n", Hex.encode(fci));
            }
        }
        return 0;
    }
}
