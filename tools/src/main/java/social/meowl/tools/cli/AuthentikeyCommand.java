/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.cli;

import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.ParentCommand;
import social.meowl.tools.card.MeowlCard;
import social.meowl.tools.core.Hex;
import social.meowl.tools.transport.CardTransport;

/**
 * {@code meowl authentikey} — fetches the card's compressed authentikey public key.
 *
 * <p>The authentikey is generated once at install time and never rotates; it anchors device
 * identity for the Secure Channel handshake and PKI personalisation. Two consecutive invocations of
 * this command must therefore return identical bytes.
 */
@Command(
        name = "authentikey",
        mixinStandardHelpOptions = true,
        description = "Returns the card's 33-byte compressed authentikey public key.")
public final class AuthentikeyCommand implements Callable<Integer> {

    @ParentCommand private MeowlCli parent;

    @Mixin public AidOption aid = new AidOption();

    @Override
    public Integer call() {
        byte[] pubkey =
                CardTransport.run(
                        parent.globalOptions.toReaderPreferences(),
                        bibo -> new MeowlCard(bibo, aid.bytes()).getAuthentikey());

        if (parent.globalOptions.json) {
            JsonOutput.writeMap(
                    System.out, "authentikey", "0x" + Hex.encode(pubkey), "length", pubkey.length);
        } else {
            System.out.println("0x" + Hex.encode(pubkey));
        }
        return 0;
    }
}
