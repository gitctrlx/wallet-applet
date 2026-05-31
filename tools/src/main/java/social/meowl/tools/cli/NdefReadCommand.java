/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.cli;

import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.ParentCommand;
import social.meowl.tools.card.MeowlCard;
import social.meowl.tools.card.Type4Tag;
import social.meowl.tools.core.Hex;
import social.meowl.tools.core.MeowlAid;
import social.meowl.tools.core.Ndef;
import social.meowl.tools.transport.CardTransport;

/**
 * {@code meowl ndef read} — SELECTs the NDEF tag, reads its NDEF file and prints the decoded URI.
 *
 * <p>Defaults to the NFC Forum well-known instance AID {@code D2760000850101} the tag is installed
 * under; override with {@code --aid} for a card that uses a different instance AID.
 */
@Command(
        name = "read",
        mixinStandardHelpOptions = true,
        description = "Reads the NDEF tag and prints the stored URI (and raw NDEF bytes).")
public final class NdefReadCommand implements Callable<Integer> {

    @ParentCommand private NdefCommand parent;

    @Option(
            names = "--aid",
            paramLabel = "HEX",
            description = "NDEF applet instance AID to SELECT, hex (default: ${DEFAULT-VALUE}).",
            defaultValue = MeowlAid.NDEF_INSTANCE_HEX)
    public String aid = MeowlAid.NDEF_INSTANCE_HEX;

    @Override
    public Integer call() {
        MeowlCli root = (MeowlCli) parent.spec.commandLine().getParent().getCommand();
        byte[] aidBytes = MeowlAid.parse(aid);

        byte[] file =
                CardTransport.run(
                        root.globalOptions.toReaderPreferences(),
                        bibo -> {
                            MeowlCard card = new MeowlCard(bibo, aidBytes);
                            card.select();
                            return new Type4Tag(card).readNdef();
                        });

        String uri = tryDecode(file);
        if (root.globalOptions.json) {
            JsonOutput.writeMap(
                    System.out,
                    "aid",
                    "0x" + Hex.encode(aidBytes),
                    "ndef",
                    "0x" + Hex.encode(file),
                    "uri",
                    uri == null ? "" : uri);
        } else {
            System.out.printf("NDEF=0x%s%n", Hex.encode(file));
            System.out.println(uri == null ? "URI=(not a single URI record)" : "URI=" + uri);
        }
        return 0;
    }

    private static String tryDecode(byte[] file) {
        try {
            return Ndef.decodeUriFile(file);
        } catch (RuntimeException ignored) {
            return null;
        }
    }
}
