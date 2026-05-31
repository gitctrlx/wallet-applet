/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.cli;

import java.util.Arrays;
import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.ParentCommand;
import social.meowl.tools.card.MeowlCard;
import social.meowl.tools.card.Type4Tag;
import social.meowl.tools.core.Hex;
import social.meowl.tools.core.MeowlAid;
import social.meowl.tools.core.Ndef;
import social.meowl.tools.transport.CardTransport;

/**
 * {@code meowl ndef write-uri <uri>} — writes a single URI record to the NDEF tag and verifies it.
 *
 * <p>Encodes the URI as a short NDEF URI record (applying the abbreviation prefix, e.g. {@code
 * "https://"}), writes it with the NFC Forum procedure, then reads it back and fails if the bytes
 * differ. The tag is openly writable, so no keys or Secure Channel are involved.
 */
@Command(
        name = "write-uri",
        mixinStandardHelpOptions = true,
        description = "Writes a URI record to the NDEF tag and reads it back to verify.")
public final class NdefWriteCommand implements Callable<Integer> {

    @ParentCommand private NdefCommand parent;

    @Option(
            names = "--aid",
            paramLabel = "HEX",
            description = "NDEF applet instance AID to SELECT, hex (default: ${DEFAULT-VALUE}).",
            defaultValue = MeowlAid.NDEF_INSTANCE_HEX)
    public String aid = MeowlAid.NDEF_INSTANCE_HEX;

    @Parameters(
            arity = "1",
            paramLabel = "URI",
            description = "URI to write, e.g. \"https://meowl.social/p/<nprofile>\".")
    public String uri;

    @Override
    public Integer call() {
        MeowlCli root = (MeowlCli) parent.spec.commandLine().getParent().getCommand();
        byte[] aidBytes = MeowlAid.parse(aid);
        byte[] file = Ndef.encodeUriFile(uri);

        byte[] readBack =
                CardTransport.run(
                        root.globalOptions.toReaderPreferences(),
                        bibo -> {
                            MeowlCard card = new MeowlCard(bibo, aidBytes);
                            card.select();
                            Type4Tag tag = new Type4Tag(card);
                            tag.writeNdef(file);
                            return tag.readNdef();
                        });

        if (!Arrays.equals(file, readBack)) {
            throw new IllegalStateException(
                    "read-back mismatch: wrote 0x%s, read 0x%s"
                            .formatted(Hex.encode(file), Hex.encode(readBack)));
        }

        if (root.globalOptions.json) {
            JsonOutput.writeMap(
                    System.out,
                    "aid",
                    "0x" + Hex.encode(aidBytes),
                    "uri",
                    uri,
                    "ndef",
                    "0x" + Hex.encode(file));
        } else {
            System.out.printf("OK wrote URI=%s (%d bytes)%n", uri, file.length);
        }
        return 0;
    }
}
