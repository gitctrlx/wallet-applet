/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.cli;

import apdu4j.core.APDUBIBO;
import apdu4j.core.BIBOException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Option;
import picocli.CommandLine.ParentCommand;
import social.meowl.tools.card.MeowlCard;
import social.meowl.tools.core.MeowlInsn;
import social.meowl.tools.proto.SecureChannelClient;
import social.meowl.tools.transport.CardTransport;

/**
 * {@code meowl backup change-pin} — rotates the backup PIN over the Secure Channel. A wrong old PIN
 * counts toward the wipe-on-exhaustion limit; a correct one consumes no try.
 */
@Command(
        name = "change-pin",
        mixinStandardHelpOptions = true,
        description = "Rotates the backup card PIN (over SC).")
public final class BackupChangePinCommand implements Callable<Integer> {

    @ParentCommand private BackupCommand parent;

    @Mixin public BackupAidOption aid = new BackupAidOption();

    @Option(
            names = {"-p", "--pin"},
            required = true,
            paramLabel = "OLD",
            description = "Current PIN.")
    public String oldPin;

    @Option(
            names = "--new-pin",
            required = true,
            paramLabel = "NEW",
            description = "New PIN to install (4-8 ASCII bytes).")
    public String newPin;

    @Override
    public Integer call() {
        MeowlCli root = (MeowlCli) parent.spec.commandLine().getParent().getCommand();
        byte[] aidBytes = aid.bytes();
        byte[] oldBytes = oldPin.getBytes(StandardCharsets.US_ASCII);
        byte[] newBytes = newPin.getBytes(StandardCharsets.US_ASCII);

        CardTransport.run(
                root.globalOptions.toReaderPreferences(),
                bibo -> changePin(bibo, aidBytes, oldBytes, newBytes));

        if (!root.globalOptions.json) {
            System.out.println("OK PIN rotated.");
        } else {
            JsonOutput.writeMap(System.out, "changed", true);
        }
        return 0;
    }

    private Void changePin(APDUBIBO bibo, byte[] aidBytes, byte[] oldBytes, byte[] newBytes)
            throws BIBOException {
        SecureChannelClient sc = new MeowlCard(bibo, aidBytes).openSecureChannel();
        sc.sendInner(MeowlInsn.CHANGE_PIN.value(), 0, 0, pair(oldBytes, newBytes));
        return null;
    }

    private static byte[] pair(byte[] first, byte[] second) {
        byte[] out = new byte[1 + first.length + 1 + second.length];
        out[0] = (byte) first.length;
        System.arraycopy(first, 0, out, 1, first.length);
        out[1 + first.length] = (byte) second.length;
        System.arraycopy(second, 0, out, 2 + first.length, second.length);
        return out;
    }
}
