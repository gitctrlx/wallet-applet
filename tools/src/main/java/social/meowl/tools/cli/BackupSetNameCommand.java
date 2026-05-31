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
 * {@code meowl backup set-name} — sets the user-facing backup card label over the Secure Channel
 * (PIN-gated). Useful for distinguishing multiple backup cards.
 */
@Command(
        name = "set-name",
        mixinStandardHelpOptions = true,
        description = "Sets the backup card label (over SC, PIN-gated).")
public final class BackupSetNameCommand implements Callable<Integer> {

    private static final int NAME_MAX_LEN = 32;

    @ParentCommand private BackupCommand parent;

    @Mixin public BackupAidOption aid = new BackupAidOption();

    @Option(
            names = {"-p", "--pin"},
            required = true,
            paramLabel = "PIN",
            description = "User PIN.")
    public String pin;

    @Option(
            names = "--name",
            required = true,
            paramLabel = "LABEL",
            description = "Card label, UTF-8 (≤ 32 bytes).")
    public String name;

    @Override
    public Integer call() {
        MeowlCli root = (MeowlCli) parent.spec.commandLine().getParent().getCommand();
        byte[] aidBytes = aid.bytes();
        byte[] pinBytes = pin.getBytes(StandardCharsets.US_ASCII);
        byte[] nameBytes = name.getBytes(StandardCharsets.UTF_8);
        if (nameBytes.length > NAME_MAX_LEN) {
            throw new IllegalArgumentException(
                    "--name must be ≤ " + NAME_MAX_LEN + " UTF-8 bytes; got " + nameBytes.length);
        }

        CardTransport.run(
                root.globalOptions.toReaderPreferences(),
                bibo -> setName(bibo, aidBytes, pinBytes, nameBytes));

        if (!root.globalOptions.json) {
            System.out.printf("OK label set to \"%s\".%n", name);
        } else {
            JsonOutput.writeMap(System.out, "name", name);
        }
        return 0;
    }

    private Void setName(APDUBIBO bibo, byte[] aidBytes, byte[] pinBytes, byte[] nameBytes)
            throws BIBOException {
        SecureChannelClient sc = new MeowlCard(bibo, aidBytes).openSecureChannel();
        sc.sendInner(MeowlInsn.VERIFY_PIN.value(), 0, 0, pinBytes);
        sc.sendInner(BackupCommand.INS_SET_NAME, 0, 0, nameBytes);
        return null;
    }
}
