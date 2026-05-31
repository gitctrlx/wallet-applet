/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.cli;

import apdu4j.core.APDUBIBO;
import apdu4j.core.BIBOException;
import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Option;
import picocli.CommandLine.ParentCommand;
import social.meowl.tools.card.MeowlCard;
import social.meowl.tools.core.Hex;
import social.meowl.tools.core.MeowlInsn;
import social.meowl.tools.proto.SecureChannelClient;
import social.meowl.tools.transport.CardTransport;

/**
 * {@code meowl backup restore} — verifies the PIN over the Secure Channel and returns the stored
 * BIP-39 entropy as hex. The card recomputes and checks the seed integrity tag before releasing the
 * bytes; a wrong PIN counts toward the wipe-on-exhaustion limit.
 */
@Command(
        name = "restore",
        mixinStandardHelpOptions = true,
        description = "Verifies the PIN and prints the stored BIP-39 entropy (hex), over SC.")
public final class BackupRestoreCommand implements Callable<Integer> {

    @ParentCommand private BackupCommand parent;

    @Mixin public BackupAidOption aid = new BackupAidOption();

    @Option(
            names = {"-p", "--pin"},
            required = true,
            paramLabel = "PIN",
            description = "User PIN (a wrong PIN counts toward the wipe-on-exhaustion limit).")
    public String pin;

    @Override
    public Integer call() {
        MeowlCli root = (MeowlCli) parent.spec.commandLine().getParent().getCommand();
        byte[] aidBytes = aid.bytes();
        byte[] pinBytes = pin.getBytes(java.nio.charset.StandardCharsets.US_ASCII);

        byte[] entropy =
                CardTransport.run(
                        root.globalOptions.toReaderPreferences(),
                        bibo -> restore(bibo, aidBytes, pinBytes));

        if (root.globalOptions.json) {
            JsonOutput.writeMap(
                    System.out, "entropy", "0x" + Hex.encode(entropy), "seed_len", entropy.length);
        } else {
            System.out.printf("entropy = 0x%s (%d bytes)%n", Hex.encode(entropy), entropy.length);
        }
        return 0;
    }

    private byte[] restore(APDUBIBO bibo, byte[] aidBytes, byte[] pinBytes) throws BIBOException {
        SecureChannelClient sc = new MeowlCard(bibo, aidBytes).openSecureChannel();
        sc.sendInner(MeowlInsn.VERIFY_PIN.value(), 0, 0, pinBytes);
        return sc.sendInner(BackupCommand.INS_RESTORE_SEED, 0, 0, new byte[0]);
    }
}
