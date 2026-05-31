/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.cli;

import apdu4j.core.APDUBIBO;
import apdu4j.core.BIBOException;
import java.util.Arrays;
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
 * {@code meowl backup provision} — provisions a fresh backup card in one Secure Channel session:
 * sets the PIN, verifies it, then stores the supplied BIP-39 entropy. The card must be {@code
 * FRESH} (no PIN yet); re-provisioning requires a {@code factory-reset} first.
 */
@Command(
        name = "provision",
        mixinStandardHelpOptions = true,
        description = "Sets the PIN and stores BIP-39 entropy on a fresh backup card (over SC).")
public final class BackupProvisionCommand implements Callable<Integer> {

    @ParentCommand private BackupCommand parent;

    @Mixin public BackupAidOption aid = new BackupAidOption();

    @Option(
            names = {"-p", "--pin"},
            required = true,
            paramLabel = "PIN",
            description = "User PIN to install (4-8 ASCII bytes; no PUK — exhaustion wipes).")
    public String pin;

    @Option(
            names = "--entropy",
            required = true,
            paramLabel = "HEX",
            description = "BIP-39 entropy to back up, hex (16, 24 or 32 bytes).")
    public String entropyHex;

    @Override
    public Integer call() {
        MeowlCli root = (MeowlCli) parent.spec.commandLine().getParent().getCommand();
        byte[] aidBytes = aid.bytes();
        byte[] pinBytes = pin.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        byte[] entropy = Hex.decode(entropyHex);
        if (entropy.length != 16 && entropy.length != 24 && entropy.length != 32) {
            throw new IllegalArgumentException(
                    "--entropy must be 16, 24 or 32 bytes; got " + entropy.length);
        }

        CardTransport.run(
                root.globalOptions.toReaderPreferences(),
                bibo -> provision(bibo, aidBytes, pinBytes, entropy));

        if (!root.globalOptions.json) {
            System.out.printf("OK provisioned: PIN set, %d-byte seed stored.%n", entropy.length);
        } else {
            JsonOutput.writeMap(System.out, "provisioned", true, "seed_len", entropy.length);
        }
        return 0;
    }

    private Void provision(APDUBIBO bibo, byte[] aidBytes, byte[] pinBytes, byte[] entropy)
            throws BIBOException {
        SecureChannelClient sc = new MeowlCard(bibo, aidBytes).openSecureChannel();
        sc.sendInner(MeowlInsn.SETUP.value(), 0, 0, lengthPrefixed(pinBytes));
        sc.sendInner(MeowlInsn.VERIFY_PIN.value(), 0, 0, pinBytes);
        sc.sendInner(BackupCommand.INS_BACKUP_SEED, 0, 0, lengthPrefixed(entropy));
        Arrays.fill(entropy, (byte) 0);
        return null;
    }

    private static byte[] lengthPrefixed(byte[] data) {
        byte[] out = new byte[1 + data.length];
        out[0] = (byte) data.length;
        System.arraycopy(data, 0, out, 1, data.length);
        return out;
    }
}
