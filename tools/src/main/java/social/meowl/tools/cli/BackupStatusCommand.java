/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.cli;

import apdu4j.core.CommandAPDU;
import apdu4j.core.ResponseAPDU;
import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.ParentCommand;
import social.meowl.tools.card.MeowlCard;
import social.meowl.tools.core.Hex;
import social.meowl.tools.core.MeowlInsn;
import social.meowl.tools.core.MeowlSw;
import social.meowl.tools.core.ProtocolException;
import social.meowl.tools.transport.CardTransport;

/**
 * {@code meowl backup status} — SELECTs the backup applet and prints its {@code GET_INFO} status:
 * lifecycle, seed presence and length, remaining PIN tries, card label and authentikey. No Secure
 * Channel or PIN is required (the status surface is public).
 */
@Command(
        name = "status",
        mixinStandardHelpOptions = true,
        description = "Prints the backup card status (lifecycle, seed presence, PIN tries, label).")
public final class BackupStatusCommand implements Callable<Integer> {

    private static final byte TAG_LIFECYCLE = (byte) 0x03;
    private static final byte TAG_SEED_PRESENT = (byte) 0x06;
    private static final byte TAG_PIN_TRIES = (byte) 0x07;
    private static final byte TAG_CARD_NAME = (byte) 0x08;
    private static final byte TAG_SEED_LEN = (byte) 0x09;
    private static final byte TAG_AUTHENTIKEY = (byte) 0x05;

    @ParentCommand private BackupCommand parent;

    @Mixin public BackupAidOption aid = new BackupAidOption();

    @Override
    public Integer call() {
        MeowlCli root = (MeowlCli) parent.spec.commandLine().getParent().getCommand();
        byte[] aidBytes = aid.bytes();

        byte[] tlv =
                CardTransport.run(
                        root.globalOptions.toReaderPreferences(),
                        bibo -> {
                            MeowlCard card = new MeowlCard(bibo, aidBytes);
                            card.select();
                            ResponseAPDU resp =
                                    card.transmit(
                                            new CommandAPDU(
                                                    MeowlInsn.CLA_MEOWL & 0xFF,
                                                    MeowlInsn.GET_INFO.value() & 0xFF,
                                                    0,
                                                    0));
                            if (!MeowlSw.isSuccess(resp.getSW())) {
                                throw new ProtocolException(resp.getSW(), "GET_INFO failed");
                            }
                            return resp.getData();
                        });

        byte[] lifecycle = tlvValue(tlv, TAG_LIFECYCLE);
        byte[] seedPresent = tlvValue(tlv, TAG_SEED_PRESENT);
        byte[] seedLen = tlvValue(tlv, TAG_SEED_LEN);
        byte[] pinTries = tlvValue(tlv, TAG_PIN_TRIES);
        byte[] name = tlvValue(tlv, TAG_CARD_NAME);
        byte[] authentikey = tlvValue(tlv, TAG_AUTHENTIKEY);

        if (root.globalOptions.json) {
            JsonOutput.writeMap(
                    System.out,
                    "lifecycle",
                    byteOrNull(lifecycle),
                    "seed_present",
                    seedPresent != null && seedPresent.length == 1 && seedPresent[0] != 0,
                    "seed_len",
                    byteOrNull(seedLen),
                    "pin_tries",
                    byteOrNull(pinTries),
                    "name",
                    name == null ? "" : new String(name, java.nio.charset.StandardCharsets.UTF_8),
                    "authentikey",
                    authentikey == null ? "" : "0x" + Hex.encode(authentikey));
        } else {
            System.out.printf("lifecycle   = %s%n", lifecycleName(byteOrNull(lifecycle)));
            System.out.printf(
                    "seed        = %s%n",
                    seedPresent != null && seedPresent.length == 1 && seedPresent[0] != 0
                            ? "present (" + byteOrNull(seedLen) + " bytes)"
                            : "empty");
            System.out.printf("pin_tries   = %s%n", byteOrNull(pinTries));
            System.out.printf(
                    "name        = %s%n",
                    name == null || name.length == 0
                            ? "(unset)"
                            : new String(name, java.nio.charset.StandardCharsets.UTF_8));
            if (authentikey != null) {
                System.out.printf("authentikey = 0x%s%n", Hex.encode(authentikey));
            }
        }
        return 0;
    }

    private static String lifecycleName(Integer state) {
        if (state == null) {
            return "unknown";
        }
        switch (state) {
            case 0:
                return "FRESH (0)";
            case 1:
                return "PIN_SET (1)";
            case 2:
                return "SEEDED (2)";
            default:
                return state.toString();
        }
    }

    private static Integer byteOrNull(byte[] v) {
        return v != null && v.length == 1 ? (v[0] & 0xFF) : null;
    }

    /** Returns the value bytes of the first TLV with {@code tag}, or {@code null} if absent. */
    private static byte[] tlvValue(byte[] data, byte tag) {
        int i = 0;
        while (i + 1 < data.length) {
            int t = data[i++] & 0xFF;
            int len = data[i++] & 0xFF;
            if (i + len > data.length) {
                break;
            }
            if (t == (tag & 0xFF)) {
                byte[] out = new byte[len];
                System.arraycopy(data, i, out, 0, len);
                return out;
            }
            i += len;
        }
        return null;
    }
}
