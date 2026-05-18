/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools;

import apdu4j.core.CommandAPDU;
import apdu4j.core.ResponseAPDU;
import apdu4j.pcsc.Readers;

/**
 * Minimal command-line tool that talks to a connected JavaCard via apdu4j's modern Readers/BIBO API
 * (apdu4j-pcsc 26+).
 *
 * <p>Usage: {@code meowl <hex-apdu>} where the APDU is the full command APDU encoded as
 * hexadecimal, e.g. {@code 80010000}.
 */
public final class Cli {

    private static final String AID_HEX = "F06D656F776C01";
    private static final CommandAPDU SELECT_MEOWL =
            new CommandAPDU(0x00, 0xA4, 0x04, 0x00, hex(AID_HEX));

    private Cli() {}

    public static void main(String[] args) throws Exception {
        if (args.length == 0 || "--help".equals(args[0])) {
            System.out.println("usage: meowl <hex-apdu>");
            return;
        }

        CommandAPDU userApdu = new CommandAPDU(hex(args[0]));

        Readers.select()
                .withCard()
                .log(System.out)
                .accept(
                        bibo -> {
                            ResponseAPDU sel = bibo.transmit(SELECT_MEOWL);
                            if (sel.getSW() != 0x9000) {
                                throw new IllegalStateException(
                                        "SELECT failed: SW=%04X".formatted(sel.getSW()));
                            }
                            ResponseAPDU resp = bibo.transmit(userApdu);
                            System.out.printf(
                                    "<-- %s SW=%04X%n", hex(resp.getData()), resp.getSW());
                        });
    }

    private static byte[] hex(String s) {
        int n = s.length();
        if ((n & 1) != 0) throw new IllegalArgumentException("odd-length hex: " + s);
        byte[] out = new byte[n / 2];
        for (int i = 0; i < n; i += 2) {
            out[i / 2] = (byte) Integer.parseInt(s, i, i + 2, 16);
        }
        return out;
    }

    private static String hex(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) sb.append("%02X".formatted(b));
        return sb.toString();
    }
}
