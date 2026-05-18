/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools;

import apdu4j.core.HexUtils;
import apdu4j.pcsc.TerminalManager;
import java.util.List;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

/**
 * Minimal command-line tool that talks to a connected JavaCard.
 *
 * <p>Usage: {@code meowl <hex-apdu>} where the APDU is the full command APDU
 * encoded as hexadecimal, e.g. {@code 80010000}.
 */
public final class Cli {

    private static final byte[] AID = {
        (byte) 0xF0, 0x6D, 0x65, 0x6F, 0x77, 0x6C, 0x01
    };

    private Cli() {}

    public static void main(String[] args) throws Exception {
        if (args.length == 0 || "--help".equals(args[0])) {
            System.out.println("usage: meowl <hex-apdu>");
            System.out.println("       meowl --list-readers");
            return;
        }

        TerminalManager manager = TerminalManager.getInstance();
        List<CardTerminal> terminals = manager.terminals().list();
        if (terminals.isEmpty()) {
            System.err.println("No PC/SC readers detected.");
            System.exit(1);
        }

        if ("--list-readers".equals(args[0])) {
            terminals.forEach(t -> System.out.println(" - " + t.getName()));
            return;
        }

        CardTerminal terminal = terminals.get(0);
        try (Card card = terminal.connect("*")) {
            CardChannel channel = card.getBasicChannel();
            ResponseAPDU select = channel.transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, AID));
            if (select.getSW() != 0x9000) {
                System.err.printf("SELECT failed: SW=%04X%n", select.getSW());
                System.exit(2);
            }
            ResponseAPDU response = channel.transmit(new CommandAPDU(HexUtils.hex2bin(args[0])));
            System.out.printf("<-- %s SW=%04X%n",
                    HexUtils.bin2hex(response.getData()), response.getSW());
        }
    }
}
