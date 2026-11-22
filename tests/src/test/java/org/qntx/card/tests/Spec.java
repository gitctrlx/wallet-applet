// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.tests;

import java.util.HexFormat;

/** Identifiers and status words as written in spec/protocol.md, independent of the applet. */
final class Spec {
    /** §2: load file (package) AID. */
    static final byte[] PACKAGE_AID = hex("F0716E747800");

    /** §2: wallet applet class AID and instance AID. */
    static final byte[] WALLET_AID = hex("F0716E74780101");

    /** §6: SELECT of the wallet applet. */
    static final byte[] SELECT = hex("00A4040007F0716E7478010100");

    static final byte[] SW_OK = hex("9000");
    static final byte[] SW_CLA = hex("6E00");
    static final byte[] SW_INS = hex("6D00");

    private Spec() {}

    static byte[] hex(String s) {
        return HexFormat.of().parseHex(s);
    }
}
