// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;

/** The qntx card wallet applet (protocol.md §2, §6, §9.1). */
public final class WalletApplet extends Applet {
    /** Proprietary class byte of every command after SELECT (protocol.md §2). */
    private static final byte CLA = (byte) 0x80;

    private WalletApplet(byte[] bArray, short bOffset) {
        register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }

    /** GlobalPlatform install entry; the instance AID is taken from the install data. */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new WalletApplet(bArray, bOffset);
    }

    /** Outer dispatch in the order of protocol.md §9.1. */
    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }
        if (apdu.getBuffer()[ISO7816.OFFSET_CLA] != CLA) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
    }
}
