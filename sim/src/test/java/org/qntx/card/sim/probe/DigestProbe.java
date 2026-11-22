// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.sim.probe;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.security.MessageDigest;

/**
 * Probe for the digest counter: the install-time {@code MessageDigest.getInstance} goes through
 * {@code Memory.messageDigest}, so {@code update}/{@code doFinal} calls are counted per algorithm
 * per command.
 */
public final class DigestProbe extends Applet {

    private static final byte INS_SHA = 0x10;
    private static final byte INS_SHA512 = 0x11;

    private final MessageDigest sha256;
    private final MessageDigest sha512;

    private DigestProbe() {
        sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        sha512 = MessageDigest.getInstance(MessageDigest.ALG_SHA_512, false);
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new DigestProbe().register();
    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }
        byte[] buffer = apdu.getBuffer();
        switch (buffer[ISO7816.OFFSET_INS]) {
            case INS_SHA:
                sha256.reset();
                sha256.update(buffer, ISO7816.OFFSET_CDATA, (short) 16);
                sha256.doFinal(
                        buffer, (short) (ISO7816.OFFSET_CDATA + 16), (short) 8, buffer, (short) 0);
                return;
            case INS_SHA512:
                sha512.reset();
                sha512.doFinal(buffer, ISO7816.OFFSET_CDATA, (short) 24, buffer, (short) 0);
                return;
            default:
                return;
        }
    }
}
