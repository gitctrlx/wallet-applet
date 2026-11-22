// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.sim.probe;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.security.RandomData;

/**
 * Probe for {@code Rng.fix}: the install-time {@code RandomData.getInstance} goes through {@code
 * Memory.randomData}, so arming before install wraps the field engine while {@link #INS_FRESH}
 * proves engines created later start the block at index 0 again.
 */
public final class RngProbe extends Applet {

    private static final byte INS_RAND = 0x70;
    private static final byte INS_FRESH = 0x71;

    private final RandomData rng;

    private RngProbe() {
        rng = RandomData.getInstance(RandomData.ALG_KEYGENERATION);
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new RngProbe().register();
    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }
        byte[] buffer = apdu.getBuffer();
        switch (buffer[ISO7816.OFFSET_INS]) {
            case INS_RAND:
                rng.generateData(buffer, (short) 0, (short) 16);
                rng.nextBytes(buffer, (short) 16, (short) 8);
                apdu.setOutgoingAndSend((short) 0, (short) 24);
                return;
            case INS_FRESH:
                {
                    RandomData fresh = RandomData.getInstance(RandomData.ALG_KEYGENERATION);
                    fresh.generateData(buffer, (short) 0, (short) 12);
                    apdu.setOutgoingAndSend((short) 0, (short) 12);
                    return;
                }
            default:
                return;
        }
    }
}
