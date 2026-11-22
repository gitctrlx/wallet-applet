// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.sim.probe;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * Probe for {@code Fault.armSkip}: void methods in an instrumented package and the {@code JCSystem}
 * transaction calls go through the agent's woven guard. {@code mark} writes its argument into a
 * persistent array so a skipped call is observable; the transaction command reports the open depth.
 */
public final class SkipProbe extends Applet {

    private static final byte INS_MARK = 0x01;
    private static final byte INS_TX = 0x02;
    private static final byte INS_FILL = 0x03;

    private final byte[] buf;

    private SkipProbe() {
        buf = new byte[8];
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new SkipProbe().register();
    }

    /** Instance void method with four argument slots: the skip path pops all of them. */
    void mark(byte[] dst, short off, short len, byte value) {
        Util.arrayFillNonAtomic(dst, off, len, value);
    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }
        byte[] buffer = apdu.getBuffer();
        byte ins = buffer[ISO7816.OFFSET_INS];
        switch (ins) {
            case INS_MARK:
                mark(buf, (short) 0, (short) 4, (byte) 0x11);
                mark(buf, (short) 4, (short) 4, (byte) 0x22);
                Util.arrayCopyNonAtomic(buf, (short) 0, buffer, (short) 0, (short) 8);
                apdu.setOutgoingAndSend((short) 0, (short) 8);
                return;
            case INS_TX:
                JCSystem.beginTransaction();
                buf[0] = (byte) 0x77;
                JCSystem.commitTransaction();
                buffer[0] = (byte) JCSystem.getTransactionDepth();
                apdu.setOutgoingAndSend((short) 0, (short) 1);
                return;
            case INS_FILL:
                Util.arrayFillNonAtomic(buf, (short) 0, (short) 8, (byte) 0x55);
                Util.arrayCopyNonAtomic(buf, (short) 0, buffer, (short) 0, (short) 8);
                apdu.setOutgoingAndSend((short) 0, (short) 8);
                return;
            default:
                return;
        }
    }
}
