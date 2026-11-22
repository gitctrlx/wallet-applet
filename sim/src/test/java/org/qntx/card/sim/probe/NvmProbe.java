// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.sim.probe;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * Probe applet for persistent-write accounting, tearing and field-write checks. Persistent state
 * lives in arrays only; {@code fieldByte} is the canary for the after-install field-write rule.
 */
public final class NvmProbe extends Applet {

    private static final byte INS_WRITE = 0x01;
    private static final byte INS_SWRITE = 0x02;
    private static final byte INS_BWRITE = 0x03;
    private static final byte INS_COPY = 0x04;
    private static final byte INS_COPY_NA = 0x05;
    private static final byte INS_FILL_NA = 0x06;
    private static final byte INS_SET_SHORT = 0x07;
    private static final byte INS_TWRITE = 0x08;
    private static final byte INS_FWRITE = 0x09;
    private static final byte INS_READ = 0x0A;
    private static final byte INS_TREAD = 0x0B;
    private static final byte INS_WRITE_FINALLY = 0x0C;
    private static final byte INS_SET_TMEM = 0x0D;

    private static final short BUF_LEN = 600;
    private static final byte FLAG_OFF = 32;
    private static final byte COPY_NA_OFF = 40;
    private static final byte FILL_NA_OFF = 48;
    private static final byte SET_SHORT_OFF = 56;
    private static final byte READ_LEN = 64;

    private final byte[] buf;
    private final short[] sbuf;
    private final boolean[] bbuf;
    private final byte[] tDeselect;
    private final byte[] tReset;
    private byte fieldByte;

    private NvmProbe() {
        buf = new byte[BUF_LEN];
        sbuf = new short[16];
        bbuf = new boolean[16];
        tDeselect = JCSystem.makeTransientByteArray((short) 4, JCSystem.CLEAR_ON_DESELECT);
        tReset = JCSystem.makeTransientByteArray((short) 4, JCSystem.CLEAR_ON_RESET);
        fieldByte = 0;
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new NvmProbe().register();
    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }
        byte[] buffer = apdu.getBuffer();
        byte ins = buffer[ISO7816.OFFSET_INS];
        byte p1 = buffer[ISO7816.OFFSET_P1];
        byte p2 = buffer[ISO7816.OFFSET_P2];
        switch (ins) {
            case INS_WRITE:
                for (short i = 0; i < (short) (p1 & 0xFF); i++) {
                    buf[i] = p2;
                }
                return;
            case INS_SWRITE:
                for (short i = 0; i < (short) (p1 & 0xFF); i++) {
                    sbuf[i] = (short) 0x0AB0;
                }
                return;
            case INS_BWRITE:
                for (short i = 0; i < (short) (p1 & 0xFF); i++) {
                    bbuf[i] = true;
                }
                return;
            case INS_COPY:
                {
                    short lc = apdu.setIncomingAndReceive();
                    Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, buf, (short) 0, lc);
                    return;
                }
            case INS_COPY_NA:
                {
                    short lc = apdu.setIncomingAndReceive();
                    Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, buf, COPY_NA_OFF, lc);
                    return;
                }
            case INS_FILL_NA:
                Util.arrayFillNonAtomic(buf, FILL_NA_OFF, (short) (p1 & 0xFF), p2);
                return;
            case INS_SET_SHORT:
                Util.setShort(buf, SET_SHORT_OFF, (short) 0x1234);
                return;
            case INS_TWRITE:
                tDeselect[0] = p1;
                tReset[0] = p2;
                return;
            case INS_SET_TMEM:
                tDeselect[1] = p1;
                tReset[1] = p2;
                return;
            case INS_FWRITE:
                try {
                    fieldByte = (byte) 1;
                } catch (Throwable t) {
                    ISOException.throwIt((short) 0x6F42);
                }
                return;
            case INS_WRITE_FINALLY:
                try {
                    for (short i = 0; i < (short) (p1 & 0xFF); i++) {
                        buf[i] = p2;
                    }
                } finally {
                    buf[FLAG_OFF] = (byte) 0xFF;
                }
                return;
            case INS_READ:
                Util.arrayCopy(buf, (short) 0, buffer, ISO7816.OFFSET_CDATA, (short) READ_LEN);
                apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) READ_LEN);
                return;
            case INS_TREAD:
                buffer[ISO7816.OFFSET_CDATA] = tDeselect[0];
                buffer[(short) (ISO7816.OFFSET_CDATA + 1)] = tReset[0];
                buffer[(short) (ISO7816.OFFSET_CDATA + 2)] = tDeselect[1];
                buffer[(short) (ISO7816.OFFSET_CDATA + 3)] = tReset[1];
                buffer[(short) (ISO7816.OFFSET_CDATA + 4)] = fieldByte;
                apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) 5);
                return;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }
}
