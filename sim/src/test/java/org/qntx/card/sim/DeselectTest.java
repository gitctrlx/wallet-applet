// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.sim;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Arrays;
import javacard.framework.ISO7816;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.qntx.card.sim.probe.NvmProbe;

/**
 * CLEAR_ON_DESELECT / CLEAR_ON_RESET semantics (architecture section 8 patch 7; verified upstream,
 * audit-impl F-6 last row): re-selecting the same applet or selecting another applet clears the
 * owner's CLEAR_ON_DESELECT arrays while CLEAR_ON_RESET survives until a power cycle clears both.
 */
class DeselectTest {

    private static final byte[] AID = {0x06, 0x02, 0x03, 0x04, 0x05};
    private static final byte[] AID2 = {0x06, 0x02, 0x03, 0x04, 0x06};
    private static final byte INS_TWRITE = 0x08;
    private static final byte INS_SET_TMEM = 0x0D;
    private static final byte INS_TREAD = 0x0B;

    private Card card;

    @BeforeEach
    void setUp() {
        card = new Card();
        card.install(AID, NvmProbe.class);
        card.transmit(selectApdu(AID));
    }

    private static byte[] selectApdu(byte[] aid) {
        byte[] apdu = new byte[5 + aid.length];
        apdu[ISO7816.OFFSET_INS] = (byte) 0xA4;
        apdu[ISO7816.OFFSET_P1] = 0x04;
        apdu[ISO7816.OFFSET_LC] = (byte) aid.length;
        System.arraycopy(aid, 0, apdu, ISO7816.OFFSET_CDATA, aid.length);
        return apdu;
    }

    private static byte[] cmd(byte ins, byte p1, byte p2) {
        byte[] apdu = new byte[5];
        apdu[ISO7816.OFFSET_INS] = ins;
        apdu[ISO7816.OFFSET_P1] = p1;
        apdu[ISO7816.OFFSET_P2] = p2;
        return apdu;
    }

    private static short sw(byte[] response) {
        return (short)
                (((response[response.length - 2] & 0xFF) << 8)
                        | (response[response.length - 1] & 0xFF));
    }

    private static void assertSw(byte[] response, int expected) {
        assertEquals(
                (short) expected,
                sw(response),
                () -> "SW 0x" + Integer.toHexString(sw(response) & 0xFFFF));
    }

    private byte[] tread() {
        byte[] response = card.transmit(cmd(INS_TREAD, (byte) 0, (byte) 0));
        assertSw(response, 0x9000);
        return Arrays.copyOf(response, response.length - 2);
    }

    private void fillTransient() {
        // tDeselect[0]=0x11, tReset[0]=0x22, tDeselect[1]=0x33,
        // tReset[1]=0x44
        assertSw(card.transmit(cmd(INS_TWRITE, (byte) 0x11, (byte) 0x22)), 0x9000);
        assertSw(card.transmit(cmd(INS_SET_TMEM, (byte) 0x33, (byte) 0x44)), 0x9000);
        byte[] filled = tread();
        assertEquals((byte) 0x11, filled[0]);
        assertEquals((byte) 0x22, filled[1]);
        assertEquals((byte) 0x33, filled[2]);
        assertEquals((byte) 0x44, filled[3]);
    }

    @Test
    void reselectClearsDeselectKeepsReset() {
        fillTransient();
        assertSw(card.transmit(selectApdu(AID)), 0x9000);
        assertArrayEquals(new byte[] {0, 0x22, 0, 0x44, 0}, tread());
    }

    @Test
    void selectingOtherAppletClearsOwnerDeselect() {
        // a second instance of the same package clears the first
        // applet's CLEAR_ON_DESELECT state on deselect
        card.install(AID2, NvmProbe.class);
        fillTransient();
        assertSw(card.transmit(selectApdu(AID2)), 0x9000);
        assertSw(card.transmit(selectApdu(AID)), 0x9000);
        assertArrayEquals(new byte[] {0, 0x22, 0, 0x44, 0}, tread());
    }

    @Test
    void powerCycleClearsBothTransientKinds() {
        fillTransient();
        card.powerCycle();
        assertSw(card.transmit(selectApdu(AID)), 0x9000);
        assertArrayEquals(new byte[] {0, 0, 0, 0, 0}, tread());
    }
}
