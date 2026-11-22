// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.sim;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Arrays;
import javacard.framework.ISO7816;
import org.junit.jupiter.api.Test;
import org.qntx.card.sim.probe.NvmProbe;
import org.qntx.card.sim.probe.TxProbe;

/**
 * Power loss at every counted write (architecture section 8 patch 5): the armed n-th persistent
 * write throws before it takes effect, so a torn command applies exactly writes 1..n-1 outside a
 * transaction and nothing inside one; a non-atomic copy may be left half written.
 */
class TearTest {

    private static final byte[] AID = {0x03, 0x02, 0x03, 0x04, 0x05};
    private static final byte[] TX_AID = {0x03, 0x02, 0x03, 0x04, 0x06};
    private static final byte INS_WRITE = 0x01;
    private static final byte INS_COPY_NA = 0x05;
    private static final byte INS_READ = 0x0A;
    private static final byte INS_TX_SPAN = 0x2C;
    private static final byte INS_READ_SPAN = 0x31;

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

    private static byte[] cmd(byte ins, byte p1, byte p2, byte[] data) {
        byte[] apdu = new byte[5 + data.length];
        apdu[ISO7816.OFFSET_INS] = ins;
        apdu[ISO7816.OFFSET_P1] = p1;
        apdu[ISO7816.OFFSET_P2] = p2;
        apdu[ISO7816.OFFSET_LC] = (byte) data.length;
        System.arraycopy(data, 0, apdu, ISO7816.OFFSET_CDATA, data.length);
        return apdu;
    }

    private static short sw(byte[] response) {
        return (short)
                (((response[response.length - 2] & 0xFF) << 8)
                        | (response[response.length - 1] & 0xFF));
    }

    private static byte[] data(byte[] response) {
        return Arrays.copyOf(response, response.length - 2);
    }

    private static void assertSw(byte[] response, int expected) {
        assertEquals(
                (short) expected,
                sw(response),
                () -> "SW 0x" + Integer.toHexString(sw(response) & 0xFFFF));
    }

    private Card cardWith(Class<? extends javacard.framework.Applet> applet, byte[] aid) {
        Card card = new Card();
        card.install(aid, applet);
        assertSw(card.transmit(selectApdu(aid)), 0x9000);
        return card;
    }

    @Test
    void tearAtEveryWritePointLeavesOnlyThePrefix() {
        int k = 8;
        for (int n = 1; n <= k; n++) {
            Card card = cardWith(NvmProbe.class, AID);
            card.tearAt(n);
            assertThrows(
                    TornException.class,
                    () -> card.transmit(cmd(INS_WRITE, (byte) k, (byte) 0x77)),
                    "tear at write " + n);
            assertEquals(n, card.writes());

            // power back up: the card answers after SELECT, writes
            // 1..n-1 are applied, write n and later are not
            assertSw(card.transmit(selectApdu(AID)), 0x9000);
            byte[] read = data(card.transmit(cmd(INS_READ, (byte) 0, (byte) 0)));
            for (int i = 0; i < k; i++) {
                assertEquals(
                        (byte) (i < n - 1 ? 0x77 : 0x00), read[i], "tear at " + n + ": byte " + i);
            }
        }
    }

    @Test
    void tearInsideTransactionAppliesNothing() {
        // INS_TX_SPAN writes span[0] and span[400] inside one
        // transaction; whatever the tear point, the power-loss
        // rollback leaves the whole span untouched
        for (int n = 1; n <= 2; n++) {
            Card card = cardWith(TxProbe.class, TX_AID);
            card.tearAt(n);
            assertThrows(
                    TornException.class,
                    () -> card.transmit(cmd(INS_TX_SPAN, (byte) 1, (byte) 0x5C)),
                    "tear at write " + n);
            assertEquals(n, card.writes());

            assertSw(card.transmit(selectApdu(TX_AID)), 0x9000);
            byte[] span = data(card.transmit(cmd(INS_READ_SPAN, (byte) 8, (byte) 0)));
            for (int i = 0; i < 8; i++) {
                assertEquals((byte) 0, span[i], "tear at " + n + ": span byte " + i);
            }
        }
    }

    @Test
    void tearLeavesNonAtomicCopyHalfWritten() {
        // a non-atomic copy is two write points; tearing at the second
        // one leaves the first half of the copy applied (patch 5)
        Card card = cardWith(NvmProbe.class, AID);
        byte[] payload = new byte[12];
        Arrays.fill(payload, (byte) 0xAB);
        card.tearAt(2);
        assertThrows(
                TornException.class,
                () -> card.transmit(cmd(INS_COPY_NA, (byte) 0, (byte) 0, payload)));

        assertSw(card.transmit(selectApdu(AID)), 0x9000);
        byte[] read = data(card.transmit(cmd(INS_READ, (byte) 0, (byte) 0)));
        for (int i = 0; i < 6; i++) {
            assertEquals((byte) 0xAB, read[40 + i], "copied half, byte " + i);
        }
        for (int i = 6; i < 12; i++) {
            assertEquals((byte) 0, read[40 + i], "uncopied half, byte " + i);
        }
    }

    @Test
    void tearAtFirstNonAtomicPointLeavesNothing() {
        Card card = cardWith(NvmProbe.class, AID);
        byte[] payload = new byte[12];
        Arrays.fill(payload, (byte) 0xAB);
        card.tearAt(1);
        assertThrows(
                TornException.class,
                () -> card.transmit(cmd(INS_COPY_NA, (byte) 0, (byte) 0, payload)));

        assertSw(card.transmit(selectApdu(AID)), 0x9000);
        byte[] read = data(card.transmit(cmd(INS_READ, (byte) 0, (byte) 0)));
        for (int i = 0; i < 12; i++) {
            assertEquals((byte) 0, read[40 + i], "byte " + i);
        }
    }
}
