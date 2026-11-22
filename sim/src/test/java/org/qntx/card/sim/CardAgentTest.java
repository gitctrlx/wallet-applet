// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.sim;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Arrays;
import javacard.framework.ISO7816;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.qntx.card.sim.probe.NvmProbe;

class CardAgentTest {

    private static final byte[] AID = {0x01, 0x02, 0x03, 0x04, 0x05};
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
    private static final byte INS_WRITE_FINALLY = 0x0C;

    private Card card;

    @BeforeEach
    void setUp() {
        card = new Card();
        card.install(AID, NvmProbe.class);
        select();
    }

    private byte[] select() {
        return card.transmit(selectApdu(AID));
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

    @Test
    void countsByteStoresPerCommand() {
        assertSw(card.transmit(cmd(INS_WRITE, (byte) 10, (byte) 0x5A)), 0x9000);
        assertEquals(10, card.writes());
        byte[] read = data(card.transmit(cmd(INS_READ, (byte) 0, (byte) 0)));
        for (int i = 0; i < 10; i++) {
            assertEquals((byte) 0x5A, read[i]);
        }
        assertEquals((byte) 0, read[10]);
    }

    @Test
    void countsEveryPersistentWriteForm() {
        card.transmit(cmd(INS_SWRITE, (byte) 3, (byte) 0));
        assertEquals(3, card.writes());
        card.transmit(cmd(INS_BWRITE, (byte) 2, (byte) 0));
        assertEquals(2, card.writes());
        card.transmit(cmd(INS_SET_SHORT, (byte) 0, (byte) 0));
        assertEquals(1, card.writes());
        card.transmit(cmd(INS_COPY, (byte) 0, (byte) 0, new byte[12]));
        assertEquals(1, card.writes());
        card.transmit(cmd(INS_COPY_NA, (byte) 0, (byte) 0, new byte[16]));
        assertEquals(2, card.writes());
        card.transmit(cmd(INS_FILL_NA, (byte) 14, (byte) 0x33));
        assertEquals(2, card.writes());
        // reads, APDU-buffer stores and transient-array stores are not
        // persistent writes
        card.transmit(cmd(INS_TWRITE, (byte) 0x11, (byte) 0x22));
        assertEquals(0, card.writes());
        card.transmit(cmd(INS_READ, (byte) 0, (byte) 0));
        assertEquals(0, card.writes());
    }

    @Test
    void persistentFieldWriteAfterInstallSurfacesAssertionError() {
        assertSw(card.transmit(cmd(INS_FWRITE, (byte) 0, (byte) 0)), 0x6F42);
    }

    @Test
    void tearAtNthWriteAppliesOnlyThePrefix() {
        card.tearAt(4);
        assertThrows(
                TornException.class, () -> card.transmit(cmd(INS_WRITE, (byte) 8, (byte) 0x77)));
        assertEquals(4, card.writes());

        assertSw(select(), 0x9000);
        byte[] read = data(card.transmit(cmd(INS_READ, (byte) 0, (byte) 0)));
        for (int i = 0; i < 3; i++) {
            assertEquals((byte) 0x77, read[i], "write " + i + " must have landed");
        }
        assertEquals((byte) 0, read[3], "the torn write must not have landed");
    }

    @Test
    void tearLeavesAtomicCopyUnwritten() {
        card.transmit(cmd(INS_WRITE, (byte) 4, (byte) 0x09));
        byte[] payload = new byte[12];
        Arrays.fill(payload, (byte) 0xAB);
        card.tearAt(1);
        assertThrows(
                TornException.class,
                () -> card.transmit(cmd(INS_COPY, (byte) 0, (byte) 0, payload)));

        assertSw(select(), 0x9000);
        byte[] read = data(card.transmit(cmd(INS_READ, (byte) 0, (byte) 0)));
        // the atomic copy never ran; only the earlier 4 writes show
        for (int i = 0; i < 4; i++) {
            assertEquals((byte) 0x09, read[i]);
        }
        assertEquals((byte) 0, read[4]);
    }

    @Test
    void tearSkipsAppletFinallyBlock() {
        card.tearAt(5);
        assertThrows(
                TornException.class,
                () -> card.transmit(cmd(INS_WRITE_FINALLY, (byte) 8, (byte) 0x66)));

        assertSw(select(), 0x9000);
        byte[] read = data(card.transmit(cmd(INS_READ, (byte) 0, (byte) 0)));
        for (int i = 0; i < 4; i++) {
            assertEquals((byte) 0x66, read[i]);
        }
        assertEquals((byte) 0, read[32], "the finally block must not have run");
    }

    @Test
    void cardAnswersAgainAfterPowerLoss() {
        card.tearAt(2);
        assertThrows(
                TornException.class, () -> card.transmit(cmd(INS_WRITE, (byte) 6, (byte) 0x55)));
        assertSw(select(), 0x9000);
        assertSw(card.transmit(cmd(INS_WRITE, (byte) 2, (byte) 0x44)), 0x9000);
        assertEquals(2, card.writes());
    }

    @Test
    void commandWithoutPersistentWritesCountsZero() {
        card.transmit(cmd(INS_WRITE, (byte) 3, (byte) 0x10));
        card.transmit(cmd(INS_READ, (byte) 0, (byte) 0));
        assertEquals(0, card.writes());
    }

    @Test
    void persistentBufferSurvivesPowerCycle() {
        card.transmit(cmd(INS_WRITE, (byte) 6, (byte) 0x7E));
        card.powerCycle();
        assertSw(select(), 0x9000);
        byte[] read = data(card.transmit(cmd(INS_READ, (byte) 0, (byte) 0)));
        for (int i = 0; i < 6; i++) {
            assertEquals((byte) 0x7E, read[i]);
        }
    }
}
