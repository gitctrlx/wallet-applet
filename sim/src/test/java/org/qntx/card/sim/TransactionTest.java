// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.sim;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Arrays;
import javacard.framework.ISO7816;
import javacard.framework.TransactionException;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.qntx.card.sim.probe.TxProbe;

class TransactionTest {

    private static final byte[] AID = {0x02, 0x02, 0x03, 0x04, 0x05};
    private static final byte INS_TX_STORE = 0x21;
    private static final byte INS_TX_COPY = 0x22;
    private static final byte INS_TX_COPY_NA = 0x23;
    private static final byte INS_TX_NESTED = 0x24;
    private static final byte INS_TX_SETKEY = 0x25;
    private static final byte INS_TX_SETS = 0x26;
    private static final byte INS_TX_SETW = 0x27;
    private static final byte INS_TX_SETEXP = 0x28;
    private static final byte INS_TX_CLEARKEY = 0x29;
    private static final byte INS_TX_GENPAIR = 0x2A;
    private static final byte INS_TX_UNUSED = 0x2B;
    private static final byte INS_TX_SPAN = 0x2C;
    private static final byte INS_TX_FILL = 0x2D;
    private static final byte INS_TX_BUF_SETW = 0x2E;
    private static final byte INS_TX_WIDE = 0x38;
    private static final byte INS_TX_OPEN = 0x2F;
    private static final byte INS_TX_OPEN_SEND = 0x39;
    private static final byte INS_READ_BUF = 0x30;
    private static final byte INS_READ_AES = 0x32;
    private static final byte INS_READ_S = 0x33;
    private static final byte INS_READ_W = 0x34;
    private static final byte INS_READ_EXP = 0x35;
    private static final byte INS_READ_PUB_MOD = 0x36;
    private static final byte INS_SET_AES = 0x37;

    private static final byte COMMIT = 1;
    private static final byte ABORT = 0;

    // jcardsim always initializes EC key domain parameters to
    // secp256r1, so setW needs a real point on that curve
    private static final byte[] W = SECNamedCurves.getByName("secp256r1").getG().getEncoded(false);

    private Card card;

    @BeforeEach
    void setUp() {
        card = new Card();
        card.install(AID, TxProbe.class);
        card.transmit(selectApdu(AID));
    }

    static byte[] selectApdu(byte[] aid) {
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

    private byte[] read(byte ins, int len) {
        return data(card.transmit(cmd(ins, (byte) len, (byte) 0)));
    }

    @Test
    void commitKeepsArrayWrites() {
        assertSw(card.transmit(cmd(INS_TX_STORE, COMMIT, (byte) 0x41)), 0x9000);
        assertEquals((byte) 0x41, read(INS_READ_BUF, 4)[0]);
        assertEquals(1024, card.commitBytes());
    }

    @Test
    void abortRestoresArrayWrites() {
        card.transmit(cmd(INS_TX_STORE, COMMIT, (byte) 0x41));
        assertSw(card.transmit(cmd(INS_TX_STORE, ABORT, (byte) 0x7F)), 0x9000);
        assertEquals((byte) 0x41, read(INS_READ_BUF, 4)[0]);
    }

    @Test
    void atomicCopyRollsBack() {
        byte[] payload = new byte[20];
        Arrays.fill(payload, (byte) 0x2E);
        assertSw(card.transmit(cmd(INS_TX_COPY, ABORT, (byte) 0, payload)), 0x9000);
        assertEquals((byte) 0, read(INS_READ_BUF, 20)[19]);
    }

    @Test
    void nonAtomicCopyIsNotRolledBack() {
        byte[] payload = new byte[20];
        Arrays.fill(payload, (byte) 0x2E);
        assertSw(card.transmit(cmd(INS_TX_COPY_NA, ABORT, (byte) 0, payload)), 0x9000);
        assertEquals((byte) 0x2E, read(INS_READ_BUF, 20)[19]);
    }

    @Test
    void nestedBeginThrowsInProgress() {
        byte[] response = card.transmit(cmd(INS_TX_NESTED, (byte) 0, (byte) 0));
        assertSw(response, 0x9000);
        assertEquals(TransactionException.IN_PROGRESS, data(response)[0]);
    }

    @Test
    void setKeyRollsBack() {
        byte[] first = new byte[16];
        Arrays.fill(first, (byte) 0x0A);
        card.transmit(cmd(INS_SET_AES, (byte) 0, (byte) 0, first));

        byte[] second = new byte[16];
        Arrays.fill(second, (byte) 0x0B);
        assertSw(card.transmit(cmd(INS_TX_SETKEY, ABORT, (byte) 0, second)), 0x9000);
        assertArrayEquals(first, read(INS_READ_AES, 0));

        assertSw(card.transmit(cmd(INS_TX_SETKEY, COMMIT, (byte) 0, second)), 0x9000);
        assertArrayEquals(second, read(INS_READ_AES, 0));
        assertEquals(512, card.commitBytes());
    }

    @Test
    void setSRollsBack() {
        byte[] s = new byte[32];
        Arrays.fill(s, (byte) 0x2D);
        assertSw(card.transmit(cmd(INS_TX_SETS, ABORT, (byte) 0, s)), 0x9000);
        // fresh key: the aborted setS left it uninitialized
        assertEquals((byte) 0xEE, read(INS_READ_S, 0)[0]);

        assertSw(card.transmit(cmd(INS_TX_SETS, COMMIT, (byte) 0, s)), 0x9000);
        assertArrayEquals(s, read(INS_READ_S, 0));
        assertEquals(512, card.commitBytes());
    }

    @Test
    void setWRollsBack() {
        byte[] w = W;
        assertSw(card.transmit(cmd(INS_TX_SETW, ABORT, (byte) 0, w)), 0x9000);
        assertEquals((byte) 0xEE, read(INS_READ_W, 0)[0]);

        assertSw(card.transmit(cmd(INS_TX_SETW, COMMIT, (byte) 0, w)), 0x9000);
        assertArrayEquals(w, read(INS_READ_W, 0));
        assertEquals(1024, card.commitBytes());
    }

    @Test
    void setExponentRollsBack() {
        byte[] exponent = {0x01, 0x00, 0x01};
        assertSw(card.transmit(cmd(INS_TX_SETEXP, ABORT, (byte) 0, exponent)), 0x9000);
        assertEquals((byte) 0xEE, read(INS_READ_EXP, 0)[0]);

        assertSw(card.transmit(cmd(INS_TX_SETEXP, COMMIT, (byte) 0, exponent)), 0x9000);
        assertArrayEquals(exponent, read(INS_READ_EXP, 0));
        assertEquals(512, card.commitBytes());
    }

    @Test
    void clearKeyRollsBackAndCostsNothing() {
        byte[] key = new byte[16];
        Arrays.fill(key, (byte) 0x0C);
        card.transmit(cmd(INS_SET_AES, (byte) 0, (byte) 0, key));

        assertSw(card.transmit(cmd(INS_TX_CLEARKEY, ABORT, (byte) 0)), 0x9000);
        assertArrayEquals(key, read(INS_READ_AES, 0));
        assertEquals(0, card.commitBytes());

        assertSw(card.transmit(cmd(INS_TX_CLEARKEY, COMMIT, (byte) 0)), 0x9000);
        // cleared: getKey throws UNINITIALIZED_KEY, surfaced as 6F00
        assertSw(card.transmit(cmd(INS_READ_AES, (byte) 0, (byte) 0)), 0x6F00);
    }

    @Test
    void genKeyPairRollsBack() {
        assertSw(card.transmit(cmd(INS_TX_GENPAIR, ABORT, (byte) 0)), 0x9000);
        // aborted generation left the public key uninitialized
        assertSw(card.transmit(cmd(INS_READ_PUB_MOD, (byte) 0, (byte) 0)), 0x6F00);

        assertSw(card.transmit(cmd(INS_TX_GENPAIR, COMMIT, (byte) 0)), 0x9000);
        assertEquals(64, read(INS_READ_PUB_MOD, 0).length);
        assertEquals(1024, card.commitBytes());
    }

    @Test
    void unusedCommitCapacityDecreasesInsideTransaction() {
        byte[] response = card.transmit(cmd(INS_TX_UNUSED, (byte) 0, (byte) 0));
        assertSw(response, 0x9000);
        int unused = ((data(response)[0] & 0xFF) << 8) | (data(response)[1] & 0xFF);
        assertEquals(4096, unused);
        assertEquals(1024, card.commitBytes());
    }

    @Test
    void commitBufferChargesMeasuredAmounts() {
        // one byte touched: one 512 B span billed at two pages
        card.transmit(cmd(INS_TX_STORE, COMMIT, (byte) 1));
        assertEquals(1024, card.commitBytes());
        // span of 401 bytes still fits one 512 B span
        card.transmit(cmd(INS_TX_SPAN, (byte) 0, (byte) 1));
        assertEquals(1024, card.commitBytes());
        // span of 513 bytes needs two spans
        card.transmit(cmd(INS_TX_WIDE, (byte) 0, (byte) 1));
        assertEquals(2048, card.commitBytes());
    }

    @Test
    void bufferPlusSetWCharges2048() {
        byte[] w = W;
        assertSw(card.transmit(cmd(INS_TX_BUF_SETW, COMMIT, (byte) 0, w)), 0x9000);
        assertEquals(2048, card.commitBytes());
    }

    @Test
    void bufferFullThrowsAndDoesNotWrite() {
        byte[] response = card.transmit(cmd(INS_TX_FILL, (byte) 0, (byte) 0));
        assertSw(response, 0x9000);
        assertEquals(TransactionException.BUFFER_FULL, data(response)[0]);
        // the overflowing tail write did not happen, and the abort
        // restored everything else
        byte[] buf = read(INS_READ_BUF, 4);
        assertEquals((byte) 0, buf[0]);
    }

    @Test
    void openTransactionAtProcessReturnAutoAborts() {
        card.transmit(cmd(INS_TX_STORE, COMMIT, (byte) 0x41));
        byte[] response = card.transmit(cmd(INS_TX_OPEN, (byte) 0, (byte) 0x7F));
        assertSw(response, 0x6F00);
        // the aborted write rolled back
        assertEquals((byte) 0x41, read(INS_READ_BUF, 4)[0]);
    }

    @Test
    void autoAbortKeepsAlreadySentResponseData() {
        card.transmit(cmd(INS_TX_STORE, COMMIT, (byte) 0x41));
        byte[] response = card.transmit(cmd(INS_TX_OPEN_SEND, (byte) 0, (byte) 0x7F));
        assertSw(response, 0x6F00);
        assertArrayEquals(new byte[] {0x41, 0x42}, data(response));
        assertEquals((byte) 0x41, read(INS_READ_BUF, 4)[0]);
    }

    @Test
    void tearRollsBackWholeTransaction() {
        card.transmit(cmd(INS_TX_STORE, COMMIT, (byte) 0x41));
        byte[] w = W;
        card.tearAt(2);
        assertThrows(
                TornException.class,
                () -> card.transmit(cmd(INS_TX_BUF_SETW, COMMIT, (byte) 0, w)));

        card.transmit(selectApdu(AID));
        assertEquals((byte) 0x41, read(INS_READ_BUF, 4)[0]);
        assertEquals((byte) 0xEE, read(INS_READ_W, 0)[0]);
    }
}
