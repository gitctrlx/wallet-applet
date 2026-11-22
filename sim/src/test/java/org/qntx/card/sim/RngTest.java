// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.sim;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.util.Arrays;
import javacard.framework.ISO7816;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.qntx.card.sim.probe.RngProbe;

/**
 * {@link Rng#fix}: arming after install rewrites every applet {@code RandomData} engine — including
 * the one created in the constructor — so each {@code generateData}/{@code nextBytes} call serves
 * the block from index 0 (cycling inside a call longer than the block), until {@link Rng#reset}
 * restores real entropy.
 */
final class RngTest {

    private static final byte[] AID = {0x07, 0x02, 0x03, 0x04, 0x05};
    private static final byte INS_RAND = 0x70;
    private static final byte INS_FRESH = 0x71;

    private static byte[] seqBlock(int len) {
        byte[] b = new byte[len];
        for (int i = 0; i < len; i++) {
            b[i] = (byte) (0xA0 + i);
        }
        return b;
    }

    @AfterEach
    void disarm() {
        Rng.reset();
    }

    private static Card install() {
        Card card = new Card();
        card.install(AID, RngProbe.class);
        byte[] sel = new byte[5 + AID.length];
        sel[ISO7816.OFFSET_INS] = (byte) 0xA4;
        sel[ISO7816.OFFSET_P1] = 0x04;
        sel[ISO7816.OFFSET_LC] = (byte) AID.length;
        System.arraycopy(AID, 0, sel, ISO7816.OFFSET_CDATA, AID.length);
        card.transmit(sel);
        return card;
    }

    private static byte[] cmd(byte ins) {
        byte[] apdu = new byte[5];
        apdu[ISO7816.OFFSET_INS] = ins;
        return apdu;
    }

    private static byte[] data(byte[] response) {
        return Arrays.copyOf(response, response.length - 2);
    }

    @Test
    void armingActsOnTheInstallTimeEngine() {
        byte[] block = seqBlock(20);
        Card card = install();
        byte[] real = data(card.transmit(cmd(INS_RAND)));
        Rng.fix(block);
        // the same install-time engine now serves the block — generateData(16) then nextBytes(8)
        // each start at index 0
        byte[] expect = new byte[24];
        System.arraycopy(block, 0, expect, 0, 16);
        System.arraycopy(block, 0, expect, 16, 8);
        assertArrayEquals(expect, data(card.transmit(cmd(INS_RAND))));
        assertArrayEquals(expect, data(card.transmit(cmd(INS_RAND))));
        assertFalse(Arrays.equals(real, expect));
    }

    @Test
    void aCallCyclesInsideItselfWhenLongerThanTheBlock() {
        byte[] block = seqBlock(10);
        Card card = install();
        Rng.fix(block);
        byte[] expect = new byte[24];
        // generateData(16) wraps inside the call; nextBytes(8) restarts at index 0
        System.arraycopy(block, 0, expect, 0, 10);
        System.arraycopy(block, 0, expect, 10, 6);
        System.arraycopy(block, 0, expect, 16, 8);
        assertArrayEquals(expect, data(card.transmit(cmd(INS_RAND))));
    }

    @Test
    void freshEnginesRestartAtIndexZero() {
        byte[] block = seqBlock(20);
        Card card = install();
        Rng.fix(block);
        byte[] expect = Arrays.copyOf(block, 12);
        assertArrayEquals(expect, data(card.transmit(cmd(INS_FRESH))));
        assertArrayEquals(expect, data(card.transmit(cmd(INS_FRESH))));
    }

    @Test
    void resetRestoresRealEntropy() {
        byte[] block = seqBlock(20);
        Card card = install();
        Rng.fix(block);
        assertArrayEquals(Arrays.copyOf(block, 12), data(card.transmit(cmd(INS_FRESH))));
        Rng.reset();
        // engines serve real entropy again from the next call on
        assertFalse(Arrays.equals(Arrays.copyOf(block, 12), data(card.transmit(cmd(INS_FRESH)))));
    }
}
