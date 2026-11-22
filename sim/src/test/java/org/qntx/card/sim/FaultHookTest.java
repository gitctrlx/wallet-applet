// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.sim;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import javacard.framework.ISO7816;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.qntx.card.sim.probe.NvmProbe;
import org.qntx.card.sim.probe.SkipProbe;

/**
 * {@link Fault#armSkip}, {@link Fault#armStore} and {@link Fault#countCalls}: the woven void-call
 * guard drops the armed call (arguments popped correctly), the store fault replaces the value a
 * persistent {@code Util.setShort} writes, and plain counting sees every woven call.
 */
final class FaultHookTest {

    private static final byte[] AID = {0x01, 0x02, 0x03, 0x04, 0x06};
    private static final byte INS_WRITE = 0x01;
    private static final byte INS_MARK = 0x01;
    private static final byte INS_TX = 0x02;
    private static final byte INS_SET_SHORT = 0x07;
    private static final byte INS_READ = 0x0A;

    private Card card;

    @BeforeEach
    void setUp() {
        card = new Card();
    }

    @AfterEach
    void disarm() {
        Fault.reset();
    }

    private void install(Class<? extends javacard.framework.Applet> probe) {
        card.install(AID, probe);
        byte[] sel = new byte[5 + AID.length];
        sel[ISO7816.OFFSET_INS] = (byte) 0xA4;
        sel[ISO7816.OFFSET_P1] = 0x04;
        sel[ISO7816.OFFSET_LC] = (byte) AID.length;
        System.arraycopy(AID, 0, sel, ISO7816.OFFSET_CDATA, AID.length);
        card.transmit(sel);
    }

    private static byte[] cmd(byte ins, byte p1, byte p2) {
        byte[] apdu = new byte[5];
        apdu[ISO7816.OFFSET_INS] = ins;
        apdu[ISO7816.OFFSET_P1] = p1;
        apdu[ISO7816.OFFSET_P2] = p2;
        return apdu;
    }

    @Test
    void armSkipDropsOnlyTheNthVoidCall() {
        install(SkipProbe.class);
        byte[] r = card.transmit(cmd(INS_MARK, (byte) 0, (byte) 0));
        assertArrayEquals(
                new byte[] {0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x22, 0x22},
                java.util.Arrays.copyOf(r, 8));

        Fault.armSkip("SkipProbe.mark", 2);
        r = card.transmit(cmd(INS_MARK, (byte) 0, (byte) 0));
        // the second mark is skipped: its four argument slots and the receiver were popped
        assertArrayEquals(
                new byte[] {0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x22, 0x22},
                java.util.Arrays.copyOf(r, 8),
                "buf keeps the previous run's second half");
        assertEquals(2, Fault.calls("SkipProbe.mark"));
    }

    @Test
    void armSkipOnCommitLeavesTheTransactionOpen() {
        install(SkipProbe.class);
        assertEquals(0, card.transmit(cmd(INS_TX, (byte) 0, (byte) 0))[0] & 0xFF);
        Fault.armSkip("JCSystem.commitTransaction", 1);
        byte[] r = card.transmit(cmd(INS_TX, (byte) 0, (byte) 0));
        assertEquals(1, r[0] & 0xFF, "skipped commit leaves the transaction open");
        assertEquals(1, Fault.calls("JCSystem.beginTransaction"));
        assertEquals(1, Fault.calls("JCSystem.commitTransaction"));
        Fault.reset();
        card.powerCycle();
    }

    @Test
    void skipIsCheapWhenNothingIsArmed() {
        install(SkipProbe.class);
        // no arm: the guard is a single flag check and every call runs
        byte[] r = card.transmit(cmd(INS_MARK, (byte) 0, (byte) 0));
        assertEquals(0x11, r[0] & 0xFF);
        assertEquals(0, Fault.calls("SkipProbe.mark"));
    }

    @Test
    void countCallsCountsWithoutAFault() {
        install(SkipProbe.class);
        Fault.countCalls();
        card.transmit(cmd(INS_MARK, (byte) 0, (byte) 0));
        assertEquals(2, Fault.calls("SkipProbe.mark"));
        Fault.reset();
        card.transmit(cmd(INS_MARK, (byte) 0, (byte) 0));
        // counting is off after reset
        assertEquals(0, Fault.calls("SkipProbe.mark"));
    }

    @Test
    void armStoreReplacesTheNthPersistentSetShort() {
        install(NvmProbe.class);
        Fault.armStore(1, (short) 0x7777);
        card.transmit(cmd(INS_SET_SHORT, (byte) 0, (byte) 0));
        byte[] r = card.transmit(cmd(INS_READ, (byte) 0, (byte) 0));
        assertEquals(0x77, r[56] & 0xFF);
        assertEquals(0x77, r[57] & 0xFF);

        // only the n-th store is replaced
        card.transmit(cmd(INS_SET_SHORT, (byte) 0, (byte) 0));
        r = card.transmit(cmd(INS_READ, (byte) 0, (byte) 0));
        assertEquals(0x12, r[56] & 0xFF);
        assertEquals(0x34, r[57] & 0xFF);
    }

    @Test
    void armStoreIgnoresTransientTargets() {
        install(NvmProbe.class);
        // INS_SET_SHORT targets the persistent buf: two armed persistent stores on 2
        Fault.armStore(2, (short) 0x7777);
        card.transmit(cmd(INS_SET_SHORT, (byte) 0, (byte) 0));
        byte[] r = card.transmit(cmd(INS_READ, (byte) 0, (byte) 0));
        assertEquals(0x12, r[56] & 0xFF, "first persistent store not armed");
        card.transmit(cmd(INS_SET_SHORT, (byte) 0, (byte) 0));
        r = card.transmit(cmd(INS_READ, (byte) 0, (byte) 0));
        assertEquals(0x77, r[56] & 0xFF);
    }
}
