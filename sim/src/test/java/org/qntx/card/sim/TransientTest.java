// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.sim;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import javacard.framework.ISO7816;
import javacard.framework.SystemException;
import org.junit.jupiter.api.Test;
import org.qntx.card.sim.probe.MemProbe;

/**
 * Measured transient-pool accounting (architecture section 8 patch 6, audit-impl memory.out): the
 * probe's install mix charges 1082 B of the shared 3990 B pool, getAvailableMemory reports 3990 -
 * used on both transient types, oversize allocations fail with NO_TRANSIENT_SPACE, and engines or
 * keys card A does not carry fail loudly.
 */
class TransientTest {

    private static final byte[] AID = {0x05, 0x02, 0x03, 0x04, 0x05};
    private static final byte INS_REPORT = 0x10;
    private static final byte INS_ALLOC = 0x11;
    private static final byte INS_UNMEASURED = 0x12;

    // 100 + 100 + 30 + 20 arrays, 272 + 32 transient keys, 48 + 32 +
    // 112 + 128 + 208 engines, three 0-charge engines
    private static final int INSTALL_USED = 1082;

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

    private static byte[] data(byte[] response) {
        return Arrays.copyOf(response, response.length - 2);
    }

    private static void assertSw(byte[] response, int expected) {
        assertEquals(
                (short) expected,
                sw(response),
                () -> "SW 0x" + Integer.toHexString(sw(response) & 0xFFFF));
    }

    private static int getShort(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }

    private Card installed() {
        Card card = new Card();
        card.install(AID, MemProbe.class);
        card.transmit(selectApdu(AID));
        return card;
    }

    @Test
    void installMixChargesTheMeasuredTable() {
        Card card = installed();
        assertEquals(INSTALL_USED, card.transientUsed());
        byte[] report = data(card.transmit(cmd(INS_REPORT, (byte) 0, (byte) 0)));
        assertEquals(3990 - INSTALL_USED, getShort(report, 0), "deselect pool");
        assertEquals(3990 - INSTALL_USED, getShort(report, 2), "reset pool");
    }

    @Test
    void memoryReportListsEveryAllocation() {
        Card card = installed();
        String report = card.memoryReport();
        assertTrue(report.contains("transient byte[100] 100"), report);
        assertTrue(report.contains("transient short[50] 100"), report);
        assertTrue(report.contains("transient boolean[30] 30"), report);
        assertTrue(report.contains("transient Object[10] 20"), report);
        assertTrue(report.contains("EC FP private transient 256 272"), report);
        assertTrue(report.contains("AES transient 128 32"), report);
        assertTrue(report.contains("cipher algorithm 13 48"), report);
        assertTrue(report.contains("signature algorithm 49 32"), report);
        assertTrue(report.contains("signature algorithm 33 112"), report);
        assertTrue(report.contains("digest algorithm 4 128"), report);
        assertTrue(report.contains("digest algorithm 6 208"), report);
        assertTrue(report.contains("agreement algorithm 6 0"), report);
        assertTrue(report.contains("agreement algorithm 5 0"), report);
        assertTrue(report.contains("random algorithm 6 0"), report);
        assertTrue(report.contains("total " + INSTALL_USED + " / 3990 (budget 3390)"), report);
    }

    @Test
    void commandAllocationChargesAndReflectsInAvailable() {
        Card card = installed();
        assertSw(card.transmit(cmd(INS_ALLOC, (byte) 0, (byte) 200)), 0x9000);
        assertEquals(INSTALL_USED + 200, card.transientUsed());
        byte[] report = data(card.transmit(cmd(INS_REPORT, (byte) 0, (byte) 0)));
        assertEquals(3990 - INSTALL_USED - 200, getShort(report, 0));
    }

    @Test
    void allocationBeyondPoolFails() {
        Card card = installed();
        assertSw(card.transmit(cmd(INS_ALLOC, (byte) 0, (byte) 200)), 0x9000);
        // 1282 + 2712 > 3990: NO_TRANSIENT_SPACE (reason 2) -> 0x6F22
        assertSw(card.transmit(cmd(INS_ALLOC, (byte) 10, (byte) 0x98)), 0x6F22);
        // the failed allocation did not consume pool
        assertEquals(INSTALL_USED + 200, card.transientUsed());
    }

    @Test
    void installBeyondPoolFailsWithNoTransientSpace() {
        Card card = new Card();
        SystemException thrown =
                assertThrows(
                        SystemException.class,
                        () -> card.install(AID, MemProbe.class, new byte[] {1}));
        assertEquals(SystemException.NO_TRANSIENT_SPACE, thrown.getReason());
    }

    @Test
    void unmeasuredEngineFailsInstall() {
        Card card = new Card();
        assertThrows(
                IllegalStateException.class,
                () -> card.install(AID, MemProbe.class, new byte[] {0, 1}));
    }

    @Test
    void unmeasuredTransientKeyTypeFailsInstall() {
        Card card = new Card();
        assertThrows(
                IllegalStateException.class,
                () -> card.install(AID, MemProbe.class, new byte[] {0, 0, 1}));
    }

    @Test
    void unmeasuredTransientKeySizeFailsInstall() {
        Card card = new Card();
        assertThrows(
                IllegalStateException.class,
                () -> card.install(AID, MemProbe.class, new byte[] {0, 0, 0, 1}));
    }

    @Test
    void unmeasuredEngineFailsInCommand() {
        Card card = installed();
        assertSw(card.transmit(cmd(INS_UNMEASURED, (byte) 0, (byte) 0)), 0x6F43);
    }
}
