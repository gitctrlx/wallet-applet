// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.sim;

import static org.junit.jupiter.api.Assertions.assertEquals;

import javacard.framework.ISO7816;
import javacard.security.MessageDigest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.qntx.card.sim.probe.DigestProbe;

/**
 * {@code Card.digests}/{@code Card.digestBytes}: per-algorithm, per-command counts of {@code
 * doFinal} calls and of the input bytes passed through {@code update} and {@code doFinal}.
 */
final class DigestCountTest {

    private static final byte[] AID = {0x01, 0x02, 0x03, 0x04, 0x07};

    private Card card;

    @BeforeEach
    void setUp() {
        card = new Card();
        card.install(AID, DigestProbe.class);
        byte[] sel = new byte[5 + AID.length];
        sel[ISO7816.OFFSET_INS] = (byte) 0xA4;
        sel[ISO7816.OFFSET_P1] = 0x04;
        sel[ISO7816.OFFSET_LC] = (byte) AID.length;
        System.arraycopy(AID, 0, sel, ISO7816.OFFSET_CDATA, AID.length);
        card.transmit(sel);
    }

    private static byte[] cmd(byte ins, int lc) {
        byte[] apdu = new byte[5 + lc];
        apdu[ISO7816.OFFSET_INS] = ins;
        apdu[ISO7816.OFFSET_LC] = (byte) lc;
        return apdu;
    }

    @Test
    void doFinalCallsAndInputBytesAreCountedPerAlgorithm() {
        card.transmit(cmd((byte) 0x10, 24));
        assertEquals(1, card.digests(MessageDigest.ALG_SHA_256));
        // 16 bytes through update + 8 through doFinal
        assertEquals(24, card.digestBytes(MessageDigest.ALG_SHA_256));
        assertEquals(0, card.digests(MessageDigest.ALG_SHA_512));
    }

    @Test
    void countsArePerCommandAndPerAlgorithm() {
        card.transmit(cmd((byte) 0x11, 24));
        assertEquals(0, card.digests(MessageDigest.ALG_SHA_256));
        assertEquals(1, card.digests(MessageDigest.ALG_SHA_512));
        assertEquals(24, card.digestBytes(MessageDigest.ALG_SHA_512));

        // the next command resets the counters
        card.transmit(cmd((byte) 0x10, 24));
        assertEquals(1, card.digests(MessageDigest.ALG_SHA_256));
        assertEquals(0, card.digests(MessageDigest.ALG_SHA_512));
    }
}
