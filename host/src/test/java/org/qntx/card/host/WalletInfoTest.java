// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.host;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;
import org.junit.jupiter.api.Test;

/** {@link WalletInfo#parse} against the §9.2 wire form: masterPublicKey ‖ origin ‖ c ‖ IDs. */
final class WalletInfoTest {

    @Test
    void parsesValidInfo() {
        byte[] data = new byte[35 + 32];
        data[0] = 0x02;
        data[1] = 0x11;
        data[33] = 0x02;
        data[34] = 0x02;
        data[35] = 0x55;
        data[51] = 0x66;
        WalletInfo info = WalletInfo.parse(data);
        assertArrayEquals(java.util.Arrays.copyOf(data, 33), info.masterPublicKey());
        assertEquals(2, info.origin());
        assertEquals(2, info.members().size());
        assertEquals((byte) 0x55, info.members().get(0)[0]);
        assertEquals((byte) 0x66, info.members().get(1)[0]);
    }

    @Test
    void rejectsMalformed() {
        byte[] good = new byte[35 + 16];
        good[0] = 0x03;
        good[33] = 0x01;
        good[34] = 0x01;
        List<byte[]> bad =
                List.of(
                        new byte[0],
                        java.util.Arrays.copyOf(good, 34), // too short for c = 1
                        java.util.Arrays.copyOf(good, 52), // trailing byte
                        mutate(good, 34, (byte) 0), // c = 0
                        mutate(good, 34, (byte) 4), // c = 4
                        mutate(good, 33, (byte) 0), // origin 0
                        mutate(good, 33, (byte) 3), // origin 3
                        mutate(good, 0, (byte) 0x04)); // uncompressed prefix
        for (byte[] b : bad) {
            assertThrows(IllegalArgumentException.class, () -> WalletInfo.parse(b));
        }
    }

    private static byte[] mutate(byte[] data, int off, byte v) {
        byte[] out = data.clone();
        out[off] = v;
        return out;
    }
}
