// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.sim;

import javacard.security.RandomData;

/**
 * The {@link Rng#fix} delegate {@link Memory#randomData} wraps around every engine it hands to
 * instrumented code: unarmed it is a pure pass-through, armed each {@code generateData}/{@code
 * nextBytes} call fills from the block starting at index 0 (cycling inside the call when it is
 * longer than the block). Wrapping unconditionally is what lets arming act on the engines an applet
 * created at install.
 */
final class FixedRandom extends RandomData {

    private final RandomData inner;

    FixedRandom(RandomData inner) {
        this.inner = inner;
    }

    private void fill(byte[] outBuff, short offset, short length) {
        byte[] block = Rng.block();
        if (block == null) {
            inner.generateData(outBuff, offset, length);
            return;
        }
        for (short i = 0; i < length; i++) {
            outBuff[offset + i] = block[i % block.length];
        }
    }

    public void generateData(byte[] outBuff, short offset, short length) {
        fill(outBuff, offset, length);
    }

    public short nextBytes(byte[] outBuff, short offset, short length) {
        fill(outBuff, offset, length);
        return length;
    }

    public void setSeed(byte[] buffer, short offset, short length) {
        inner.setSeed(buffer, offset, length);
    }

    public byte getAlgorithm() {
        return inner.getAlgorithm();
    }
}
