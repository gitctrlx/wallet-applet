// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.sim;

import javacard.security.MessageDigest;

/**
 * A {@link MessageDigest} that delegates every method and reports {@code update}/{@code doFinal}
 * input bytes and {@code doFinal} calls to the bound {@link CardRuntime} (architecture spec section
 * 8, patch 6). {@link Memory#messageDigest} wraps the engines it hands to instrumented code, so a
 * command's digest calls are counted per algorithm and per command.
 */
final class CountingDigest extends MessageDigest {

    private final MessageDigest inner;
    private final byte algorithm;

    CountingDigest(byte algorithm, MessageDigest inner) {
        this.algorithm = algorithm;
        this.inner = inner;
    }

    public byte getAlgorithm() {
        return inner.getAlgorithm();
    }

    public byte getLength() {
        return inner.getLength();
    }

    public void update(byte[] inBuff, short inOffset, short inLength) {
        inner.update(inBuff, inOffset, inLength);
        CardRuntime rt = CardRuntime.current();
        if (rt != null) {
            rt.digest(algorithm, inLength, false);
        }
    }

    public short doFinal(
            byte[] inBuff, short inOffset, short inLength, byte[] outBuff, short outOffset) {
        short len = inner.doFinal(inBuff, inOffset, inLength, outBuff, outOffset);
        CardRuntime rt = CardRuntime.current();
        if (rt != null) {
            rt.digest(algorithm, inLength, true);
        }
        return len;
    }

    public void reset() {
        inner.reset();
    }
}
