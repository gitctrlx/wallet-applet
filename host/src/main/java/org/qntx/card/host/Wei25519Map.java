// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.host;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * The host map of spec/protocol.md §10.4 from a Wei25519 point {@code W(P) = X(32) ‖ Y(32)} to the
 * RFC 8032 edwards25519 encoding: {@code u = X − A₃}, {@code y = (u−1)·(u+1)⁻¹}, {@code x =
 * c·u·Y⁻¹} (all mod {@code q}), then {@code le32(y)} with bit 255 = {@code x mod 2}.
 */
public final class Wei25519Map {
    private Wei25519Map() {}

    /**
     * The RFC 8032 encoding (32 bytes) of the point whose affine Wei25519 coordinates are {@code
     * wei64}.
     *
     * @throws IllegalArgumentException when {@code wei64} is not a Wei25519 point
     */
    public static byte[] encode(byte[] wei64) {
        if (wei64 == null || wei64.length != 64) {
            throw new IllegalArgumentException("W(P) must be 64 bytes");
        }
        BigInteger x = new BigInteger(1, Arrays.copyOfRange(wei64, 0, 32));
        BigInteger y = new BigInteger(1, Arrays.copyOfRange(wei64, 32, 64));
        if (!Wei25519.onCurve(x, y)) {
            throw new IllegalArgumentException("not a Wei25519 point");
        }
        BigInteger q = Wei25519.Q;
        BigInteger u = x.subtract(Wei25519.A3).mod(q);
        BigInteger ey =
                u.subtract(BigInteger.ONE).multiply(u.add(BigInteger.ONE).modInverse(q)).mod(q);
        BigInteger ex = Wei25519.C.multiply(u).multiply(y.modInverse(q)).mod(q);
        byte[] be = ey.toByteArray();
        int skip = Math.max(0, be.length - 32);
        byte[] out = new byte[32];
        // le32(y): the 32 low big-endian bytes of y, reversed
        for (int i = skip; i < be.length; i++) {
            out[be.length - 1 - i] = be[i];
        }
        if (ex.testBit(0)) {
            out[31] |= (byte) 0x80;
        }
        return out;
    }
}
