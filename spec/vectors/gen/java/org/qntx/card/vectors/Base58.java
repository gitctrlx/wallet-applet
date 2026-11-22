// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: MIT OR Apache-2.0
package org.qntx.card.vectors;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Base58Check (BIP-32 extended keys): the 78-byte payload behind an {@code xprv}/{@code xpub}
 * string, verified against its 4-byte double-SHA-256 checksum.
 */
final class Base58 {
    private static final String ALPHABET =
            "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    private Base58() {}

    static byte[] decodeCheck(String s) {
        byte[] raw = decode(s);
        if (raw.length != 82) {
            throw new IllegalArgumentException("extended key must decode to 82 bytes");
        }
        byte[] sum = Crypto.sha256(Crypto.sha256(Arrays.copyOf(raw, 78)));
        if (!Arrays.equals(Arrays.copyOfRange(raw, 78, 82), Arrays.copyOf(sum, 4))) {
            throw new IllegalArgumentException("Base58Check checksum mismatch");
        }
        return Arrays.copyOf(raw, 78);
    }

    private static byte[] decode(String s) {
        BigInteger v = BigInteger.ZERO;
        for (int i = 0; i < s.length(); i++) {
            int d = ALPHABET.indexOf(s.charAt(i));
            if (d < 0) {
                throw new IllegalArgumentException("not base58: " + s.charAt(i));
            }
            v = v.multiply(BigInteger.valueOf(58)).add(BigInteger.valueOf(d));
        }
        int zeros = 0;
        while (zeros < s.length() && s.charAt(zeros) == '1') {
            zeros++;
        }
        byte[] b = v.toByteArray();
        int skip = b.length > 0 && b[0] == 0 ? 1 : 0;
        byte[] out = new byte[zeros + b.length - skip];
        System.arraycopy(b, skip, out, zeros, b.length - skip);
        return out;
    }
}
