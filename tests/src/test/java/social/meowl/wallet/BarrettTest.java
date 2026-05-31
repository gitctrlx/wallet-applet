/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.wallet;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.math.BigInteger;
import java.util.Random;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Differential test for {@link Barrett} against the secp256k1 group order {@code n} and the Ed25519
 * prime subgroup order {@code ℓ}. Replaces the v1 {@code BarrettN} / {@code BarrettL} fixture trio
 * with a single shared kernel pinned by 200+ random reductions per modulus plus the boundary cases
 * {@code 0}, {@code m − 1}, {@code 2m − 1} and {@code 2⁵¹² − 1}.
 */
class BarrettTest {

    private static final short LEN = 32;
    private static final short DIVIDEND_LEN = 64;
    private static final BigInteger TWO_TO_512 = BigInteger.ONE.shiftLeft(512);
    private static final Random RNG = new Random(0xDEADBEEF);

    private static byte[] beBytes(BigInteger value, int len) {
        byte[] raw = value.toByteArray();
        byte[] out = new byte[len];
        if (raw.length <= len) {
            System.arraycopy(raw, 0, out, len - raw.length, raw.length);
        } else {
            System.arraycopy(raw, raw.length - len, out, 0, len);
        }
        return out;
    }

    private static void roundTrip(Barrett reducer, BigInteger m, BigInteger x) {
        byte[] xBytes = beBytes(x.mod(TWO_TO_512), DIVIDEND_LEN);
        byte[] scratch = new byte[Barrett.SCRATCH_LEN];
        byte[] out = new byte[LEN];
        reducer.reduce(xBytes, (short) 0, scratch, (short) 0, out, (short) 0);
        BigInteger expected = x.mod(TWO_TO_512).mod(m);
        assertArrayEquals(beBytes(expected, LEN), out);
    }

    @Test
    @DisplayName("Barrett mod n: 200 random 512-bit dividends + boundary cases")
    void modSecp256k1Order() {
        Barrett reducer = new Barrett(Secp256k1Curve.N, (short) 0, Secp256k1Curve.MU_N, (short) 0);
        BigInteger n = new BigInteger(1, Secp256k1Curve.N);

        roundTrip(reducer, n, BigInteger.ZERO);
        roundTrip(reducer, n, BigInteger.ONE);
        roundTrip(reducer, n, n.subtract(BigInteger.ONE));
        roundTrip(reducer, n, n);
        roundTrip(reducer, n, n.shiftLeft(1).subtract(BigInteger.ONE));
        roundTrip(reducer, n, TWO_TO_512.subtract(BigInteger.ONE));

        for (int i = 0; i < 200; i++) {
            roundTrip(reducer, n, new BigInteger(512, RNG));
        }
    }

    @Test
    @DisplayName("Barrett mod ℓ: 200 random 512-bit dividends + boundary cases")
    void modEd25519Order() {
        Barrett reducer = new Barrett(Wei25519.L, (short) 0, Wei25519.MU_L, (short) 0);
        BigInteger l = new BigInteger(1, Wei25519.L);

        roundTrip(reducer, l, BigInteger.ZERO);
        roundTrip(reducer, l, BigInteger.ONE);
        roundTrip(reducer, l, l.subtract(BigInteger.ONE));
        roundTrip(reducer, l, l);
        roundTrip(reducer, l, l.shiftLeft(1).subtract(BigInteger.ONE));
        roundTrip(reducer, l, TWO_TO_512.subtract(BigInteger.ONE));

        for (int i = 0; i < 200; i++) {
            roundTrip(reducer, l, new BigInteger(512, RNG));
        }
    }
}
