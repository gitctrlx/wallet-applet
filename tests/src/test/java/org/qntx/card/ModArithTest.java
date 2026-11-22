// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import org.junit.jupiter.api.Test;
import org.qntx.card.host.Crypto;
import org.qntx.card.sim.Card;
import org.qntx.card.tests.Spec;
import org.qntx.card.tests.Vecs;

/**
 * {@link ModArith} against {@link BigInteger} modulo the secp256k1 field prime: edge cases plus
 * 100,000 random mul/square rounds (the count is reported as evidence).
 */
final class ModArithTest {
    static final int RANDOM_ROUNDS = 100_000;
    private static final SecureRandom RND = new SecureRandom();
    private static final BigInteger P = Crypto.DOMAIN.getCurve().getField().getCharacteristic();

    private static ModArith modArith() {
        Card card = Vecs.factory();
        return Internals.modArith(card.applet(Spec.WALLET_AID));
    }

    private static byte[] toBytes(BigInteger v) {
        byte[] b = v.toByteArray();
        byte[] out = new byte[32];
        System.arraycopy(
                b,
                Math.max(0, b.length - 32),
                out,
                Math.max(0, 32 - b.length),
                Math.min(32, b.length));
        return out;
    }

    private static BigInteger of(byte[] x) {
        return new BigInteger(1, x);
    }

    @Test
    void randomMulSquareAddSubHalf() {
        ModArith m = modArith();
        byte[] a = new byte[32];
        byte[] b = new byte[32];
        byte[] out = new byte[32];
        int rounds = RANDOM_ROUNDS;
        for (int i = 0; i < rounds; i++) {
            RND.nextBytes(a);
            RND.nextBytes(b);
            BigInteger va = of(a).mod(P);
            BigInteger vb = of(b).mod(P);
            // reduce the operands below p first: ModArith requires inputs < p
            a = toBytes(va);
            b = toBytes(vb);
            Arrays.fill(out, (byte) 0xAA);
            m.mul(a, (short) 0, b, (short) 0, out, (short) 0);
            assertArrayEquals(toBytes(va.multiply(vb).mod(P)), out, "mul round " + i);
            Arrays.fill(out, (byte) 0xAA);
            m.square(a, (short) 0, out, (short) 0);
            assertArrayEquals(toBytes(va.multiply(va).mod(P)), out, "square round " + i);
            Arrays.fill(out, (byte) 0xAA);
            m.addMod(a, (short) 0, b, (short) 0, out, (short) 0);
            assertArrayEquals(toBytes(va.add(vb).mod(P)), out, "addMod round " + i);
            Arrays.fill(out, (byte) 0xAA);
            m.subMod(a, (short) 0, b, (short) 0, out, (short) 0);
            assertArrayEquals(toBytes(va.subtract(vb).mod(P)), out, "subMod round " + i);
            Arrays.fill(out, (byte) 0xAA);
            m.half(a, (short) 0, out, (short) 0);
            assertArrayEquals(
                    toBytes(va.multiply(BigInteger.TWO.modInverse(P)).mod(P)),
                    out,
                    "half round " + i);
        }
        System.out.println("ModArith random rounds: " + rounds + " x 5 ops");
    }

    @Test
    void edgeOperands() {
        ModArith m = modArith();
        byte[] out = new byte[32];
        byte[][] edges = {
            new byte[32],
            toBytes(BigInteger.ONE),
            toBytes(P.subtract(BigInteger.ONE)),
            toBytes(P.subtract(BigInteger.TWO)),
            toBytes(P.shiftRight(1)),
        };
        for (byte[] a : edges) {
            for (byte[] b : edges) {
                BigInteger va = of(a);
                BigInteger vb = of(b);
                m.mul(a, (short) 0, b, (short) 0, out, (short) 0);
                assertArrayEquals(toBytes(va.multiply(vb).mod(P)), out);
                m.square(a, (short) 0, out, (short) 0);
                assertArrayEquals(toBytes(va.multiply(va).mod(P)), out);
                m.addMod(a, (short) 0, b, (short) 0, out, (short) 0);
                assertArrayEquals(toBytes(va.add(vb).mod(P)), out);
                m.subMod(a, (short) 0, b, (short) 0, out, (short) 0);
                assertArrayEquals(toBytes(va.subtract(vb).mod(P)), out);
            }
        }
    }
}
