/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.util.Random;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

/**
 * Randomised correctness tests for {@link Field25519}, oracle-checked against {@link BigInteger}.
 *
 * <p>Every operation is run on freshly drawn 32-byte field elements, the in-applet result is
 * compared byte-for-byte with the equivalent {@code BigInteger} computation modulo {@code p =
 * 2²⁵⁵ − 19}, and a small number of fixed edge cases (zero, one, {@code p − 1}) are exercised
 * separately. Inversion is correctness-checked by the round-trip identity
 * {@code a · a⁻¹ ≡ 1 (mod p)}.
 */
class Field25519Test {

    private static final BigInteger P = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));
    private static final Random RNG = new Random(0xCAFEBABEL);

    private final byte[] out = new byte[Field25519.LEN];
    private final byte[] scratch = new byte[Field25519.SCRATCH_LEN];

    private static byte[] randomElement() {
        byte[] raw = new byte[64];
        RNG.nextBytes(raw);
        BigInteger v = new BigInteger(1, raw).mod(P);
        return toBytes(v);
    }

    private static byte[] toBytes(BigInteger v) {
        byte[] full = v.toByteArray();
        byte[] out = new byte[Field25519.LEN];
        if (full.length > Field25519.LEN) {
            System.arraycopy(full, full.length - Field25519.LEN, out, 0, Field25519.LEN);
        } else {
            System.arraycopy(full, 0, out, Field25519.LEN - full.length, full.length);
        }
        return out;
    }

    private static BigInteger toBig(byte[] buf) {
        return new BigInteger(1, buf);
    }

    @Nested
    @DisplayName("Constants and trivial helpers")
    class Constants {

        @Test
        @DisplayName("FIELD_P encodes 2²⁵⁵ − 19")
        void fieldPMatches() {
            assertEquals(P, toBig(Field25519.FIELD_P));
        }

        @Test
        @DisplayName("zero / one / isZero / isOdd")
        void trivialHelpers() {
            byte[] z = new byte[Field25519.LEN];
            Field25519.zero(z, (short) 0);
            assertTrue(Field25519.isZero(z, (short) 0));
            assertFalse(Field25519.isOdd(z, (short) 0));

            byte[] o = new byte[Field25519.LEN];
            Field25519.one(o, (short) 0);
            assertEquals(BigInteger.ONE, toBig(o));
            assertFalse(Field25519.isZero(o, (short) 0));
            assertTrue(Field25519.isOdd(o, (short) 0));

            byte[] two = toBytes(BigInteger.valueOf(2));
            assertFalse(Field25519.isOdd(two, (short) 0));
        }
    }

    @Nested
    @DisplayName("add / sub / neg")
    class AddSubNeg {

        @RepeatedTest(40)
        @DisplayName("(a + b) mod p matches BigInteger")
        void randomAdd() {
            byte[] a = randomElement();
            byte[] b = randomElement();
            Field25519.add(a, (short) 0, b, (short) 0, out, (short) 0);
            BigInteger expected = toBig(a).add(toBig(b)).mod(P);
            assertArrayEquals(toBytes(expected), out);
        }

        @RepeatedTest(40)
        @DisplayName("(a − b) mod p matches BigInteger")
        void randomSub() {
            byte[] a = randomElement();
            byte[] b = randomElement();
            Field25519.sub(a, (short) 0, b, (short) 0, out, (short) 0);
            BigInteger expected = toBig(a).subtract(toBig(b)).mod(P);
            assertArrayEquals(toBytes(expected), out);
        }

        @RepeatedTest(40)
        @DisplayName("(−a) mod p matches BigInteger")
        void randomNeg() {
            byte[] a = randomElement();
            Field25519.neg(a, (short) 0, out, (short) 0);
            BigInteger expected = toBig(a).negate().mod(P);
            assertArrayEquals(toBytes(expected), out);
        }

        @Test
        @DisplayName("Edge cases: 0, 1, p−1 across all unary / binary ops")
        void edgeCases() {
            byte[] zero = new byte[Field25519.LEN];
            byte[] one = toBytes(BigInteger.ONE);
            byte[] pMinus1 = toBytes(P.subtract(BigInteger.ONE));

            // 0 + 0 = 0
            Field25519.add(zero, (short) 0, zero, (short) 0, out, (short) 0);
            assertArrayEquals(zero, out);

            // 1 + (p−1) = 0 (mod p)
            Field25519.add(one, (short) 0, pMinus1, (short) 0, out, (short) 0);
            assertArrayEquals(zero, out);

            // 0 − 1 = p−1
            Field25519.sub(zero, (short) 0, one, (short) 0, out, (short) 0);
            assertArrayEquals(pMinus1, out);

            // −0 = 0 (canonical: not p)
            Field25519.neg(zero, (short) 0, out, (short) 0);
            assertArrayEquals(zero, out);

            // −1 = p−1
            Field25519.neg(one, (short) 0, out, (short) 0);
            assertArrayEquals(pMinus1, out);
        }

        @Test
        @DisplayName("Output may alias either input in add / sub / neg")
        void aliasing() {
            byte[] a = randomElement();
            byte[] b = randomElement();
            BigInteger expected = toBig(a).add(toBig(b)).mod(P);
            byte[] aCopy = a.clone();
            Field25519.add(aCopy, (short) 0, b, (short) 0, aCopy, (short) 0);
            assertArrayEquals(toBytes(expected), aCopy);

            BigInteger expectedSub = toBig(a).subtract(toBig(b)).mod(P);
            byte[] bCopy = b.clone();
            Field25519.sub(a, (short) 0, bCopy, (short) 0, bCopy, (short) 0);
            assertArrayEquals(toBytes(expectedSub), bCopy);

            BigInteger expectedNeg = toBig(a).negate().mod(P);
            byte[] aCopy2 = a.clone();
            Field25519.neg(aCopy2, (short) 0, aCopy2, (short) 0);
            assertArrayEquals(toBytes(expectedNeg), aCopy2);
        }
    }

    @Nested
    @DisplayName("mul / sqr")
    class MulSqr {

        @RepeatedTest(80)
        @DisplayName("(a · b) mod p matches BigInteger")
        void randomMul() {
            byte[] a = randomElement();
            byte[] b = randomElement();
            Field25519.mul(a, (short) 0, b, (short) 0, out, (short) 0, scratch, (short) 0);
            BigInteger expected = toBig(a).multiply(toBig(b)).mod(P);
            assertArrayEquals(toBytes(expected), out);
        }

        @RepeatedTest(80)
        @DisplayName("(a · a) mod p == sqr(a) matches BigInteger")
        void randomSqr() {
            byte[] a = randomElement();
            Field25519.sqr(a, (short) 0, out, (short) 0, scratch, (short) 0);
            BigInteger expected = toBig(a).multiply(toBig(a)).mod(P);
            assertArrayEquals(toBytes(expected), out);
        }

        @Test
        @DisplayName("0 · x = 0 and 1 · x = x")
        void mulIdentities() {
            byte[] zero = new byte[Field25519.LEN];
            byte[] one = toBytes(BigInteger.ONE);
            byte[] a = randomElement();

            Field25519.mul(zero, (short) 0, a, (short) 0, out, (short) 0, scratch, (short) 0);
            assertArrayEquals(zero, out);

            Field25519.mul(one, (short) 0, a, (short) 0, out, (short) 0, scratch, (short) 0);
            assertArrayEquals(a, out);
        }

        @Test
        @DisplayName("(p−1) · (p−1) = 1 (mod p)")
        void mulPMinus1Squared() {
            byte[] pMinus1 = toBytes(P.subtract(BigInteger.ONE));
            byte[] one = toBytes(BigInteger.ONE);
            Field25519.mul(pMinus1, (short) 0, pMinus1, (short) 0, out, (short) 0, scratch, (short) 0);
            assertArrayEquals(one, out);
        }

        @Test
        @DisplayName("Output may alias either input in mul")
        void mulAliasing() {
            byte[] a = randomElement();
            byte[] b = randomElement();
            BigInteger expected = toBig(a).multiply(toBig(b)).mod(P);
            byte[] aCopy = a.clone();
            Field25519.mul(aCopy, (short) 0, b, (short) 0, aCopy, (short) 0, scratch, (short) 0);
            assertArrayEquals(toBytes(expected), aCopy);
        }
    }

    @Nested
    @DisplayName("inv")
    class Inv {

        @RepeatedTest(20)
        @DisplayName("a · a⁻¹ ≡ 1 (mod p)")
        void invRoundTrip() {
            byte[] a;
            do {
                a = randomElement();
            } while (Field25519.isZero(a, (short) 0));
            byte[] inv = new byte[Field25519.LEN];
            Field25519.inv(a, (short) 0, inv, (short) 0, scratch, (short) 0);
            Field25519.mul(a, (short) 0, inv, (short) 0, out, (short) 0, scratch, (short) 0);
            byte[] one = toBytes(BigInteger.ONE);
            assertArrayEquals(one, out);
        }

        @Test
        @DisplayName("inv(1) = 1, inv(p−1) = p−1")
        void invSelfInverses() {
            byte[] one = toBytes(BigInteger.ONE);
            Field25519.inv(one, (short) 0, out, (short) 0, scratch, (short) 0);
            assertArrayEquals(one, out);

            byte[] pMinus1 = toBytes(P.subtract(BigInteger.ONE));
            Field25519.inv(pMinus1, (short) 0, out, (short) 0, scratch, (short) 0);
            assertArrayEquals(pMinus1, out);
        }
    }
}
