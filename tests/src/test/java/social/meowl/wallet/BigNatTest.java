/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.wallet;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.util.Random;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Differential and edge-case tests for {@link BigNat}. Java's {@link BigInteger} is the oracle for
 * every arithmetic primitive; mask-driven helpers are pinned against their two extreme masks
 * ({@code 0} and {@code -1}) and a few hand-rolled inputs.
 */
class BigNatTest {

    private static final short LEN = 32;
    private static final Random RNG = new Random(0xC0FFEE);

    private static byte[] beBytes(BigInteger value) {
        byte[] raw = value.toByteArray();
        if (raw.length == LEN) {
            return raw;
        }
        byte[] out = new byte[LEN];
        if (raw.length < LEN) {
            System.arraycopy(raw, 0, out, LEN - raw.length, raw.length);
        } else {
            System.arraycopy(raw, raw.length - LEN, out, 0, LEN);
        }
        return out;
    }

    private static BigInteger bigInt(byte[] bytes) {
        return new BigInteger(1, bytes);
    }

    private static byte[] randomScalar() {
        byte[] out = new byte[LEN];
        RNG.nextBytes(out);
        return out;
    }

    @Nested
    @DisplayName("add / sub vs BigInteger oracle")
    class AddSub {

        @Test
        @DisplayName("100 random 32-byte add pairs match BigInteger arithmetic")
        void addMatchesOracle() {
            for (int i = 0; i < 100; i++) {
                byte[] a = randomScalar();
                byte[] b = randomScalar();
                byte[] aCopy = a.clone();

                boolean carry = BigNat.add(aCopy, (short) 0, b, (short) 0, LEN);

                BigInteger sum = bigInt(a).add(bigInt(b));
                BigInteger truncated = sum.mod(BigInteger.ONE.shiftLeft(256));
                boolean expectedCarry = sum.shiftRight(256).signum() != 0;

                assertEquals(expectedCarry, carry, "carry flag mismatch");
                assertArrayEquals(beBytes(truncated), aCopy);
            }
        }

        @Test
        @DisplayName("100 random 32-byte sub pairs match BigInteger arithmetic")
        void subMatchesOracle() {
            for (int i = 0; i < 100; i++) {
                byte[] a = randomScalar();
                byte[] b = randomScalar();
                byte[] aCopy = a.clone();

                boolean borrow = BigNat.sub(aCopy, (short) 0, b, (short) 0, LEN);

                BigInteger diff = bigInt(a).subtract(bigInt(b));
                BigInteger wrap =
                        diff.add(BigInteger.ONE.shiftLeft(256)).mod(BigInteger.ONE.shiftLeft(256));
                boolean expectedBorrow = diff.signum() < 0;

                assertEquals(expectedBorrow, borrow, "borrow flag mismatch");
                assertArrayEquals(beBytes(wrap), aCopy);
            }
        }
    }

    @Nested
    @DisplayName("mult / multAsymmetric vs BigInteger oracle")
    class Multiplication {

        @Test
        @DisplayName("50 random 32×32 multiplications produce the 64-byte product")
        void multMatchesOracle() {
            for (int i = 0; i < 50; i++) {
                byte[] a = randomScalar();
                byte[] b = randomScalar();
                byte[] product = new byte[64];

                BigNat.multAsymmetric(a, (short) 0, LEN, b, (short) 0, LEN, product, (short) 0);

                BigInteger expected = bigInt(a).multiply(bigInt(b));
                byte[] expectedBytes = new byte[64];
                byte[] raw = expected.toByteArray();
                if (raw.length <= 64) {
                    System.arraycopy(raw, 0, expectedBytes, 64 - raw.length, raw.length);
                } else {
                    System.arraycopy(raw, raw.length - 64, expectedBytes, 0, 64);
                }
                assertArrayEquals(expectedBytes, product);
            }
        }

        @Test
        @DisplayName("multAsymmetric handles 33×32 widths used by Barrett step 5")
        void asymmetricMatchesOracle() {
            byte[] x = new byte[33];
            byte[] y = new byte[32];
            RNG.nextBytes(x);
            RNG.nextBytes(y);
            byte[] product = new byte[65];

            BigNat.multAsymmetric(
                    x, (short) 0, (short) 33, y, (short) 0, (short) 32, product, (short) 0);

            BigInteger expected = new BigInteger(1, x).multiply(new BigInteger(1, y));
            byte[] expectedBytes = new byte[65];
            byte[] raw = expected.toByteArray();
            int copyLen = Math.min(raw.length, 65);
            System.arraycopy(raw, raw.length - copyLen, expectedBytes, 65 - copyLen, copyLen);
            assertArrayEquals(expectedBytes, product);
        }
    }

    @Nested
    @DisplayName("constant-time predicates return the canonical mask")
    class CtPredicates {

        @Test
        @DisplayName("ctLessThan returns -1 iff x < y")
        void ctLessThan() {
            byte[] zero = new byte[LEN];
            byte[] one = new byte[LEN];
            one[LEN - 1] = 1;
            byte[] max = new byte[LEN];
            for (int i = 0; i < LEN; i++) {
                max[i] = (byte) 0xFF;
            }
            assertEquals((short) -1, BigNat.ctLessThan(zero, (short) 0, one, (short) 0, LEN));
            assertEquals((short) 0, BigNat.ctLessThan(one, (short) 0, zero, (short) 0, LEN));
            assertEquals((short) 0, BigNat.ctLessThan(one, (short) 0, one, (short) 0, LEN));
            assertEquals((short) -1, BigNat.ctLessThan(zero, (short) 0, max, (short) 0, LEN));
            assertEquals((short) 0, BigNat.ctLessThan(max, (short) 0, zero, (short) 0, LEN));
        }

        @Test
        @DisplayName("ctIsZero / ctEquals agree on canonical inputs")
        void ctZero() {
            byte[] zero = new byte[LEN];
            byte[] one = new byte[LEN];
            one[LEN - 1] = 1;
            assertEquals((short) -1, BigNat.ctIsZero(zero, (short) 0, LEN));
            assertEquals((short) 0, BigNat.ctIsZero(one, (short) 0, LEN));
            assertTrue(BigNat.ctEquals(zero, (short) 0, zero, (short) 0, LEN));
            assertFalse(BigNat.ctEquals(zero, (short) 0, one, (short) 0, LEN));
        }
    }

    @Nested
    @DisplayName("mask-driven mutations are gated by the mask byte")
    class CondMutations {

        @Test
        @DisplayName("ctSelectSub with mask -1 subtracts; with mask 0 is a no-op")
        void ctSelectSub() {
            byte[] x = randomScalar();
            byte[] y = randomScalar();

            byte[] subbed = x.clone();
            BigNat.ctSelectSub(subbed, (short) 0, y, (short) 0, LEN, (short) -1);
            BigInteger expected = bigInt(x).subtract(bigInt(y));
            BigInteger wrap =
                    expected.add(BigInteger.ONE.shiftLeft(256)).mod(BigInteger.ONE.shiftLeft(256));
            assertArrayEquals(beBytes(wrap), subbed);

            byte[] untouched = x.clone();
            BigNat.ctSelectSub(untouched, (short) 0, y, (short) 0, LEN, (short) 0);
            assertArrayEquals(x, untouched);
        }

        @Test
        @DisplayName(
                "ctSelectNeg with mask -1 produces (m − a); zero corner is masked back to"
                        + " zero by neg")
        void ctSelectNeg() {
            byte[] m = Secp256k1Curve.N;
            for (int i = 0; i < 20; i++) {
                BigInteger aValue;
                do {
                    aValue = new BigInteger(255, RNG);
                } while (aValue.signum() == 0 || aValue.compareTo(new BigInteger(1, m)) >= 0);
                byte[] a = beBytes(aValue);

                byte[] negated = a.clone();
                BigNat.ctSelectNeg(negated, (short) 0, m, (short) 0, LEN, (short) -1);
                BigInteger expected = new BigInteger(1, m).subtract(aValue);
                assertArrayEquals(beBytes(expected), negated);

                byte[] kept = a.clone();
                BigNat.ctSelectNeg(kept, (short) 0, m, (short) 0, LEN, (short) 0);
                assertArrayEquals(a, kept);
            }
        }
    }

    @Nested
    @DisplayName("modAdd / modSub match BigInteger.mod arithmetic")
    class ModAddSub {

        @ParameterizedTest
        @ValueSource(
                strings = {
                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
                    "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED"
                })
        @DisplayName("modAdd matches (a + b) mod m for 50 random pairs")
        void modAddMatchesOracle(String hex) {
            BigInteger m = new BigInteger(hex, 16);
            byte[] mBytes = beBytes(m);
            for (int i = 0; i < 50; i++) {
                BigInteger a = new BigInteger(255, RNG).mod(m);
                BigInteger b = new BigInteger(255, RNG).mod(m);
                byte[] out = new byte[LEN];
                BigNat.modAdd(
                        beBytes(a),
                        (short) 0,
                        beBytes(b),
                        (short) 0,
                        mBytes,
                        (short) 0,
                        out,
                        (short) 0,
                        LEN);
                assertArrayEquals(beBytes(a.add(b).mod(m)), out);
            }
        }

        @ParameterizedTest
        @ValueSource(
                strings = {
                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
                    "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED"
                })
        @DisplayName("modSub matches (a − b) mod m for 50 random pairs")
        void modSubMatchesOracle(String hex) {
            BigInteger m = new BigInteger(hex, 16);
            byte[] mBytes = beBytes(m);
            for (int i = 0; i < 50; i++) {
                BigInteger a = new BigInteger(255, RNG).mod(m);
                BigInteger b = new BigInteger(255, RNG).mod(m);
                byte[] out = new byte[LEN];
                BigNat.modSub(
                        beBytes(a),
                        (short) 0,
                        beBytes(b),
                        (short) 0,
                        mBytes,
                        (short) 0,
                        out,
                        (short) 0,
                        LEN);
                assertArrayEquals(beBytes(a.subtract(b).mod(m)), out);
            }
        }
    }
}
