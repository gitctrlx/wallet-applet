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
import java.security.SecureRandom;
import java.util.Arrays;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

/**
 * Pure-Java tests for the multi-precision {@link Bignat} primitives.
 *
 * <p>Cross-references every operation against the JDK's {@link BigInteger} as the oracle: random
 * 32-byte inputs, repeated 200× per primitive to cover edge cases (small operands, near-modulus
 * values, leading zero limbs, etc.).
 */
class BignatTest {

    private static final SecureRandom RNG = new SecureRandom();
    private static final BigInteger SECP256K1_N =
            new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);

    @RepeatedTest(200)
    @DisplayName("add: 32-byte unsigned addition matches BigInteger")
    void addMatches() {
        byte[] a = randomBytes(32);
        byte[] b = randomBytes(32);
        BigInteger expected = unsigned(a).add(unsigned(b));
        boolean expectedCarry = expected.bitLength() > 256;
        byte[] result = a.clone();
        boolean carry = Bignat.add(result, (short) 0, b, (short) 0, (short) 32);
        assertEquals(expectedCarry, carry, "carry mismatch");
        BigInteger gotMod = unsigned(result);
        BigInteger expectedMod = expected.mod(BigInteger.ONE.shiftLeft(256));
        assertEquals(expectedMod, gotMod);
    }

    @RepeatedTest(200)
    @DisplayName("sub: 32-byte unsigned subtraction matches BigInteger")
    void subMatches() {
        byte[] a = randomBytes(32);
        byte[] b = randomBytes(32);
        BigInteger expected = unsigned(a).subtract(unsigned(b));
        boolean expectedBorrow = expected.signum() < 0;
        byte[] result = a.clone();
        boolean borrow = Bignat.sub(result, (short) 0, b, (short) 0, (short) 32);
        assertEquals(expectedBorrow, borrow);
        BigInteger gotMod = unsigned(result);
        BigInteger expectedMod = expected.mod(BigInteger.ONE.shiftLeft(256));
        assertEquals(expectedMod, gotMod);
    }

    @Test
    @DisplayName("lessThan: strict less-than matches BigInteger.compareTo")
    void lessThanMatches() {
        for (int i = 0; i < 100; i++) {
            byte[] a = randomBytes(32);
            byte[] b = randomBytes(32);
            boolean expected = unsigned(a).compareTo(unsigned(b)) < 0;
            assertEquals(expected, Bignat.lessThan(a, (short) 0, b, (short) 0, (short) 32));
        }
        // Equal case must not be reported as strictly less.
        byte[] x = randomBytes(32);
        assertFalse(Bignat.lessThan(x, (short) 0, x, (short) 0, (short) 32));
    }

    @Test
    @DisplayName("isZero: detects all-zero buffer of any size")
    void isZeroDetects() {
        byte[] z = new byte[64];
        assertTrue(Bignat.isZero(z, (short) 0, (short) 64));
        z[33] = 1;
        assertFalse(Bignat.isZero(z, (short) 0, (short) 64));
        // A nonzero byte outside the [off, off+size) window must not affect the result.
        z[0] = 0x55;
        assertTrue(Bignat.isZero(z, (short) 1, (short) 32));
    }

    @RepeatedTest(200)
    @DisplayName("mult: 32×32 → 64 schoolbook multiplication matches BigInteger")
    void multMatches() {
        byte[] a = randomBytes(32);
        byte[] b = randomBytes(32);
        byte[] z = new byte[64];
        Bignat.mult(a, (short) 0, b, (short) 0, (short) 32, z, (short) 0);
        BigInteger expected = unsigned(a).multiply(unsigned(b));
        BigInteger got = unsigned(z);
        assertEquals(expected, got);
    }

    @RepeatedTest(200)
    @DisplayName("mod: 64-byte dividend mod 32-byte divisor (n) matches BigInteger.mod")
    void modMatches() {
        byte[] dividend = randomBytes(64);
        byte[] divisor = bigIntToFixed(SECP256K1_N, 32);
        byte[] dvCopy = dividend.clone();
        Bignat.mod(dvCopy, (short) 0, (short) 64, divisor, (short) 0, (short) 32);
        // The remainder occupies the last 32 bytes; the leading 32 bytes must be zero.
        byte[] remainder = Arrays.copyOfRange(dvCopy, 32, 64);
        byte[] leadingZeros = Arrays.copyOfRange(dvCopy, 0, 32);
        assertArrayEquals(new byte[32], leadingZeros, "leading bytes must be zeroed");
        BigInteger expected = unsigned(dividend).mod(SECP256K1_N);
        BigInteger got = unsigned(remainder);
        assertEquals(expected, got);
    }

    @Test
    @DisplayName("mod: edge cases — dividend < divisor, dividend == divisor, all zero")
    void modEdgeCases() {
        byte[] divisor = bigIntToFixed(SECP256K1_N, 32);
        // Dividend < divisor → unchanged in the trailing 32 bytes (after the schoolbook walks
        // realise no subtraction is needed).
        byte[] small = new byte[64];
        small[63] = 0x07;
        byte[] expected = small.clone();
        Bignat.mod(small, (short) 0, (short) 64, divisor, (short) 0, (short) 32);
        assertArrayEquals(expected, small, "dividend < divisor must remain unchanged");

        // Dividend == divisor (zero-extended to 64 bytes) → result == 0.
        byte[] eq = new byte[64];
        System.arraycopy(divisor, 0, eq, 32, 32);
        Bignat.mod(eq, (short) 0, (short) 64, divisor, (short) 0, (short) 32);
        assertArrayEquals(new byte[64], eq);

        // All-zero dividend → result == 0.
        byte[] zero = new byte[64];
        Bignat.mod(zero, (short) 0, (short) 64, divisor, (short) 0, (short) 32);
        assertArrayEquals(new byte[64], zero);
    }

    @RepeatedTest(50)
    @DisplayName("mult + mod composition: (e * d) mod n matches BigInteger")
    void multThenModMatches() {
        byte[] e = randomBytes(32);
        byte[] d = randomBytes(32);
        BigInteger expected = unsigned(e).multiply(unsigned(d)).mod(SECP256K1_N);
        byte[] z = new byte[64];
        Bignat.mult(e, (short) 0, d, (short) 0, (short) 32, z, (short) 0);
        byte[] divisor = bigIntToFixed(SECP256K1_N, 32);
        Bignat.mod(z, (short) 0, (short) 64, divisor, (short) 0, (short) 32);
        BigInteger got = unsigned(Arrays.copyOfRange(z, 32, 64));
        assertEquals(expected, got);
    }

    @Test
    @DisplayName("condSubInPlace: mask=0 is a no-op, mask=-1 subtracts")
    void condSubMaskedBranches() {
        byte[] xCopy = bigIntToFixed(BigInteger.valueOf(100), 32);
        byte[] y = bigIntToFixed(BigInteger.valueOf(30), 32);
        byte[] x = xCopy.clone();
        Bignat.condSubInPlace(x, (short) 0, y, (short) 0, (short) 32, (short) 0);
        assertArrayEquals(xCopy, x, "mask=0 must leave x unchanged");
        Bignat.condSubInPlace(x, (short) 0, y, (short) 0, (short) 32, (short) -1);
        assertArrayEquals(bigIntToFixed(BigInteger.valueOf(70), 32), x);
    }

    @Test
    @DisplayName("condSubInPlace: borrow propagates across all 32 byte positions")
    void condSubFullBorrow() {
        byte[] x = new byte[32];
        x[0] = 1;
        byte[] y = new byte[32];
        for (int i = 1; i < 32; i++) {
            y[i] = (byte) 0xFF;
        }
        Bignat.condSubInPlace(x, (short) 0, y, (short) 0, (short) 32, (short) -1);
        byte[] expected = new byte[32];
        expected[31] = 1;
        assertArrayEquals(expected, x, "0x0100…00 − 0x00FF…FF must equal 0x0000…01");
    }

    @RepeatedTest(50)
    @DisplayName("condSubInPlace: mask=-1 matches BigInteger subtraction modulo 2²⁵⁶")
    void condSubRandomized() {
        byte[] x = randomBytes(32);
        byte[] y = randomBytes(32);
        BigInteger expected = unsigned(x).subtract(unsigned(y)).mod(BigInteger.ONE.shiftLeft(256));
        byte[] result = x.clone();
        Bignat.condSubInPlace(result, (short) 0, y, (short) 0, (short) 32, (short) -1);
        assertEquals(expected, unsigned(result));
    }

    @Test
    @DisplayName("condAddInPlace: mask=0 is a no-op, mask=-1 adds")
    void condAddMaskedBranches() {
        byte[] xCopy = bigIntToFixed(BigInteger.valueOf(100), 32);
        byte[] y = bigIntToFixed(BigInteger.valueOf(30), 32);
        byte[] x = xCopy.clone();
        Bignat.condAddInPlace(x, (short) 0, y, (short) 0, (short) 32, (short) 0);
        assertArrayEquals(xCopy, x, "mask=0 must leave x unchanged");
        Bignat.condAddInPlace(x, (short) 0, y, (short) 0, (short) 32, (short) -1);
        assertArrayEquals(bigIntToFixed(BigInteger.valueOf(130), 32), x);
    }

    @Test
    @DisplayName("condAddInPlace: carry propagates from LSB up through every byte")
    void condAddFullCarry() {
        byte[] x = new byte[32];
        for (int i = 0; i < 32; i++) {
            x[i] = (byte) 0xFF;
        }
        byte[] y = new byte[32];
        y[31] = 1;
        Bignat.condAddInPlace(x, (short) 0, y, (short) 0, (short) 32, (short) -1);
        assertArrayEquals(new byte[32], x, "0xFF…FF + 1 mod 2²⁵⁶ must equal 0");
    }

    @RepeatedTest(50)
    @DisplayName("condAddInPlace: mask=-1 matches BigInteger addition modulo 2²⁵⁶")
    void condAddRandomized() {
        byte[] x = randomBytes(32);
        byte[] y = randomBytes(32);
        BigInteger expected = unsigned(x).add(unsigned(y)).mod(BigInteger.ONE.shiftLeft(256));
        byte[] result = x.clone();
        Bignat.condAddInPlace(result, (short) 0, y, (short) 0, (short) 32, (short) -1);
        assertEquals(expected, unsigned(result));
    }

    @Test
    @DisplayName("ctLessThan: three-way verdict (a<b, a==b, a>b)")
    void ctLessThanThreeWay() {
        byte[] one = bigIntToFixed(BigInteger.ONE, 32);
        byte[] two = bigIntToFixed(BigInteger.TWO, 32);
        assertEquals((short) -1, Bignat.ctLessThan(one, (short) 0, two, (short) 0, (short) 32));
        assertEquals((short) 0, Bignat.ctLessThan(two, (short) 0, one, (short) 0, (short) 32));
        assertEquals((short) 0, Bignat.ctLessThan(one, (short) 0, one, (short) 0, (short) 32));
    }

    @Test
    @DisplayName("ctLessThan: most-significant differing byte wins (sticky-mask property)")
    void ctLessThanMsbWins() {
        byte[] a = new byte[32];
        byte[] b = new byte[32];
        a[0] = (byte) 0x01;
        a[1] = (byte) 0xFF;
        b[0] = (byte) 0x02;
        b[1] = (byte) 0x00;
        assertEquals((short) -1, Bignat.ctLessThan(a, (short) 0, b, (short) 0, (short) 32));
    }

    @Test
    @DisplayName("ctLessThan: unsigned semantics — 0xFF is larger than 0x80")
    void ctLessThanUnsignedHighBytes() {
        byte[] a = new byte[32];
        byte[] b = new byte[32];
        a[0] = (byte) 0x80;
        b[0] = (byte) 0xFF;
        assertEquals((short) -1, Bignat.ctLessThan(a, (short) 0, b, (short) 0, (short) 32));
        assertEquals((short) 0, Bignat.ctLessThan(b, (short) 0, a, (short) 0, (short) 32));
    }

    @RepeatedTest(50)
    @DisplayName("ctLessThan: matches BigInteger.compareTo on random 32-byte pairs")
    void ctLessThanRandomized() {
        byte[] a = randomBytes(32);
        byte[] b = randomBytes(32);
        short expected = unsigned(a).compareTo(unsigned(b)) < 0 ? (short) -1 : (short) 0;
        assertEquals(expected, Bignat.ctLessThan(a, (short) 0, b, (short) 0, (short) 32));
    }

    @Test
    @DisplayName("ctIsZero: all-zero buffer returns -1 (0xFFFF mask)")
    void ctIsZeroAllZero() {
        assertEquals((short) -1, Bignat.ctIsZero(new byte[32], (short) 0, (short) 32));
    }

    @Test
    @DisplayName("ctIsZero: non-zero at any of the 32 positions returns 0")
    void ctIsZeroEveryPosition() {
        for (int pos = 0; pos < 32; pos++) {
            byte[] a = new byte[32];
            a[pos] = 1;
            assertEquals(
                    (short) 0,
                    Bignat.ctIsZero(a, (short) 0, (short) 32),
                    "non-zero at position " + pos + " must report non-zero");
        }
    }

    @Test
    @DisplayName("ctIsZero: honours offset — sentinels outside the window are ignored")
    void ctIsZeroOffset() {
        byte[] buf = new byte[64];
        buf[10] = 1;
        assertEquals(
                (short) -1,
                Bignat.ctIsZero(buf, (short) 16, (short) 32),
                "sentinel outside [16, 48) must not influence the verdict");
        buf[20] = 1;
        assertEquals(
                (short) 0,
                Bignat.ctIsZero(buf, (short) 16, (short) 32),
                "sentinel inside the window must flip the verdict");
    }

    private static byte[] randomBytes(int n) {
        byte[] b = new byte[n];
        RNG.nextBytes(b);
        return b;
    }

    private static BigInteger unsigned(byte[] b) {
        return new BigInteger(1, b);
    }

    private static byte[] bigIntToFixed(BigInteger n, int len) {
        byte[] raw = n.toByteArray();
        if (raw.length == len) return raw;
        byte[] out = new byte[len];
        if (raw.length > len) System.arraycopy(raw, raw.length - len, out, 0, len);
        else System.arraycopy(raw, 0, out, len - raw.length, raw.length);
        return out;
    }
}
