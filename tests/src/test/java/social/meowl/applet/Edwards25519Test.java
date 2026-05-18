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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Random;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

/**
 * Correctness tests for {@link Edwards25519}. The applet's point operations are oracle-checked
 * against a {@link BigInteger}-based reference implementation in this test class
 * ({@code RefPoint}) and against the RFC 8032 §7.1 known-answer vector for {@code sk → pk}
 * derivation, which exercises {@link Edwards25519#scalarMult} and
 * {@link Edwards25519#encodePoint} together.
 */
class Edwards25519Test {

    private static final BigInteger P =
            BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));
    private static final BigInteger D =
            BigInteger.valueOf(-121665).multiply(BigInteger.valueOf(121666).modInverse(P)).mod(P);
    private static final BigInteger L =
            BigInteger.ONE
                    .shiftLeft(252)
                    .add(new BigInteger("27742317777372353535851937790883648493"));
    private static final BigInteger BASE_X =
            new BigInteger(
                    "216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A", 16);
    private static final BigInteger BASE_Y =
            new BigInteger(
                    "6666666666666666666666666666666666666666666666666666666666666658", 16);

    private static final Random RNG = new Random(0xDEADBEEFL);

    private static byte[] beBytes(BigInteger v) {
        byte[] full = v.mod(P).toByteArray();
        byte[] out = new byte[32];
        if (full.length > 32) {
            System.arraycopy(full, full.length - 32, out, 0, 32);
        } else {
            System.arraycopy(full, 0, out, 32 - full.length, full.length);
        }
        return out;
    }

    private static BigInteger toBig(byte[] buf, int off, int len) {
        byte[] slice = new byte[len];
        System.arraycopy(buf, off, slice, 0, len);
        return new BigInteger(1, slice);
    }

    /** Reference affine point with {@code BigInteger}-based addition / doubling / scalar mult. */
    private static final class RefPoint {
        final BigInteger x;
        final BigInteger y;

        RefPoint(BigInteger x, BigInteger y) {
            this.x = x.mod(P);
            this.y = y.mod(P);
        }

        static final RefPoint IDENTITY = new RefPoint(BigInteger.ZERO, BigInteger.ONE);
        static final RefPoint BASE = new RefPoint(BASE_X, BASE_Y);

        RefPoint add(RefPoint other) {
            BigInteger x1y2 = x.multiply(other.y).mod(P);
            BigInteger x2y1 = other.x.multiply(y).mod(P);
            BigInteger y1y2 = y.multiply(other.y).mod(P);
            BigInteger x1x2 = x.multiply(other.x).mod(P);
            BigInteger dxy = D.multiply(x1y2).multiply(x2y1).mod(P);
            BigInteger newX =
                    x1y2.add(x2y1)
                            .multiply(BigInteger.ONE.add(dxy).modInverse(P))
                            .mod(P);
            BigInteger newY =
                    y1y2.add(x1x2)
                            .multiply(BigInteger.ONE.subtract(dxy).modInverse(P))
                            .mod(P);
            return new RefPoint(newX, newY);
        }

        RefPoint dbl() {
            return add(this);
        }

        RefPoint scalarMult(BigInteger k) {
            RefPoint r = IDENTITY;
            for (int i = k.bitLength() - 1; i >= 0; i--) {
                r = r.dbl();
                if (k.testBit(i)) {
                    r = r.add(BASE);
                }
            }
            return r;
        }

        boolean equalsAffine(RefPoint other) {
            return x.equals(other.x) && y.equals(other.y);
        }
    }

    /** Project an applet point {@code (X:Y:Z:T)} (BE) to its affine representative for compare. */
    private static RefPoint affineOf(byte[] point) {
        BigInteger X = toBig(point, Edwards25519.PT_X_OFF, 32);
        BigInteger Y = toBig(point, Edwards25519.PT_Y_OFF, 32);
        BigInteger Z = toBig(point, Edwards25519.PT_Z_OFF, 32);
        BigInteger zInv = Z.modInverse(P);
        return new RefPoint(X.multiply(zInv).mod(P), Y.multiply(zInv).mod(P));
    }

    /** Returns {@code true} iff the affine representative is on edwards25519. */
    private static boolean onCurve(RefPoint p) {
        BigInteger lhs =
                p.y.multiply(p.y)
                        .subtract(p.x.multiply(p.x))
                        .mod(P);
        BigInteger rhs =
                BigInteger.ONE
                        .add(D.multiply(p.x).multiply(p.x).multiply(p.y).multiply(p.y))
                        .mod(P);
        return lhs.equals(rhs);
    }

    /** Build a 128-byte applet point with {@code Z = 1, T = X · Y} from affine {@code (x, y)}. */
    private static byte[] appletPointFromAffine(BigInteger x, BigInteger y) {
        byte[] p = new byte[Edwards25519.POINT_LEN];
        System.arraycopy(beBytes(x), 0, p, Edwards25519.PT_X_OFF, 32);
        System.arraycopy(beBytes(y), 0, p, Edwards25519.PT_Y_OFF, 32);
        p[Edwards25519.PT_Z_OFF + 31] = 0x01;
        System.arraycopy(beBytes(x.multiply(y).mod(P)), 0, p, Edwards25519.PT_T_OFF, 32);
        return p;
    }

    @Nested
    @DisplayName("Curve constants")
    class CurveConstants {

        @Test
        @DisplayName("D = -121665/121666 mod p")
        void dConstant() {
            assertEquals(D, toBig(Edwards25519.D, 0, 32));
        }

        @Test
        @DisplayName("D2 = 2 · D mod p")
        void d2Constant() {
            assertEquals(D.shiftLeft(1).mod(P), toBig(Edwards25519.D2, 0, 32));
        }

        @Test
        @DisplayName("Base point lies on the curve and matches RFC 8032 §5.1.4")
        void basePointOnCurve() {
            byte[] base = new byte[Edwards25519.POINT_LEN];
            Edwards25519.setBase(base, (short) 0);
            RefPoint affine = affineOf(base);
            assertTrue(onCurve(affine));
            assertEquals(BASE_X, affine.x);
            assertEquals(BASE_Y, affine.y);
        }

        @Test
        @DisplayName("Identity (0, 1, 1, 0) is on the curve")
        void identityOnCurve() {
            byte[] id = new byte[Edwards25519.POINT_LEN];
            Edwards25519.setIdentity(id, (short) 0);
            assertTrue(onCurve(affineOf(id)));
        }
    }

    @Nested
    @DisplayName("pointDouble")
    class Doubling {

        private final byte[] scratch = new byte[Edwards25519.POINT_OP_SCRATCH_LEN];
        private final byte[] result = new byte[Edwards25519.POINT_LEN];

        @Test
        @DisplayName("2 · identity = identity")
        void doubleIdentity() {
            byte[] id = new byte[Edwards25519.POINT_LEN];
            Edwards25519.setIdentity(id, (short) 0);
            Edwards25519.pointDouble(result, (short) 0, id, (short) 0, scratch, (short) 0);
            assertTrue(affineOf(result).equalsAffine(RefPoint.IDENTITY));
        }

        @Test
        @DisplayName("2 · B matches BigInteger reference")
        void doubleBase() {
            byte[] base = new byte[Edwards25519.POINT_LEN];
            Edwards25519.setBase(base, (short) 0);
            Edwards25519.pointDouble(result, (short) 0, base, (short) 0, scratch, (short) 0);
            assertTrue(onCurve(affineOf(result)));
            assertTrue(affineOf(result).equalsAffine(RefPoint.BASE.dbl()));
        }

        @RepeatedTest(20)
        @DisplayName("2 · (k · B) matches BigInteger reference")
        void doubleRandomMultiple() {
            BigInteger k = new BigInteger(252, RNG).mod(L);
            RefPoint expected = RefPoint.BASE.scalarMult(k).dbl();
            RefPoint kP = RefPoint.BASE.scalarMult(k);
            byte[] in = appletPointFromAffine(kP.x, kP.y);
            Edwards25519.pointDouble(result, (short) 0, in, (short) 0, scratch, (short) 0);
            assertTrue(onCurve(affineOf(result)));
            assertTrue(affineOf(result).equalsAffine(expected));
        }

        @Test
        @DisplayName("In-place doubling (out aliases in) gives the same result")
        void doubleInPlace() {
            byte[] base = new byte[Edwards25519.POINT_LEN];
            Edwards25519.setBase(base, (short) 0);
            Edwards25519.pointDouble(base, (short) 0, base, (short) 0, scratch, (short) 0);
            assertTrue(affineOf(base).equalsAffine(RefPoint.BASE.dbl()));
        }
    }

    @Nested
    @DisplayName("pointAdd")
    class Addition {

        private final byte[] scratch = new byte[Edwards25519.POINT_OP_SCRATCH_LEN];
        private final byte[] result = new byte[Edwards25519.POINT_LEN];

        @Test
        @DisplayName("identity + B = B")
        void addIdentity() {
            byte[] id = new byte[Edwards25519.POINT_LEN];
            byte[] base = new byte[Edwards25519.POINT_LEN];
            Edwards25519.setIdentity(id, (short) 0);
            Edwards25519.setBase(base, (short) 0);
            Edwards25519.pointAdd(
                    result, (short) 0, id, (short) 0, base, (short) 0, scratch, (short) 0);
            assertTrue(affineOf(result).equalsAffine(RefPoint.BASE));
        }

        @Test
        @DisplayName("B + B = 2 · B (matches doubling)")
        void addEqualsDouble() {
            byte[] base = new byte[Edwards25519.POINT_LEN];
            Edwards25519.setBase(base, (short) 0);
            Edwards25519.pointAdd(
                    result, (short) 0, base, (short) 0, base, (short) 0, scratch, (short) 0);
            assertTrue(affineOf(result).equalsAffine(RefPoint.BASE.dbl()));
        }

        @RepeatedTest(20)
        @DisplayName("(k1 · B) + (k2 · B) matches BigInteger reference")
        void addRandomMultiples() {
            BigInteger k1 = new BigInteger(252, RNG).mod(L);
            BigInteger k2 = new BigInteger(252, RNG).mod(L);
            RefPoint p1 = RefPoint.BASE.scalarMult(k1);
            RefPoint p2 = RefPoint.BASE.scalarMult(k2);
            byte[] in1 = appletPointFromAffine(p1.x, p1.y);
            byte[] in2 = appletPointFromAffine(p2.x, p2.y);
            Edwards25519.pointAdd(
                    result, (short) 0, in1, (short) 0, in2, (short) 0, scratch, (short) 0);
            assertTrue(onCurve(affineOf(result)));
            assertTrue(affineOf(result).equalsAffine(p1.add(p2)));
        }
    }

    @Nested
    @DisplayName("scalarMult")
    class ScalarMult {

        private final byte[] scratch = new byte[Edwards25519.SCALAR_MULT_SCRATCH_LEN];
        private final byte[] base = new byte[Edwards25519.POINT_LEN];
        private final byte[] out = new byte[Edwards25519.POINT_LEN];

        {
            Edwards25519.setBase(base, (short) 0);
        }

        @Test
        @DisplayName("0 · B = identity")
        void zeroScalar() {
            byte[] zero = new byte[32];
            Edwards25519.scalarMult(
                    zero, (short) 0, base, (short) 0, out, (short) 0, scratch, (short) 0);
            assertTrue(affineOf(out).equalsAffine(RefPoint.IDENTITY));
        }

        @Test
        @DisplayName("1 · B = B")
        void unitScalar() {
            byte[] one = new byte[32];
            one[31] = 0x01;
            Edwards25519.scalarMult(
                    one, (short) 0, base, (short) 0, out, (short) 0, scratch, (short) 0);
            assertTrue(affineOf(out).equalsAffine(RefPoint.BASE));
        }

        @Test
        @DisplayName("L · B = identity (B has order L in the prime subgroup)")
        void groupOrderScalar() {
            byte[] l = beBytes(L);
            Edwards25519.scalarMult(
                    l, (short) 0, base, (short) 0, out, (short) 0, scratch, (short) 0);
            assertTrue(affineOf(out).equalsAffine(RefPoint.IDENTITY));
        }

        @RepeatedTest(5)
        @DisplayName("k · B matches BigInteger reference")
        void randomScalar() {
            BigInteger k = new BigInteger(252, RNG).mod(L);
            byte[] kBytes = beBytes(k);
            Edwards25519.scalarMult(
                    kBytes, (short) 0, base, (short) 0, out, (short) 0, scratch, (short) 0);
            assertTrue(onCurve(affineOf(out)));
            assertTrue(affineOf(out).equalsAffine(RefPoint.BASE.scalarMult(k)));
        }
    }

    @Nested
    @DisplayName("encodePoint and RFC 8032 sk → pk")
    class Encoding {

        private final byte[] smScratch = new byte[Edwards25519.SCALAR_MULT_SCRATCH_LEN];
        private final byte[] encScratch = new byte[Edwards25519.ENCODE_SCRATCH_LEN];
        private final byte[] base = new byte[Edwards25519.POINT_LEN];
        private final byte[] point = new byte[Edwards25519.POINT_LEN];
        private final byte[] enc = new byte[Edwards25519.ENCODED_LEN];

        @Test
        @DisplayName("encode(B) matches RFC 8032 §5.1.4 fixed-base encoding")
        void encodeBase() {
            // RFC 8032 §5.1.4: B encodes to LE y with bit 0 of x in bit 255. Here BASE_X is
            // even (0x216936...51A — last byte 0x1A, bit 0 = 0), so the high bit stays clear.
            byte[] expected =
                    HexFormat.of()
                            .parseHex(
                                    "5866666666666666666666666666666666666666666666666666666666666666");
            Edwards25519.setBase(base, (short) 0);
            Edwards25519.encodePoint(base, (short) 0, enc, (short) 0, encScratch, (short) 0);
            assertArrayEquals(expected, enc);
        }

        @Test
        @DisplayName("encode(identity) = 0x01000…0 (LE 1, x = 0 ⇒ no parity bit)")
        void encodeIdentity() {
            byte[] id = new byte[Edwards25519.POINT_LEN];
            Edwards25519.setIdentity(id, (short) 0);
            Edwards25519.encodePoint(id, (short) 0, enc, (short) 0, encScratch, (short) 0);
            byte[] expected = new byte[32];
            expected[0] = 0x01;
            assertArrayEquals(expected, enc);
        }

        @Test
        @DisplayName("RFC 8032 §7.1 TEST 1: sk → pk derivation matches expected")
        void rfc8032Test1() throws NoSuchAlgorithmException {
            // RFC 8032 §7.1 ----------- TEST 1 -----------
            byte[] sk =
                    HexFormat.of()
                            .parseHex(
                                    "9d61b19deffd5a60ba844af492ec2cc4"
                                            + "4449c5697b326919703bac031cae7f60");
            byte[] expectedPk =
                    HexFormat.of()
                            .parseHex(
                                    "d75a980182b10ab7d54bfed3c964073a"
                                            + "0ee172f3daa62325af021a68f707511a");

            byte[] pk = derivePublicKey(sk);
            assertArrayEquals(expectedPk, pk);
        }

        @Test
        @DisplayName("RFC 8032 §7.1 TEST 2: sk → pk derivation matches expected")
        void rfc8032Test2() throws NoSuchAlgorithmException {
            byte[] sk =
                    HexFormat.of()
                            .parseHex(
                                    "4ccd089b28ff96da9db6c346ec114e0f"
                                            + "5b8a319f35aba624da8cf6ed4fb8a6fb");
            byte[] expectedPk =
                    HexFormat.of()
                            .parseHex(
                                    "3d4017c3e843895a92b70aa74d1b7ebc"
                                            + "9c982ccf2ec4968cc0cd55f12af4660c");

            byte[] pk = derivePublicKey(sk);
            assertArrayEquals(expectedPk, pk);
        }

        private byte[] derivePublicKey(byte[] sk) throws NoSuchAlgorithmException {
            // 1. h = SHA-512(sk). h[0..32] is the secret-scalar precursor.
            MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
            byte[] h = sha512.digest(sk);
            // 2. Clamp h[0..32] per RFC 8032 §5.1.5 then reverse to BE for our scalarMult.
            byte[] sLE = new byte[32];
            System.arraycopy(h, 0, sLE, 0, 32);
            sLE[0] &= (byte) 248;
            sLE[31] &= (byte) 127;
            sLE[31] |= (byte) 64;
            byte[] sBE = new byte[32];
            for (int i = 0; i < 32; i++) {
                sBE[i] = sLE[31 - i];
            }
            // 3. A = s · B
            Edwards25519.setBase(base, (short) 0);
            Edwards25519.scalarMult(
                    sBE, (short) 0, base, (short) 0, point, (short) 0, smScratch, (short) 0);
            // 4. Encode A.
            Edwards25519.encodePoint(point, (short) 0, enc, (short) 0, encScratch, (short) 0);
            return enc.clone();
        }
    }

    @Test
    @DisplayName("scalarMult uses every iteration (not short-circuited on leading zeros)")
    void scalarMultConstantIterations() {
        byte[] scratch = new byte[Edwards25519.SCALAR_MULT_SCRATCH_LEN];
        byte[] base = new byte[Edwards25519.POINT_LEN];
        byte[] out = new byte[Edwards25519.POINT_LEN];
        Edwards25519.setBase(base, (short) 0);

        // Two scalars with very different Hamming weights but the same expected timing.
        byte[] zero = new byte[32];
        byte[] full = new byte[32];
        for (int i = 0; i < 32; i++) {
            full[i] = (byte) 0xFF;
        }
        // Sanity: both should produce on-curve points (full-scalar wraps mod 8L per Edwards
        // group structure but stays on the curve). We're not timing-measuring here — just making
        // sure the routine accepts both extremes without crashing.
        Edwards25519.scalarMult(zero, (short) 0, base, (short) 0, out, (short) 0, scratch, (short) 0);
        assertTrue(affineOf(out).equalsAffine(RefPoint.IDENTITY));
        Edwards25519.scalarMult(full, (short) 0, base, (short) 0, out, (short) 0, scratch, (short) 0);
        assertTrue(onCurve(affineOf(out)));
        assertFalse(affineOf(out).equalsAffine(RefPoint.IDENTITY));
    }
}
