// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: MIT OR Apache-2.0
package org.qntx.card.vectors;

import java.math.BigInteger;
import java.util.Arrays;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Wei25519, the short-Weierstrass curve {@code Y² = X³ + a_W·X + b_W} over {@code q = 2²⁵⁵ − 19}
 * that is isomorphic to edwards25519, and the host map to the RFC 8032 encoding (spec/protocol.md
 * §10.4, draft-ietf-lwig-curve-representations). All constants are the values printed in §10.4.
 */
final class Wei25519 {
    static final BigInteger Q =
            new BigInteger("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed", 16);
    static final BigInteger A_W =
            new BigInteger("2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa984914a144", 16);
    static final BigInteger B_W =
            new BigInteger("7b425ed097b425ed097b425ed097b425ed097b425ed097b4260b5e9c7710c864", 16);
    static final BigInteger ORDER =
            new BigInteger("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed", 16);
    static final BigInteger A3 =
            new BigInteger("2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad2451", 16);
    static final BigInteger C =
            new BigInteger("70d9120b9f5ff9442d84f723fc03b0813a5e2c2eb482e57d3391fb5500ba81e7", 16);
    private static final BigInteger GX =
            new BigInteger("2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad245a", 16);
    private static final BigInteger GY =
            new BigInteger("20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9", 16);

    static final ECCurve.Fp CURVE = new ECCurve.Fp(Q, A_W, B_W, ORDER, BigInteger.ONE);
    static final ECPoint G = CURVE.createPoint(GX, GY);

    static {
        if (!G.isValid() || !G.multiply(ORDER).isInfinity()) {
            throw new IllegalStateException("G_W is not an order-ℓ Wei25519 point");
        }
    }

    private Wei25519() {}

    /**
     * {@code a mod ℓ} for the RFC 8032 private key {@code sk}: {@code a =
     * clamp(SHA-512(sk)[0..32))} read little-endian (RFC 8032 §5.1.5, spec/protocol.md §10.4).
     */
    static BigInteger scalar(byte[] sk) {
        byte[] a = Arrays.copyOf(Crypto.sha512(sk), 32);
        a[0] &= 0xf8;
        a[31] &= 0x7f;
        a[31] |= 0x40;
        reverse(a);
        return new BigInteger(1, a).mod(ORDER);
    }

    /** {@code W(P) = X(32) ‖ Y(32)}, the affine Wei25519 coordinates big-endian (§10.4). */
    static byte[] wei(ECPoint p) {
        ECPoint affine = p.normalize();
        byte[] out = new byte[64];
        write(affine.getAffineXCoord().toBigInteger(), out, 0);
        write(affine.getAffineYCoord().toBigInteger(), out, 32);
        return out;
    }

    /**
     * The §10.4 host map: {@code u = X − A₃}, {@code y = (u−1)/(u+1)}, {@code x = c·u/Y}, {@code
     * le32(y)} with bit 255 = {@code x mod 2}. Rejects a point not on Wei25519.
     */
    static byte[] encode(byte[] wei64) {
        if (wei64.length != 64) {
            throw new IllegalArgumentException("W(P) must be 64 bytes");
        }
        BigInteger x = new BigInteger(1, Arrays.copyOfRange(wei64, 0, 32));
        BigInteger y = new BigInteger(1, Arrays.copyOfRange(wei64, 32, 64));
        BigInteger y2 = y.modPow(BigInteger.TWO, Q);
        BigInteger x3 = x.modPow(BigInteger.valueOf(3), Q).add(A_W.multiply(x)).add(B_W).mod(Q);
        if (x.signum() < 0 || x.compareTo(Q) >= 0 || y.compareTo(Q) >= 0 || !y2.equals(x3)) {
            throw new IllegalArgumentException("not a Wei25519 point");
        }
        BigInteger u = x.subtract(A3).mod(Q);
        BigInteger ey =
                u.subtract(BigInteger.ONE).multiply(u.add(BigInteger.ONE).modInverse(Q)).mod(Q);
        BigInteger ex = C.multiply(u).multiply(y.modInverse(Q)).mod(Q);
        byte[] out = le32(ey);
        if (ex.testBit(0)) {
            out[31] |= (byte) 0x80;
        }
        return out;
    }

    /** {@code le32(v)}: the 32-byte little-endian encoding of {@code v}. */
    private static byte[] le32(BigInteger v) {
        byte[] out = Vec.scalar(v);
        reverse(out);
        return out;
    }

    private static void write(BigInteger v, byte[] out, int off) {
        byte[] b = Vec.scalar(v);
        System.arraycopy(b, 0, out, off, 32);
    }

    private static void reverse(byte[] a) {
        for (int i = 0, j = a.length - 1; i < j; i++, j--) {
            byte t = a[i];
            a[i] = a[j];
            a[j] = t;
        }
    }
}
