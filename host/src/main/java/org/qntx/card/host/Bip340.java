// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.host;

import java.math.BigInteger;
import java.util.Arrays;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Host-side BIP-340 schnorr helpers for {@code SIGN_BIP340} (spec/protocol.md §9.10, §12.2): tagged
 * hashes, the BIP-86 {@code TapTweak} output key, Default Signing of a tweaked scalar and
 * Verification of the {@code R_x ‖ s} signature under the 32-byte output key. BouncyCastle has no
 * BIP-340 implementation, so the algorithms are written from BIP-340 on its point arithmetic.
 */
public final class Bip340 {
    private static final BigInteger P = Crypto.DOMAIN.getCurve().getField().getCharacteristic();
    private static final BigInteger N = Crypto.N;
    private static final BigInteger TWO = BigInteger.valueOf(2);
    private static final BigInteger THREE = BigInteger.valueOf(3);
    private static final BigInteger SEVEN = BigInteger.valueOf(7);
    private static final BigInteger SQRT_EXP = P.add(BigInteger.ONE).shiftRight(2);

    private Bip340() {}

    /** {@code TaggedHash(tag, msg…) = SHA-256(SHA-256(tag) ‖ SHA-256(tag) ‖ msg…)} (BIP-340). */
    public static byte[] taggedHash(String tag, byte[]... messages) {
        byte[] tagHash = Crypto.sha256(tag.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        byte[][] in = new byte[messages.length + 2][];
        in[0] = tagHash;
        in[1] = tagHash;
        System.arraycopy(messages, 0, in, 2, messages.length);
        return Crypto.sha256(in);
    }

    /**
     * The BIP-86 output key {@code x(P_even + t·G)} of {@code internalKey65} tweaked by {@code
     * tweak32} ({@code TaggedHash("TapTweak", x(P) [‖ merkleRoot])}, §12.2); the signature of
     * {@code SIGN_BIP340} verifies under this key.
     *
     * @throws IllegalArgumentException when {@code tweak32} is {@code ≥ n} or the tweaked key is
     *     zero (the point at infinity)
     */
    public static byte[] outputKey(byte[] internalKey65, byte[] tweak32) {
        BigInteger t = new BigInteger(1, tweak32);
        if (t.compareTo(N) >= 0) {
            throw new IllegalArgumentException("tweak >= n");
        }
        ECPoint p = Crypto.DOMAIN.getCurve().decodePoint(internalKey65);
        if (p.getAffineYCoord().toBigInteger().testBit(0)) {
            p = p.negate();
        }
        ECPoint q = p.add(Crypto.DOMAIN.getG().multiply(t));
        if (q.isInfinity()) {
            throw new IllegalArgumentException("the tweaked key is zero");
        }
        return x(q);
    }

    /**
     * The exact {@code R_x ‖ s} signature of {@code SIGN_BIP340}: BIP-340 Default Signing with
     * {@code tweakedScalar} as the secret key ({@code y(tweakedScalar·G)} is even by construction,
     * so the BIP-340 negation is a no-op); the signature is self-verified before it is returned.
     *
     * @throws IllegalArgumentException when {@code tweakedScalar} is outside {@code [1, n−1]}
     */
    public static byte[] signature(BigInteger tweakedScalar, byte[] message, byte[] aux) {
        if (tweakedScalar.signum() <= 0 || tweakedScalar.compareTo(N) >= 0) {
            throw new IllegalArgumentException("secret key outside [1, n-1]");
        }
        ECPoint p = Crypto.DOMAIN.getG().multiply(tweakedScalar).normalize();
        BigInteger d =
                p.getAffineYCoord().toBigInteger().testBit(0)
                        ? N.subtract(tweakedScalar)
                        : tweakedScalar;
        byte[] px = x(p);
        byte[] t = xor(scalar(d), taggedHash("BIP0340/aux", aux));
        byte[] rand = taggedHash("BIP0340/nonce", t, px, message);
        BigInteger k0 = new BigInteger(1, rand).mod(N);
        if (k0.signum() == 0) {
            throw new IllegalStateException("BIP-340 nonce is zero");
        }
        ECPoint r = Crypto.DOMAIN.getG().multiply(k0).normalize();
        BigInteger k = r.getAffineYCoord().toBigInteger().testBit(0) ? N.subtract(k0) : k0;
        byte[] rx = x(r);
        BigInteger e = new BigInteger(1, taggedHash("BIP0340/challenge", rx, px, message)).mod(N);
        byte[] sig = new byte[64];
        System.arraycopy(rx, 0, sig, 0, 32);
        System.arraycopy(scalar(k.add(e.multiply(d)).mod(N)), 0, sig, 32, 32);
        if (!verify(px, message, sig)) {
            throw new IllegalStateException("BIP-340 self-verification failed");
        }
        return sig;
    }

    /**
     * BIP-340 Verification of the 64-byte signature {@code R_x ‖ s} under the 32-byte x-only {@code
     * outputKey32}; {@code false} on every failure.
     */
    public static boolean verify(byte[] outputKey32, byte[] message, byte[] signature) {
        if (outputKey32 == null
                || outputKey32.length != 32
                || signature == null
                || signature.length != 64) {
            return false;
        }
        ECPoint p = liftX(new BigInteger(1, outputKey32));
        if (p == null) {
            return false;
        }
        BigInteger r = new BigInteger(1, Arrays.copyOfRange(signature, 0, 32));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(signature, 32, 64));
        if (r.compareTo(P) >= 0 || s.compareTo(N) >= 0) {
            return false;
        }
        BigInteger e =
                new BigInteger(
                                1,
                                taggedHash(
                                        "BIP0340/challenge",
                                        Arrays.copyOfRange(signature, 0, 32),
                                        outputKey32,
                                        message))
                        .mod(N);
        ECPoint pointR = Crypto.DOMAIN.getG().multiply(s).subtract(p.multiply(e));
        if (pointR.isInfinity()) {
            return false;
        }
        pointR = pointR.normalize();
        return !pointR.getAffineYCoord().toBigInteger().testBit(0)
                && pointR.getAffineXCoord().toBigInteger().equals(r);
    }

    /**
     * {@code lift_x(x)}: the point with {@code x(P) = x} and even {@code y(P)}, or {@code null}
     * when {@code x ≥ p} or {@code x³ + 7} is not a residue (BIP-340).
     */
    private static ECPoint liftX(BigInteger x) {
        if (x.signum() < 0 || x.compareTo(P) >= 0) {
            return null;
        }
        BigInteger c = x.modPow(THREE, P).add(SEVEN).mod(P);
        BigInteger y = c.modPow(SQRT_EXP, P);
        if (!y.modPow(TWO, P).equals(c)) {
            return null;
        }
        if (y.testBit(0)) {
            y = P.subtract(y);
        }
        return Crypto.DOMAIN.getCurve().createPoint(x, y);
    }

    private static byte[] x(ECPoint point) {
        return scalar(point.normalize().getAffineXCoord().toBigInteger());
    }

    private static byte[] scalar(BigInteger v) {
        byte[] b = v.toByteArray();
        byte[] out = new byte[32];
        int len = Math.min(b.length, 32);
        System.arraycopy(b, b.length - len, out, 32 - len, len);
        return out;
    }

    private static byte[] xor(byte[] a, byte[] b) {
        byte[] out = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            out[i] = (byte) (a[i] ^ b[i]);
        }
        return out;
    }
}
