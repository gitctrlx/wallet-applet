// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: MIT OR Apache-2.0
package org.qntx.card.vectors;

import java.math.BigInteger;
import java.util.Arrays;
import org.bouncycastle.math.ec.ECPoint;

/**
 * BIP-340 Schnorr signatures over secp256k1 (spec/protocol.md §12.2): tagged hashes, {@code
 * lift_x}, Default Signing and Verification, written from BIP-340 on BouncyCastle point arithmetic
 * (BouncyCastle has no BIP-340 implementation).
 */
final class Bip340 {
    private static final BigInteger P = Crypto.DOMAIN.getCurve().getField().getCharacteristic();
    private static final BigInteger N = Crypto.N;
    private static final BigInteger TWO = BigInteger.valueOf(2);
    private static final BigInteger THREE = BigInteger.valueOf(3);
    private static final BigInteger SEVEN = BigInteger.valueOf(7);
    private static final BigInteger SQRT_EXP = P.add(BigInteger.ONE).shiftRight(2);

    private Bip340() {}

    /** {@code TaggedHash(tag, msg) = SHA-256(SHA-256(tag) ‖ SHA-256(tag) ‖ msg)} (BIP-340). */
    static byte[] taggedHash(String tag, byte[]... parts) {
        byte[] tagHash = Crypto.sha256(Vec.ascii(tag));
        byte[][] in = new byte[parts.length + 2][];
        in[0] = tagHash;
        in[1] = tagHash;
        System.arraycopy(parts, 0, in, 2, parts.length);
        return Crypto.sha256(in);
    }

    /**
     * {@code lift_x(x)}: the point with {@code x(P) = x} and even {@code y(P)}, or {@code null}
     * when {@code x ≥ p} or {@code x³ + 7} is not a residue (BIP-340).
     */
    static ECPoint liftX(BigInteger x) {
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

    /** The x coordinate of {@code point} as 32 big-endian bytes. */
    static byte[] x(ECPoint point) {
        return Vec.scalar(point.normalize().getAffineXCoord().toBigInteger());
    }

    /**
     * BIP-340 Default Signing: {@code Sign(d₀, m, aux)} with the secret key negated when {@code
     * y(d₀·G)} is odd; the signature is self-verified before it is returned.
     *
     * @throws IllegalArgumentException when {@code d₀} is outside {@code [1, n−1]}
     */
    static byte[] sign(BigInteger d0, byte[] message, byte[] aux) {
        if (d0.signum() <= 0 || d0.compareTo(N) >= 0) {
            throw new IllegalArgumentException("BIP-340 secret key outside [1, n-1]");
        }
        ECPoint p = Crypto.DOMAIN.getG().multiply(d0).normalize();
        BigInteger d = p.getAffineYCoord().toBigInteger().testBit(0) ? N.subtract(d0) : d0;
        byte[] px = x(p);
        byte[] t = xor(Vec.scalar(d), taggedHash("BIP0340/aux", aux));
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
        System.arraycopy(Vec.scalar(k.add(e.multiply(d)).mod(N)), 0, sig, 32, 32);
        if (!verify(px, message, sig)) {
            throw new IllegalStateException("BIP-340 self-verification failed");
        }
        return sig;
    }

    /**
     * BIP-340 Verification of the 64-byte signature {@code R_x ‖ s} under the x-only public key for
     * a message of any length; {@code false} on every failure (§"Verification").
     */
    static boolean verify(byte[] publicKeyX, byte[] message, byte[] sig) {
        if (publicKeyX == null || publicKeyX.length != 32 || sig == null || sig.length != 64) {
            return false;
        }
        ECPoint p = liftX(new BigInteger(1, publicKeyX));
        if (p == null) {
            return false;
        }
        BigInteger r = new BigInteger(1, Arrays.copyOfRange(sig, 0, 32));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(sig, 32, 64));
        if (r.compareTo(P) >= 0 || s.compareTo(N) >= 0) {
            return false;
        }
        BigInteger e =
                new BigInteger(
                                1,
                                taggedHash(
                                        "BIP0340/challenge",
                                        Arrays.copyOfRange(sig, 0, 32),
                                        publicKeyX,
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

    private static byte[] xor(byte[] a, byte[] b) {
        byte[] out = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            out[i] = (byte) (a[i] ^ b[i]);
        }
        return out;
    }
}
