// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.host;

import java.math.BigInteger;
import java.util.Arrays;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Host-side helpers for {@code SIGN_ECDSA} (spec/protocol.md §9.9, §12.1): verification of the
 * {@code r ‖ s} wire signature over a pre-computed 32-byte digest, the SEC 1 §4.1.6 public key
 * recovery id, and the low-s variant a caller may request for malleability-sensitive chains.
 */
public final class Ecdsa {
    private Ecdsa() {}

    /**
     * The recovery id (0–3) of {@code r ‖ s} for {@code publicKey65}: candidate points are {@code x
     * = r + (i ≫ 1)·n} with {@code y} parity {@code i & 1} and the recovered key is {@code r⁻¹·(s·R
     * − e·G)} (SEC 1 §4.1.6); {@code -1} when no candidate recovers the key.
     */
    public static int recoveryId(byte[] publicKey65, byte[] digest, byte[] signature) {
        if (signature.length != 64) {
            return -1;
        }
        BigInteger r = new BigInteger(1, Arrays.copyOfRange(signature, 0, 32));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(signature, 32, 64));
        if (r.signum() <= 0
                || r.compareTo(Crypto.N) >= 0
                || s.signum() <= 0
                || s.compareTo(Crypto.N) >= 0) {
            return -1;
        }
        ECPoint want;
        try {
            want = Crypto.DOMAIN.getCurve().decodePoint(publicKey65);
        } catch (IllegalArgumentException e) {
            return -1;
        }
        BigInteger e = new BigInteger(1, digest);
        BigInteger rInv = r.modInverse(Crypto.N);
        for (int j = 0; j < 2; j++) {
            BigInteger x = r.add(Crypto.N.multiply(BigInteger.valueOf(j)));
            if (x.compareTo(Crypto.DOMAIN.getCurve().getField().getCharacteristic()) >= 0) {
                continue;
            }
            for (int parity = 0; parity < 2; parity++) {
                byte[] enc = new byte[33];
                enc[0] = (byte) (0x02 | parity);
                writeFixed(x, enc, 1);
                ECPoint pointR;
                try {
                    pointR = Crypto.DOMAIN.getCurve().decodePoint(enc);
                } catch (IllegalArgumentException ex) {
                    continue; // x³ + 7 not a residue: not a candidate
                }
                ECPoint q =
                        pointR.multiply(s)
                                .subtract(Crypto.DOMAIN.getG().multiply(e))
                                .multiply(rInv)
                                .normalize();
                if (q.equals(want)) {
                    return 2 * j + parity;
                }
            }
        }
        return -1;
    }

    /** {@code r ‖ min(s, n−s)}: the low-s normalisation of the {@code r ‖ s} signature. */
    public static byte[] lowS(byte[] signature) {
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(signature, 32, 64));
        BigInteger complement = Crypto.N.subtract(s);
        byte[] out = signature.clone();
        if (complement.compareTo(s) < 0) {
            writeFixed(complement, out, 32);
        }
        return out;
    }

    /**
     * {@code true} when {@code r ‖ s} verifies under {@code publicKey65} over the 32-byte {@code
     * digest}; any value of {@code s} in {@code [1, n−1]} is accepted (§1).
     */
    public static boolean verify(byte[] publicKey65, byte[] digest, byte[] signature) {
        return Crypto.verify(publicKey65, digest, signature);
    }

    private static void writeFixed(BigInteger v, byte[] out, int off) {
        byte[] b = v.toByteArray();
        int len = Math.min(b.length, 32);
        System.arraycopy(b, b.length - len, out, off + 32 - len, len);
    }
}
