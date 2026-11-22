// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.host;

import java.math.BigInteger;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Wei25519, the short-Weierstrass curve {@code Y² = X³ + a_W·X + b_W} over {@code q = 2²⁵⁵ − 19}
 * that is isomorphic to edwards25519 (spec/protocol.md §10.4,
 * draft-ietf-lwig-curve-representations). All constants are the values printed in §10.4.
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

    static final ECCurve.Fp CURVE = new ECCurve.Fp(Q, A_W, B_W, ORDER, BigInteger.ONE);

    /** {@code G_W}, the point corresponding to the edwards25519 base point {@code B}. */
    static final ECPoint G =
            CURVE.createPoint(
                    new BigInteger(
                            "2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad245a", 16),
                    new BigInteger(
                            "20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9",
                            16));

    private Wei25519() {}

    /** Whether {@code (x, y)} satisfies {@code y² = x³ + a_W·x + b_W} over {@code q}. */
    static boolean onCurve(BigInteger x, BigInteger y) {
        if (x.signum() < 0 || x.compareTo(Q) >= 0 || y.signum() < 0 || y.compareTo(Q) >= 0) {
            return false;
        }
        BigInteger y2 = y.modPow(BigInteger.TWO, Q);
        BigInteger x3 = x.modPow(BigInteger.valueOf(3), Q).add(A_W.multiply(x)).add(B_W).mod(Q);
        return y2.equals(x3);
    }
}
