// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: MIT OR Apache-2.0
package org.qntx.card.vectors;

import java.math.BigInteger;
import org.bouncycastle.math.ec.ECPoint;

/**
 * The deterministic CA and card-identity material shared by {@code cert.json} and {@code
 * session.json}: private scalars are {@code det(...)} values asserted in {@code [1, n−1]}
 * (spec/vectors generator rules).
 */
final class Cards {
    private Cards() {}

    /** CA private scalar {@code det("cert/" + name)}. */
    static BigInteger caPrivate(String name) {
        return scalar("cert/" + name);
    }

    /**
     * A card identity private scalar: the first {@code det(name + "/" + i)} of {@code i = 0, 1, …}
     * whose public key has the requested {@code y} parity.
     */
    static BigInteger identityPrivate(String name, boolean wantOddY) {
        for (int i = 0; ; i++) {
            BigInteger d = scalar(name + "/" + i);
            ECPoint pub = Crypto.DOMAIN.getG().multiply(d).normalize();
            if (pub.getAffineYCoord().toBigInteger().testBit(0) == wantOddY) {
                return d;
            }
        }
    }

    /** {@code det(name)} asserted in {@code [1, n−1]} as required for private scalars. */
    static BigInteger scalar(String name) {
        BigInteger d = new BigInteger(1, Vec.det(name));
        if (d.signum() <= 0 || d.compareTo(Crypto.N) >= 0) {
            throw new IllegalStateException("det scalar out of range: " + name);
        }
        return d;
    }
}
