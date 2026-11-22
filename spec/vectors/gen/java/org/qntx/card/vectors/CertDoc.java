// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: MIT OR Apache-2.0
package org.qntx.card.vectors;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

/**
 * {@code cert.json}: the test CAs and card identities of spec/protocol.md §5 — certificates {@code
 * A(33) ‖ r(32) ‖ s(32)} issued under ca1 and the verify cases of §5.2, including a high-{@code s}
 * variant, a wrong anchor, a wrong key, a corrupted {@code s} and out-of-range scalars (§1 {@code
 * Verify}).
 */
final class CertDoc {
    static final BigInteger CA1 = Cards.caPrivate("ca1");
    static final BigInteger CA2 = Cards.caPrivate("ca2");

    /** card1 has an even {@code y}, card2 an odd {@code y} (the parity loop of the brief). */
    static final BigInteger CARD1 = Cards.identityPrivate("cert/card1", false);

    static final BigInteger CARD2 = Cards.identityPrivate("cert/card2", true);

    private CertDoc() {}

    static Object document() {
        byte[] a1 = Crypto.compress(Crypto.publicKey(CARD1));
        byte[] a2 = Crypto.compress(Crypto.publicKey(CARD2));
        byte[] cert1 = Certificates.issue(CA1, a1);
        byte[] cert2 = Certificates.issue(CA1, a2);
        byte[] ca1Public = Crypto.publicKey(CA1);
        byte[] ca2Public = Crypto.publicKey(CA2);

        byte[] highS = cert1.clone();
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(cert1, 65, 97));
        System.arraycopy(Vec.scalar(Crypto.N.subtract(s)), 0, highS, 65, 32);
        byte[] wrongKey = cert2.clone();
        System.arraycopy(cert1, 33, wrongKey, 33, 64);
        byte[] sFlip = cert1.clone();
        sFlip[96] ^= 1;

        List<Object> verify =
                List.of(
                        verify("card1-under-ca1", ca1Public, cert1, true),
                        verify("card2-under-ca1", ca1Public, cert2, true),
                        verify("card1-high-s", ca1Public, highS, true),
                        verify("wrong-anchor", ca2Public, cert1, false),
                        verify("wrong-key", ca1Public, wrongKey, false),
                        verify("s-flip", ca1Public, sFlip, false),
                        verify("r-zero", ca1Public, withScalar(cert1, 33, BigInteger.ZERO), false),
                        verify("s-zero", ca1Public, withScalar(cert1, 65, BigInteger.ZERO), false),
                        verify("r-n", ca1Public, withScalar(cert1, 33, Crypto.N), false),
                        verify("s-n", ca1Public, withScalar(cert1, 65, Crypto.N), false));

        return Vec.object(
                "label", Vec.hex(Vec.ascii("qntx-card/v1/cert")),
                "cas",
                        List.of(
                                Vec.object(
                                        "name", "ca1",
                                        "private", Vec.hex(Vec.scalar(CA1)),
                                        "public", Vec.hex(ca1Public)),
                                Vec.object(
                                        "name", "ca2",
                                        "private", Vec.hex(Vec.scalar(CA2)),
                                        "public", Vec.hex(ca2Public))),
                "identities", List.of(identity("card1", CARD1), identity("card2", CARD2)),
                "verify", verify);
    }

    private static Object identity(String name, BigInteger d) {
        byte[] pub = Crypto.publicKey(d);
        byte[] a = Crypto.compress(pub);
        return Vec.object(
                "name", name,
                "private", Vec.hex(Vec.scalar(d)),
                "public", Vec.hex(pub),
                "compressed", Vec.hex(a),
                "id", Vec.hex(Ids.cardId(a)),
                "short", Ids.shortId(a));
    }

    private static Object verify(String name, byte[] anchor, byte[] cert, boolean expected) {
        boolean valid = Certificates.verify(anchor, cert);
        if (valid != expected) {
            throw new IllegalStateException("verify case disagrees with its oracle: " + name);
        }
        return Vec.object(
                "name", name, "anchor", Vec.hex(anchor), "cert", Vec.hex(cert), "valid", valid);
    }

    private static byte[] withScalar(byte[] cert, int off, BigInteger v) {
        byte[] out = cert.clone();
        System.arraycopy(Vec.scalar(v), 0, out, off, 32);
        return out;
    }
}
