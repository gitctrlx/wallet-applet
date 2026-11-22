// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.host;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** {@link Ed25519} against the ed25519.json vectors of §12.3 (RFC 8032, stream, wrong stream). */
final class Ed25519Test {
    private final Map<String, Object> doc = Vectors.load("ed25519.json");

    @Test
    void rfc8032VectorsVerify() {
        for (Map<String, Object> v : Vectors.list(doc, "rfc8032")) {
            assertTrue(
                    Ed25519.verify(
                            Vectors.hex(v, "publicKey"),
                            Vectors.hex(v, "message"),
                            Vectors.hex(v, "signature")),
                    (String) v.get("name"));
        }
    }

    @Test
    void everyCaseVerifiesAndItsStreamProducesK() {
        for (Map<String, Object> c : Vectors.list(doc, "cases")) {
            byte[] publicKey = Vectors.hex(c, "publicKey");
            byte[] message = Vectors.hex(c, "message");
            byte[] encodedR = Vectors.hex(c, "encodedR");
            byte[] signature = Ed25519.signature(encodedR, Vectors.hex(c, "s"));
            assertArrayEquals(Vectors.hex(c, "signature"), signature, (String) c.get("name"));
            assertTrue(Ed25519.verify(publicKey, message, signature), (String) c.get("name"));
            // the stream is what the card hashes (§12.3): int_le(SHA-512(stream)) mod ℓ = k
            byte[] stream = Ed25519.stream(encodedR, publicKey, message);
            assertArrayEquals(
                    le32(intLe(Crypto.sha512(stream)).mod(Wei25519.ORDER)),
                    Vectors.hex(c, "k"),
                    (String) c.get("name"));
        }
    }

    @Test
    void wrongStreamSignaturesDoNotVerify() {
        Map<String, Object> solanaCard1 = caseByName("solana-card1");
        byte[] publicKey = Vectors.hex(solanaCard1, "publicKey");
        byte[] message = Vectors.hex(solanaCard1, "message");
        for (Map<String, Object> w : Vectors.list(doc, "wrongStream")) {
            assertFalse(
                    Ed25519.verify(publicKey, message, Vectors.hex(w, "signature")),
                    (String) w.get("name"));
        }
    }

    private Map<String, Object> caseByName(String name) {
        for (Map<String, Object> c : Vectors.list(doc, "cases")) {
            if (c.get("name").equals(name)) {
                return c;
            }
        }
        throw new IllegalStateException("missing case " + name);
    }

    private static BigInteger intLe(byte[] le) {
        byte[] be = le.clone();
        reverse(be);
        return new BigInteger(1, be);
    }

    private static byte[] le32(BigInteger v) {
        byte[] b = v.toByteArray();
        byte[] out = new byte[32];
        int len = Math.min(b.length, 32);
        System.arraycopy(b, b.length - len, out, 32 - len, len);
        reverse(out);
        return out;
    }

    private static void reverse(byte[] a) {
        for (int i = 0, j = a.length - 1; i < j; i++, j--) {
            byte t = a[i];
            a[i] = a[j];
            a[j] = t;
        }
    }
}
