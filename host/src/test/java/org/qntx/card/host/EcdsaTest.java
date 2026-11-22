// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.host;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import org.junit.jupiter.api.Test;

/** {@link Ecdsa} against the ecdsa.json vectors of §12.1 (recovery ids, low/high-s, invalid). */
final class EcdsaTest {
    private final Map<String, Object> doc = Vectors.load("ecdsa.json");

    @Test
    void everyCaseVerifiesAndRecovers() {
        for (Map<String, Object> c : Vectors.list(doc, "cases")) {
            byte[] pub65 = Vectors.hex(c, "publicKeyUncompressed");
            byte[] digest = Vectors.hex(c, "digest");
            for (String[] variant :
                    new String[][] {
                        {"signature", "recoveryId"},
                        {"lowS", "lowSRecoveryId"},
                        {"highS", "highSRecoveryId"},
                    }) {
                byte[] sig = Vectors.hex(c, variant[0]);
                assertTrue(Ecdsa.verify(pub65, digest, sig), c.get("name") + " " + variant[0]);
                int expected = ((Number) c.get(variant[1])).intValue();
                assertEquals(
                        expected,
                        Ecdsa.recoveryId(pub65, digest, sig),
                        c.get("name") + " " + variant[0]);
            }
        }
    }

    @Test
    void lowSProducesTheLowSVariant() {
        for (Map<String, Object> c : Vectors.list(doc, "cases")) {
            assertArrayEquals(
                    Vectors.hex(c, "lowS"),
                    Ecdsa.lowS(Vectors.hex(c, "signature")),
                    (String) c.get("name"));
            assertArrayEquals(
                    Vectors.hex(c, "lowS"),
                    Ecdsa.lowS(Vectors.hex(c, "highS")),
                    (String) c.get("name"));
        }
    }

    @Test
    void invalidCasesDoNotVerify() {
        for (Map<String, Object> c : Vectors.list(doc, "invalid")) {
            byte[] pub65 = Crypto.decompress(Vectors.hex(c, "publicKey"));
            assertFalse(
                    Ecdsa.verify(pub65, Vectors.hex(c, "digest"), Vectors.hex(c, "signature")),
                    (String) c.get("name"));
        }
    }
}
