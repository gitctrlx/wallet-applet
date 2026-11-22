// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.host;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** {@link Bip340} against the bip340.json vectors of §12.2 (BIP-340 CSV, BIP-86, tweaks). */
final class Bip340Test {
    private final Map<String, Object> doc = Vectors.load("bip340.json");

    @Test
    void officialRowsVerifyAsFlagged() {
        for (Map<String, Object> row : Vectors.list(doc, "official")) {
            byte[] publicKey = Vectors.unhex((String) row.get("publicKey"));
            byte[] message = Vectors.unhex((String) row.get("message"));
            byte[] signature = Vectors.unhex((String) row.get("signature"));
            assertEquals(
                    row.get("valid"),
                    Bip340.verify(publicKey, message, signature),
                    "index " + row.get("index"));
        }
    }

    @Test
    void bip86KeysDeriveTheOfficialOutputKeys() {
        Map<String, Object> bip86 = Vectors.obj(doc, "bip86");
        for (Map<String, Object> key : Vectors.list(bip86, "keys")) {
            byte[] internalKey = Vectors.hex(key, "internalKey");
            assertArrayEquals(
                    Vectors.hex(key, "tweak"),
                    Bip340.taggedHash("TapTweak", internalKey),
                    (String) key.get("path"));
            // the x-only internal key lifted to its even-y point
            byte[] compressed = new byte[33];
            compressed[0] = 0x02;
            System.arraycopy(internalKey, 0, compressed, 1, 32);
            byte[] pub65 = Crypto.decompress(compressed);
            assertArrayEquals(
                    Vectors.hex(key, "outputKey"),
                    Bip340.outputKey(pub65, Vectors.hex(key, "tweak")),
                    (String) key.get("path"));
        }
    }

    @Test
    void everyCaseVerifiesUnderItsOutputKey() {
        for (Map<String, Object> c : Vectors.list(doc, "cases")) {
            byte[] internalKey = Vectors.hex(c, "internalKey");
            byte[] tweak = Vectors.hex(c, "tweak");
            byte[] merkleRoot =
                    (String) c.get("merkleRoot") != null ? Vectors.hex(c, "merkleRoot") : null;
            // "untweaked" carries the zero tweak override; every other case is the BIP-86 tweak
            if (!c.get("name").equals("untweaked")) {
                byte[] expectedTweak =
                        merkleRoot != null
                                ? Bip340.taggedHash("TapTweak", internalKey, merkleRoot)
                                : Bip340.taggedHash("TapTweak", internalKey);
                assertArrayEquals(expectedTweak, tweak, (String) c.get("name"));
            }
            byte[] pub65 = Crypto.decompress(Vectors.hex(c, "publicKey"));
            assertArrayEquals(
                    Vectors.hex(c, "outputKey"),
                    Bip340.outputKey(pub65, tweak),
                    (String) c.get("name"));
            byte[] message = Vectors.hex(c, "message");
            byte[] signature = Vectors.hex(c, "signature");
            assertTrue(
                    Bip340.verify(Vectors.hex(c, "outputKey"), message, signature),
                    (String) c.get("name"));
            BigInteger tweaked = new BigInteger(1, Vectors.hex(c, "tweakedKey"));
            assertArrayEquals(
                    signature,
                    Bip340.signature(tweaked, message, Vectors.hex(c, "aux")),
                    (String) c.get("name"));
        }
    }

    @Test
    void invalidTweaksAreRejected() {
        byte[] internalPub65 = Crypto.decompress(Vectors.hex(caseByName("untweaked"), "publicKey"));
        for (Map<String, Object> c : Vectors.list(doc, "invalidTweak")) {
            assertThrows(
                    IllegalArgumentException.class,
                    () -> Bip340.outputKey(internalPub65, Vectors.hex(c, "tweak")),
                    (String) c.get("name"));
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
}
