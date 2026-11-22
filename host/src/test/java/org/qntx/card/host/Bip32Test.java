// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.host;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * {@link Bip32} against the derivation.json vectors: the official BIP-32 test vectors 1–4 and the
 * wallet template paths (§10.2–10.3).
 */
final class Bip32Test {
    private final Map<String, Object> derivation = Vectors.load("derivation.json");

    @Test
    void officialVectorsDeriveEveryNode() {
        for (Map<String, Object> v : Vectors.list(derivation, "bip32")) {
            byte[] seed = Vectors.hex(v, "seed");
            for (Map<String, Object> n : Vectors.list(v, "nodes")) {
                Bip32.Node node = Bip32.derive(seed, (String) n.get("path"));
                assertArrayEquals(
                        Vectors.hex(n, "privateKey"), node.privateKey(), (String) n.get("path"));
                assertArrayEquals(
                        Vectors.hex(n, "chainCode"), node.chainCode(), (String) n.get("path"));
                assertArrayEquals(
                        Vectors.hex(n, "publicKey"), node.publicKey(), (String) n.get("path"));
            }
        }
    }

    @Test
    void templatePathsAndMasterPublicKey() {
        Map<String, Object> templates = Vectors.obj(derivation, "templates");
        byte[] seed = Vectors.hex(templates, "seed");
        assertArrayEquals(Vectors.hex(templates, "masterPublicKey"), Bip32.masterPublicKey(seed));
        for (Map<String, Object> e : Vectors.list(templates, "secp256k1")) {
            String path = (String) e.get("path");
            Bip32.Node node = Bip32.derive(seed, path);
            assertArrayEquals(Vectors.hex(e, "privateKey"), node.privateKey(), path);
            assertArrayEquals(Vectors.hex(e, "chainCode"), node.chainCode(), path);
            assertArrayEquals(Vectors.hex(e, "publicKey"), node.publicKey(), path);
        }
    }

    @Test
    void badMasterThrows() {
        // the invalidMaster rule 1 ≤ kM ≤ n−1 is covered by the vector file;
        // an out-of-range path index is a host error
        assertThrows(
                IllegalArgumentException.class, () -> Bip32.derive(new byte[64], "m/2147483648"));
    }
}
