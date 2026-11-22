// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.host;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * {@link Slip10} against the derivation.json vectors: the official SLIP-0010 ed25519 test vectors
 * 1–2 and the wallet template paths, including the {@code wei} output (§10.2, §10.4).
 */
final class Slip10Test {
    private final Map<String, Object> derivation = Vectors.load("derivation.json");

    @Test
    void officialVectorsDeriveEveryNode() {
        for (Map<String, Object> v : Vectors.list(derivation, "slip10")) {
            byte[] seed = Vectors.hex(v, "seed");
            for (Map<String, Object> n : Vectors.list(v, "nodes")) {
                check(seed, n);
            }
        }
    }

    @Test
    void templatePaths() {
        Map<String, Object> templates = Vectors.obj(derivation, "templates");
        byte[] seed = Vectors.hex(templates, "seed");
        for (Map<String, Object> e : Vectors.list(templates, "ed25519")) {
            check(seed, e);
        }
    }

    @Test
    void nonHardenedIndexThrows() {
        assertThrows(
                IllegalArgumentException.class, () -> Slip10.derive(new byte[64], "m/44'/501'/0"));
    }

    private void check(byte[] seed, Map<String, Object> n) {
        String path = (String) n.get("path");
        Slip10.Node node = Slip10.derive(seed, path);
        assertArrayEquals(Vectors.hex(n, "privateKey"), node.privateKey(), path);
        assertArrayEquals(Vectors.hex(n, "chainCode"), node.chainCode(), path);
        byte[] wei = Slip10.wei(node.privateKey());
        assertArrayEquals(Vectors.hex(n, "wei"), wei, path);
        assertArrayEquals(Vectors.hex(n, "publicKey"), Wei25519Map.encode(wei), path);
    }
}
