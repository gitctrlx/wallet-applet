// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.host;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * {@link Wei25519Map#encode} against derivation.json: the base point, the eight points of {@code
 * wei25519}, and every {@code wei} of the slip10 and template nodes mapping to {@code publicKey}
 * (§10.4).
 */
final class Wei25519MapTest {
    private final Map<String, Object> derivation = Vectors.load("derivation.json");

    @Test
    void basePointEncodesToRfc8032Base() {
        Map<String, Object> w = Vectors.obj(derivation, "wei25519");
        Map<String, Object> base = Vectors.obj(w, "base");
        assertArrayEquals(
                Vectors.unhex("5866666666666666666666666666666666666666666666666666666666666666"),
                Wei25519Map.encode(Vectors.hex(base, "wei")));
        assertArrayEquals(
                Vectors.hex(base, "encoding"), Wei25519Map.encode(Vectors.hex(base, "wei")));
    }

    @Test
    void everyVectorPointMaps() {
        List<Map<String, Object>> points =
                Vectors.list(Vectors.obj(derivation, "wei25519"), "points");
        for (Map<String, Object> p : points) {
            assertArrayEquals(
                    Vectors.hex(p, "encoding"),
                    Wei25519Map.encode(Vectors.hex(p, "wei")),
                    (String) p.get("name"));
        }
    }

    @Test
    void everySlip10AndTemplateWeiMapsToPublicKey() {
        for (Map<String, Object> v : Vectors.list(derivation, "slip10")) {
            for (Map<String, Object> n : Vectors.list(v, "nodes")) {
                assertArrayEquals(
                        Vectors.hex(n, "publicKey"),
                        Wei25519Map.encode(Vectors.hex(n, "wei")),
                        (String) n.get("path"));
            }
        }
        Map<String, Object> templates = Vectors.obj(derivation, "templates");
        for (Map<String, Object> e : Vectors.list(templates, "ed25519")) {
            assertArrayEquals(
                    Vectors.hex(e, "publicKey"),
                    Wei25519Map.encode(Vectors.hex(e, "wei")),
                    (String) e.get("path"));
        }
    }

    @Test
    void offCurveRejected() {
        Map<String, Object> w = Vectors.obj(derivation, "wei25519");
        byte[] wei = Vectors.hex(w, "gW");
        // y + 1 is off the curve for the base point's x
        wei[63] ^= 1;
        assertThrows(IllegalArgumentException.class, () -> Wei25519Map.encode(wei));
        assertThrows(IllegalArgumentException.class, () -> Wei25519Map.encode(new byte[63]));
    }
}
