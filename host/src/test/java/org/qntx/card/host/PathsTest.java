// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.host;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Map;
import org.junit.jupiter.api.Test;

/** {@link Paths} against the derivation.json {@code path} ‖ {@code wire} pairs (§9.2). */
final class PathsTest {
    private final Map<String, Object> derivation = Vectors.load("derivation.json");

    @Test
    void vectorPathsRoundTrip() {
        for (Map<String, Object> v : Vectors.list(derivation, "bip32")) {
            for (Map<String, Object> n : Vectors.list(v, "nodes")) {
                check((String) n.get("path"), (String) n.get("wire"));
            }
        }
        for (Map<String, Object> v : Vectors.list(derivation, "slip10")) {
            for (Map<String, Object> n : Vectors.list(v, "nodes")) {
                check((String) n.get("path"), (String) n.get("wire"));
            }
        }
        Map<String, Object> templates = Vectors.obj(derivation, "templates");
        for (Map<String, Object> e : Vectors.list(templates, "secp256k1")) {
            check((String) e.get("path"), (String) e.get("wire"));
        }
        for (Map<String, Object> e : Vectors.list(templates, "ed25519")) {
            check((String) e.get("path"), (String) e.get("wire"));
        }
    }

    @Test
    void masterHasDepthZero() {
        assertArrayEquals(new byte[] {0}, Paths.wire("m"));
        assertEquals("m", Paths.format(new byte[] {0}));
    }

    @Test
    void rejectsBadPaths() {
        for (String p :
                new String[] {
                    "x/0", "m//0", "m/0x", "m/'0", "m/2147483648", "m/0/1/2/3/4/5/6/7/8/9/10", "",
                }) {
            assertThrows(IllegalArgumentException.class, () -> Paths.wire(p), p);
        }
        for (byte[] w :
                new byte[][] {
                    new byte[0], new byte[] {1}, new byte[] {1, 0, 0, 0, 0, 0},
                }) {
            assertThrows(IllegalArgumentException.class, () -> Paths.format(w));
        }
    }

    private void check(String path, String wire) {
        if (wire == null) {
            assertEquals("m", path);
            return;
        }
        byte[] expected = Vectors.unhex(wire);
        assertArrayEquals(expected, Paths.wire(path), path);
        assertEquals(path, Paths.format(expected), path);
    }
}
