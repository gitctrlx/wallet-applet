// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.host;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** {@link AccessCode#hash} against the access.json vectors (§7.1): valid and rejected codes. */
final class AccessCodeTest {
    private final Map<String, Object> access = Vectors.load("access.json");

    @Test
    void validCodesHashToAccessHash() {
        for (Map<String, Object> c : Vectors.list(access, "valid")) {
            byte[] cardId = Vectors.hex(c, "cardId");
            byte[] salt = Vectors.hex(c, "salt");
            assertArrayEquals(
                    Vectors.hex(c, "accessHash"),
                    AccessCode.hash((String) c.get("code"), cardId),
                    (String) c.get("name"));
            // the salt is "qntx-card/v1/access" ‖ cardId (§7.1)
            byte[] expect = new byte[19 + 16];
            System.arraycopy(
                    "qntx-card/v1/access".getBytes(StandardCharsets.US_ASCII), 0, expect, 0, 19);
            System.arraycopy(cardId, 0, expect, 19, 16);
            assertArrayEquals(expect, salt, (String) c.get("name"));
        }
    }

    @Test
    void rejectedCodesThrow() {
        for (Map<String, Object> c : Vectors.list(access, "rejected")) {
            String code = new String(Vectors.hex(c, "codeHex"), StandardCharsets.UTF_8);
            assertThrows(
                    IllegalArgumentException.class,
                    () -> AccessCode.hash(code, new byte[16]),
                    (String) c.get("name"));
        }
    }
}
