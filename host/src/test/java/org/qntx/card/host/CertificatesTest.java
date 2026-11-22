// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.host;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** cert.json: deterministic issue and every §5.2 verify case including the invalid ones. */
final class CertificatesTest {
    private final Map<String, Object> cert = Vectors.load("cert.json");

    @Test
    void verifyAgreesWithEveryCase() {
        for (Map<String, Object> v : Vectors.list(cert, "verify")) {
            boolean expected = (Boolean) v.get("valid");
            assertEquals(
                    expected,
                    Certificates.verify(Vectors.hex(v, "anchor"), Vectors.hex(v, "cert")),
                    (String) v.get("name"));
        }
    }

    @Test
    void issueIsDeterministicAndVerifies() {
        List<Map<String, Object>> cas = Vectors.list(cert, "cas");
        BigInteger ca1 = new BigInteger(1, Vectors.hex(cas.get(0), "private"));
        List<Map<String, Object>> ids = Vectors.list(cert, "identities");
        byte[] a1 = Vectors.hex(ids.get(0), "compressed");
        byte[] issued = Certificates.issue(ca1, a1);
        // the card1-under-ca1 verify case stores the deterministic certificate
        for (Map<String, Object> v : Vectors.list(cert, "verify")) {
            if (v.get("name").equals("card1-under-ca1")) {
                assertArrayEquals(Vectors.hex(v, "cert"), issued);
            }
        }
        assertEquals(97, issued.length);
        assertArrayEquals(a1, java.util.Arrays.copyOf(issued, 33));
        assertNotEquals(0, issued[33]);
    }

    @Test
    void identitiesDeriveTheirCardIds() {
        for (Map<String, Object> id : Vectors.list(cert, "identities")) {
            byte[] a = Vectors.hex(id, "compressed");
            assertArrayEquals(Vectors.hex(id, "id"), Ids.cardId(a));
            assertEquals(id.get("short"), Ids.shortId(a));
        }
    }
}
