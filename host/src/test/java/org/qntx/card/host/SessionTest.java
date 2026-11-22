// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.host;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import org.junit.jupiter.api.Test;

/** record.json: §8.4/§8.5 command and response records replayed host-side at fixed keys. */
final class SessionTest {
    private final Map<String, Object> doc = Vectors.load("record.json");
    private final byte[] a = new byte[33];

    private Session at(int ctr) {
        Map<String, Object> keys = Vectors.obj(doc, "keys");
        return new Session(
                a,
                new byte[97],
                Vectors.hex(keys, "kce"),
                Vectors.hex(keys, "kcm"),
                Vectors.hex(keys, "kre"),
                Vectors.hex(keys, "krm"),
                ctr);
    }

    @Test
    void wrapProducesEveryCommandVector() throws Exception {
        Map<String, Object> keys = Vectors.obj(doc, "keys");
        byte[] kce = Vectors.hex(keys, "kce");
        byte[] kcm = Vectors.hex(keys, "kcm");
        for (Map<String, Object> c : Vectors.list(doc, "commands")) {
            int ctr = ((Number) c.get("ctr")).intValue();
            String name = (String) c.get("name");
            // rebuild the record from the raw plaintext to check the vector itself (§8.3)
            byte[] plain =
                    concat(
                            Vectors.unhex((String) c.get("ins")),
                            Vectors.unhex((String) c.get("p1")),
                            Vectors.unhex((String) c.get("p2")),
                            Vectors.hex(c, "data"));
            byte[] seed = new byte[16];
            seed[0] = 0x01;
            System.arraycopy(Crypto.u16(ctr), 0, seed, 14, 2);
            byte[] iv = Crypto.aesBlock(kce, seed);
            assertArrayEquals(Vectors.hex(c, "iv"), iv, name + " iv");
            byte[] ct = Crypto.aesCbc(kce, iv, Crypto.m2pad(plain), true);
            byte[] tag = new byte[8];
            System.arraycopy(Crypto.cmac(kcm, Crypto.u16(ctr), ct), 0, tag, 0, 8);
            byte[] apdu = new byte[5 + ct.length + 8 + 1];
            apdu[0] = (byte) 0x80;
            apdu[1] = 0x12;
            apdu[4] = (byte) (ct.length + 8);
            System.arraycopy(ct, 0, apdu, 5, ct.length);
            System.arraycopy(tag, 0, apdu, 5 + ct.length, 8);
            assertArrayEquals(Vectors.unhex((String) c.get("apdu")), apdu, name + " record");
            // where the inner header is complete, Session.wrap must produce the same APDU
            if (plain.length >= 3) {
                Session s = at(ctr);
                assertArrayEquals(
                        Vectors.unhex((String) c.get("apdu")),
                        s.wrap(
                                plain[0] & 0xFF,
                                plain[1] & 0xFF,
                                plain[2] & 0xFF,
                                java.util.Arrays.copyOfRange(plain, 3, plain.length)),
                        name);
                if (ctr == 0xFFFF) {
                    assertTrue(!s.closed(), "wrap alone does not close");
                }
            }
        }
    }

    private static byte[] concat(byte[]... parts) {
        int n = 0;
        for (byte[] p : parts) {
            n += p.length;
        }
        byte[] out = new byte[n];
        int off = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, off, p.length);
            off += p.length;
        }
        return out;
    }

    @Test
    void unwrapProducesEveryResponseVector() throws Exception {
        for (Map<String, Object> r : Vectors.list(doc, "responses")) {
            Session s = at(((Number) r.get("ctr")).intValue());
            Response resp = s.unwrap(Vectors.unhex((String) r.get("rapdu")));
            assertArrayEquals(Vectors.hex(r, "data"), resp.data(), (String) r.get("name"));
            assertEquals(
                    Integer.parseInt((String) r.get("sw"), 16), resp.sw(), (String) r.get("name"));
        }
    }

    @Test
    void rejectedResponsesTearTheSessionDown() {
        for (Map<String, Object> r : Vectors.list(doc, "rejectedResponses")) {
            Session s = at(((Number) r.get("ctr")).intValue());
            assertThrows(
                    SessionBrokenException.class,
                    () -> s.unwrap(Vectors.unhex((String) r.get("rapdu"))),
                    (String) r.get("name"));
            assertTrue(s.closed(), (String) r.get("name"));
            assertThrows(
                    SessionBrokenException.class,
                    () -> s.wrap(0x20, 0, 0, new byte[0]),
                    "wrap after teardown: " + r.get("name"));
        }
    }
}
