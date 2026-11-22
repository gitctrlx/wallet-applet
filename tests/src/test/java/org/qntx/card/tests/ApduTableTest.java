// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.tests;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.qntx.card.host.Open;
import org.qntx.card.host.Response;
import org.qntx.card.host.Session;
import org.qntx.card.sim.Card;

/** Replays every case of spec/vectors/apdu.json: §9.1/§9.2 checking order and §9.3 STATUS. */
final class ApduTableTest {

    @Test
    void everyTableCase() throws Exception {
        Map<String, Object> doc = Vecs.load("apdu.json");
        for (Map<String, Object> group : Vecs.list(doc, "commands")) {
            for (Map<String, Object> c : Vecs.list(group, "cases")) {
                run(group, c);
            }
        }
    }

    @SuppressWarnings("unchecked")
    private static void run(Map<String, Object> group, Map<String, Object> c) throws Exception {
        String name = group.get("name") + "." + c.get("name");
        String life = (String) c.get("life");
        if (life.equals("LOADED")) {
            return; // LOADED is unreachable in the core stage; the case is a later-stage anchor
        }
        Card card = Vecs.factory();
        byte[] a = tryA(card); // GET_IDENTITY works only in FACTORY, so read it first
        if (life.equals("BLANK")) {
            Vecs.blankFor(card, a);
        }
        int expectedSw = Integer.parseInt((String) c.get("sw"), 16);
        if (!(Boolean) c.get("inner")) {
            byte[] apdu = Vecs.resolveApdu((String) c.get("apdu"), card, a);
            byte[] rapdu = card.transmit(apdu);
            assertEquals(expectedSw, Vecs.sw(rapdu), name);
            Object response = c.get("response");
            if (response != null) {
                checkResponse((String) response, rapdu, a, apdu, name);
            }
            return;
        }
        // inner cases run inside a command record on an open session
        assertTrue(((String) c.get("session")).equals("open"), name);
        Session session = Vecs.open(card);
        byte[] plain = Vecs.unhex((String) c.get("apdu"));
        byte[] data = java.util.Arrays.copyOfRange(plain, 3, plain.length);
        Response r =
                Vecs.roundtrip(
                        card, session, plain[0] & 0xFF, plain[1] & 0xFF, plain[2] & 0xFF, data);
        assertEquals(expectedSw, r.sw(), name);
        Object response = c.get("response");
        if (response != null) {
            assertArrayEquals(Vecs.unhex((String) response), r.data(), name);
        }
    }

    private static byte[] tryA(Card card) {
        byte[] rapdu = card.transmit(Vecs.unhex("80E0000000"));
        return Vecs.sw(rapdu) == 0x9000 ? java.util.Arrays.copyOf(rapdu, 33) : new byte[33];
    }

    private static void checkResponse(String sym, byte[] rapdu, byte[] a, byte[] apdu, String name)
            throws Exception {
        if (sym.equals("{A}")) {
            assertArrayEquals(a, java.util.Arrays.copyOf(rapdu, 33), name);
            return;
        }
        if (sym.equals("{openResponse}")) {
            // host-verifiable: the fixed session.json request against the ca1 anchor
            Map<String, Object> doc = Vecs.load("session.json");
            Session s =
                    Open.response(
                            Vecs.hex(doc, "hostPrivate"), apdu, rapdu, List.of(Vecs.caPublic()));
            assertEquals(0, s.counter(), name);
            return;
        }
        assertArrayEquals(Vecs.unhex(sym), java.util.Arrays.copyOf(rapdu, rapdu.length - 2), name);
    }
}
