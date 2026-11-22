// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.Test;
import org.qntx.card.host.Response;
import org.qntx.card.host.Session;
import org.qntx.card.sim.Card;

/** §9.1/§9.2 dispatch checking order beyond the apdu.json table cases. */
final class DispatchTest {

    @Test
    void wrongClaBeatsEveryOtherViolation() {
        // CLA bad AND INS unknown AND P1/P2 bad AND wrong length: 6E00 must win (§9.1 order)
        assertEquals(0x6E00, Vecs.sw(Vecs.factory().transmit(Vecs.unhex("0099010200"))));
        assertEquals(0x6E00, Vecs.sw(Vecs.blankSelf().transmit(Vecs.unhex("0112000000"))));
    }

    @Test
    void unknownInsBeatsP1P2AndLife() {
        Card card = Vecs.blankSelf();
        // unknown INS + bad P1/P2 + bad Lc → 6D00 wins; also in the wrong life state
        assertEquals(0x6D00, Vecs.sw(card.transmit(Vecs.unhex("807f01020100"))));
        assertEquals(0x6D00, Vecs.sw(Vecs.factory().transmit(Vecs.unhex("80a4040000"))));
    }

    @Test
    void sessionWithoutOpenSessionIs6985() {
        byte[] record = new byte[29];
        record[0] = (byte) 0x80;
        record[1] = 0x12;
        record[4] = 0x18;
        record[28] = 0;
        assertEquals(0x6985, Vecs.sw(Vecs.factory().transmit(record)));
        Card blank = Vecs.blankSelf();
        assertEquals(0x6985, Vecs.sw(blank.transmit(record)));
        // a wrong CLA on SESSION still wins over the session check
        assertEquals(0x6E00, Vecs.sw(blank.transmit(new byte[] {0, 0x12, 0, 0, 0x18})));
    }

    @Test
    void innerErrorsKeepTheSessionAlive() throws Exception {
        Card card = Vecs.blankSelf();
        Session session = Vecs.open(card);
        // unknown inner INS → 6D00 inside a record; the session must survive (§8.5)
        Response r = Vecs.roundtrip(card, session, 0x7F, 0, 0, new byte[0]);
        assertEquals(0x6D00, r.sw());
        r = Vecs.roundtrip(card, session, 0x20, 0, 0, new byte[0]);
        assertEquals(0x9000, r.sw());
        assertNotNull(r.data());
        // P2 != 0 → 6A86 inside the record
        r = Vecs.roundtrip(card, session, 0x20, 0, 1, new byte[0]);
        assertEquals(0x6A86, r.sw());
        // session still alive
        assertEquals(0x9000, Vecs.roundtrip(card, session, 0x20, 0, 0, new byte[0]).sw());
    }
}
