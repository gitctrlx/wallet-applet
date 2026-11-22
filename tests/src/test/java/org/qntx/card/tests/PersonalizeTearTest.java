// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.qntx.card.host.Open;
import org.qntx.card.sim.Card;
import org.qntx.card.sim.TornException;

/** §16.3: power loss inside T-PERSO at every write index must leave the card in FACTORY. */
final class PersonalizeTearTest {

    @Test
    void tearAtEveryWriteLeavesFactoryOrBlank() throws Exception {
        // T-PERSO performs exactly 3 persistent writes (caKey.setW, cert, life)
        for (int n = 1; n <= 4; n++) {
            Card card = Vecs.factory();
            byte[] a = Vecs.cardA(card);
            byte[] apdu = Vecs.personalizeApdu(Vecs.certFor(a));
            card.tearAt(n);
            if (n <= 3) {
                assertThrows(TornException.class, () -> card.transmit(apdu), "write " + n);
                card.powerCycle();
                card.transmit(Spec.SELECT);
                // the transaction was aborted: nothing of it may be visible
                assertEquals(
                        0x9000,
                        Vecs.sw(card.transmit(Vecs.unhex("80E0000000"))),
                        "card must still be FACTORY after tear at write " + n);
                // a clean retry must work
                assertEquals(0x9000, Vecs.sw(card.transmit(apdu)));
            } else {
                // no 4th write exists: the command completes
                assertEquals(0x9000, Vecs.sw(card.transmit(apdu)));
            }
            // the card is BLANK and fully functional
            Open.Request req = Open.request(Vecs.RND);
            byte[] open = card.transmit(req.apdu());
            assertEquals(0x9000, Vecs.sw(open));
            Open.response(req.secret(), req.apdu(), open, List.of(Vecs.caPublic()));
        }
    }
}
