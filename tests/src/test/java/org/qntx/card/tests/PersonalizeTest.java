// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.qntx.card.host.Certificates;
import org.qntx.card.sim.Card;

/** §14.2 PERSONALIZE: checking order, certificate validation and the T-PERSO transaction. */
final class PersonalizeTest {

    private static boolean factory(Card card) {
        return Vecs.sw(card.transmit(Vecs.unhex("80E0000000"))) == 0x9000;
    }

    @Test
    void successTransitionsToBlankAtomically() {
        Card card = Vecs.factory();
        byte[] a = Vecs.cardA(card);
        byte[] rapdu = card.transmit(Vecs.personalizeApdu(Vecs.certFor(a)));
        assertEquals(0x9000, Vecs.sw(rapdu));
        // T-PERSO: caKey.setW + cert write + setLife = 3 persistent writes, one transaction
        assertEquals(3, card.writes());
        assertEquals(1, card.commits().size());
        assertTrue(card.commitBytes() > 0);
        assertTrue(
                card.commitBytes() <= 2560,
                "T-PERSO commit bytes " + card.commitBytes() + " exceed half of the 5120 B buffer");
        // BLANK: GET_IDENTITY and a second PERSONALIZE are now refused
        assertEquals(0x6985, Vecs.sw(card.transmit(Vecs.unhex("80E0000000"))));
        assertEquals(0x6985, Vecs.sw(card.transmit(Vecs.personalizeApdu(Vecs.certFor(a)))));
    }

    @Test
    void rejectedCertificatesLeaveTheCardFactory() {
        byte[] a = Vecs.cardA(Vecs.factory());
        byte[] good = Vecs.certFor(a);
        byte[][] bad = new byte[5][];
        bad[0] = good.clone();
        bad[0][33] = 0; // r = 0 prefix byte flipped
        bad[1] = good.clone();
        java.util.Arrays.fill(bad[1], 33, 65, (byte) 0); // r = 0
        bad[2] = good.clone();
        java.util.Arrays.fill(bad[2], 65, 97, (byte) 0); // s = 0
        bad[3] = Vecs.certOtherA(); // valid cert for a different A
        bad[4] = good.clone();
        bad[4][96] ^= 1; // corrupt s
        for (byte[] cert : bad) {
            Card card = Vecs.factory();
            assertEquals(0x6A80, Vecs.sw(card.transmit(Vecs.personalizeApdu(cert))));
            assertTrue(factory(card), "card must stay FACTORY after a rejected cert");
        }
        // a cert issued by a different CA is a valid object but fails §5.2 under ca1
        Card card = Vecs.factory();
        byte[] aa = Vecs.cardA(card);
        assertEquals(
                0x6A80,
                Vecs.sw(
                        card.transmit(
                                Vecs.personalizeApdu(Certificates.issue(Vecs.ca2Private(), aa)))));
        assertTrue(factory(card));
    }

    @Test
    void rejectedCaKeysLeaveTheCardFactory() {
        for (String sym :
                new String[] {"caKey.prefix03", "caKey.xIsP", "caKey.yIsP", "caKey.offCurve"}) {
            Card card = Vecs.factory();
            byte[] a = Vecs.cardA(card);
            byte[] apdu = Vecs.personalizeApdu(Vecs.certFor(a));
            byte[] caKey = Vecs.symbol(sym, card, a);
            System.arraycopy(caKey, 0, apdu, 102, 65);
            assertEquals(0x6A80, Vecs.sw(card.transmit(apdu)), sym);
            assertTrue(factory(card), sym);
        }
    }

    @Test
    void verifyResetsTheSharedDigest() {
        // junk left mid-digest must not leak into the certificate hash — verify()
        // resets the shared sha256 engine before hashing
        Card card = Vecs.factory();
        byte[] a = Vecs.cardA(card);
        org.qntx.card.Internals.sha256(card.applet(Spec.WALLET_AID))
                .update(new byte[] {9, 9, 9}, (short) 0, (short) 3);
        assertEquals(0x9000, Vecs.sw(card.transmit(Vecs.personalizeApdu(Vecs.certFor(a)))));
    }

    @Test
    void checkOrderIsLifeThenP1P2ThenLength() {
        // multi-violation: bad P1 with bad Lc → 6A86 wins (§14.2 order)
        Card card = Vecs.factory();
        byte[] apdu = Vecs.unhex("80e2010000");
        assertEquals(0x6A86, Vecs.sw(card.transmit(apdu)));
        assertEquals(0x6A86, Vecs.sw(card.transmit(Vecs.unhex("80e2000100"))));
        assertEquals(0x6700, Vecs.sw(card.transmit(Vecs.unhex("80e2000000"))));
        byte[] a = Vecs.cardA(card);
        byte[] bad = Vecs.personalizeApdu(Vecs.certFor(a));
        bad[4] = (byte) 161;
        assertEquals(0x6700, Vecs.sw(card.transmit(bad)));
        assertTrue(factory(card));
    }
}
