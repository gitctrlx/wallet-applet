// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.qntx.card.host.Session;
import org.qntx.card.sim.Card;

/**
 * §16.1 item 7 (architecture §14.4 W11): on a LOADED card in an unverified session the only
 * persistent writes allowed are T-FAIL per failed VERIFY and the single T-ERASE at the limit.
 */
final class UnverifiedWriteTest {

    private Card card;
    private Session session;

    private void loaded() throws Exception {
        card = Vecs.blankSelf();
        session = Vecs.loadWallet(card);
    }

    private int run(int ins, int p1, byte[] data) throws Exception {
        int sw = Vecs.roundtrip(card, session, ins, p1, 0, data).sw();
        return sw;
    }

    @Test
    void writesPerCommand() throws Exception {
        loaded();
        assertEquals(0x9000, run(0x20, 0, new byte[0]));
        assertEquals(0, card.writes(), "STATUS writes nothing");

        assertEquals(0x63c9, run(0x22, 0, Vecs.accessHashWrong()));
        assertEquals(List.of(1024), card.commits(), "wrong VERIFY commits T-FAIL only");
        assertEquals(2, card.writes(), "T-FAIL = the fails pair");

        assertEquals(0x9000, run(0x25, 0, new byte[0]));
        assertEquals(0, card.writes(), "WAIT writes nothing");
        assertEquals(0, card.commits().size());

        assertEquals(0x6982, run(0x23, 0, Vecs.accessHashNew()));
        assertEquals(0, card.writes(), "CHANGE rejected before any write");
        assertEquals(0x6982, run(0x24, 0, new byte[0]));
        assertEquals(0, card.writes(), "ERASE rejected before any write");
        assertEquals(0x6982, run(0x30, 0, Vecs.pathSecpEvm()), "PUBLIC_KEY rejected");
        assertEquals(0, card.writes());
        byte[] ecdsaData = new byte[32 + Vecs.pathSecpEvm().length];
        System.arraycopy(Vecs.digest(), 0, ecdsaData, 0, 32);
        System.arraycopy(Vecs.pathSecpEvm(), 0, ecdsaData, 32, Vecs.pathSecpEvm().length);
        assertEquals(0x6982, run(0x31, 0, ecdsaData), "SIGN_ECDSA rejected");
        assertEquals(0, card.writes(), "SIGN_ECDSA writes nothing unverified");
        byte[] bip340Data = new byte[64 + Vecs.pathSecpEvm().length];
        System.arraycopy(Vecs.pathSecpEvm(), 0, bip340Data, 64, Vecs.pathSecpEvm().length);
        assertEquals(0x6982, run(0x32, 0, bip340Data), "SIGN_BIP340 rejected");
        assertEquals(0, card.writes(), "SIGN_BIP340 writes nothing unverified");
        assertEquals(0x6982, run(0x33, 0, Vecs.pathEdSolana()), "SIGN_ED25519 begin rejected");
        assertEquals(0, card.writes(), "begin writes nothing unverified");
        assertEquals(0x6982, run(0x33, 1, new byte[] {1}), "update rejected");
        assertEquals(0x6982, run(0x33, 2, new byte[0]), "finish rejected");
        assertEquals(0, card.writes());

        byte[] create = new byte[96];
        System.arraycopy(Vecs.accessHash(), 0, create, 0, 32);
        System.arraycopy(Vecs.seed(), 0, create, 32, 64);
        assertEquals(0x6985, run(0x21, 1, create));
        assertEquals(0, card.writes(), "CREATE on LOADED writes nothing");
    }

    @Test
    void onlyTFailAndOneTEraseAcrossTheLimit() throws Exception {
        loaded();
        int tFail = 0;
        int tErase = 0;
        for (int i = 0; i < 10; i++) {
            if (i >= 3) {
                for (int w = 0; w < 15; w++) {
                    run(0x25, 0, new byte[0]);
                    assertEquals(0, card.writes(), "WAIT never writes");
                }
            }
            int sw = run(0x22, 0, Vecs.accessHashWrong());
            for (int c : card.commits()) {
                if (c == 1024) {
                    tFail++;
                } else if (c == 1536) {
                    tErase++;
                }
            }
            assertEquals(i < 9 ? 0x63c0 | (9 - i) : 0x6983, sw);
        }
        assertEquals(10, tFail, "exactly L T-FAIL commits");
        assertEquals(1, tErase, "exactly one T-ERASE commit");
    }
}
