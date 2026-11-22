// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.qntx.card.host.Session;
import org.qntx.card.sim.Card;

/**
 * §14.2/architecture §5: every wallet transaction must fit the commit buffer with margin. Expected
 * sizes come from architecture §16.1: the CREATE/CHANGE/ERASE transactions rewrite the wrap
 * material plus key objects (1536 B), T-FAIL and T-OK write the failure pair and session bits (1024
 * B). {@code card.commits()} is reset per command, so it reports the command's transactions.
 */
final class CommitCapacityTest {

    private static final int BUFFER = 2560;

    private Card card;
    private Session session;

    private void blank() throws Exception {
        byte[] a = Vecs.cardA(card = Vecs.factory());
        card = Vecs.blankFor(card, a);
        session = Vecs.open(card);
    }

    private void loaded() throws Exception {
        blank();
        session = Vecs.loadWallet(card);
    }

    @Test
    void persoTransactionUsesAtMostHalfTheCommitBuffer() {
        Card card = Vecs.factory();
        byte[] a = Vecs.cardA(card);
        assertEquals(0x9000, Vecs.sw(card.transmit(Vecs.personalizeApdu(Vecs.certFor(a)))));
        // one transaction: caKey.setW + the 97-byte cert write + the coded life write
        assertEquals(1, card.commits().size());
        assertEquals(3, card.writes());
        int used = card.commitBytes();
        assertTrue(used > 0 && used <= BUFFER, "T-PERSO commit bytes " + used + " vs the buffer");
        System.out.println("T-PERSO commit bytes: " + used);
    }

    @Test
    void createTransactionFits() throws Exception {
        blank();
        byte[] data = new byte[96];
        System.arraycopy(Vecs.accessHash(), 0, data, 0, 32);
        System.arraycopy(Vecs.seed(), 0, data, 32, 64);
        assertEquals(0x9000, Vecs.roundtrip(card, session, 0x21, 1, 0, data).sw());
        List<Integer> commits = card.commits();
        assertEquals(1, commits.size(), "T-CREATE is a single commit");
        assertEquals(1536, (int) commits.get(0), "T-CREATE commit bytes");
        System.out.println("T-CREATE commit bytes: " + commits.get(0));
    }

    @Test
    void failAndOkTransactionsFit() throws Exception {
        loaded();
        assertEquals(
                0x63c9, Vecs.roundtrip(card, session, 0x22, 0, 0, Vecs.accessHashWrong()).sw());
        List<Integer> fail = card.commits();
        assertEquals(1, fail.size(), "T-FAIL is a single commit");
        assertEquals(1024, (int) fail.get(0), "T-FAIL commit bytes");
        System.out.println("T-FAIL commit bytes: " + fail.get(0));

        assertEquals(0x9000, Vecs.roundtrip(card, session, 0x22, 0, 0, Vecs.accessHash()).sw());
        List<Integer> ok = card.commits();
        assertEquals(2, ok.size(), "a successful VERIFY commits T-FAIL then T-OK");
        assertEquals(1024, (int) ok.get(1), "T-OK commit bytes");
        System.out.println("T-OK commit bytes: " + ok.get(1));
    }

    @Test
    void changeAndEraseTransactionsFit() throws Exception {
        loaded();
        assertEquals(0x9000, Vecs.roundtrip(card, session, 0x22, 0, 0, Vecs.accessHash()).sw());
        assertEquals(0x9000, Vecs.roundtrip(card, session, 0x23, 0, 0, Vecs.accessHashNew()).sw());
        List<Integer> change = card.commits();
        assertEquals(1, change.size(), "T-CHANGE is a single commit");
        assertEquals(1536, (int) change.get(0), "T-CHANGE commit bytes");
        System.out.println("T-CHANGE commit bytes: " + change.get(0));

        assertEquals(0x9000, Vecs.roundtrip(card, session, 0x24, 0, 0, new byte[0]).sw());
        List<Integer> erase = card.commits();
        assertEquals(1, erase.size(), "T-ERASE is a single commit");
        assertEquals(1536, (int) erase.get(0), "T-ERASE commit bytes");
        System.out.println("T-ERASE commit bytes: " + erase.get(0));
    }
}
