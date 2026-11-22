// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.qntx.card.sim.Card;

/** §14.2/architecture §5: the T-PERSO transaction must fit the commit buffer with margin. */
final class CommitCapacityTest {

    @Test
    void persoTransactionUsesAtMostHalfTheCommitBuffer() {
        Card card = Vecs.factory();
        byte[] a = Vecs.cardA(card);
        assertEquals(0x9000, Vecs.sw(card.transmit(Vecs.personalizeApdu(Vecs.certFor(a)))));
        // one transaction: caKey.setW + the 97-byte cert write + the coded life write
        assertEquals(1, card.commits().size());
        assertEquals(3, card.writes());
        int used = card.commitBytes();
        assertTrue(
                used > 0 && used <= 2560, "T-PERSO commit bytes " + used + " vs the 5120 B buffer");
        // record the evidence line consumed by the final report
        System.out.println("T-PERSO commit bytes: " + used);
    }
}
