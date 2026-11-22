// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.tests;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Map;
import javacard.security.MessageDigest;
import org.junit.jupiter.api.Test;
import org.qntx.card.host.Response;
import org.qntx.card.host.Session;
import org.qntx.card.sim.Card;
import org.qntx.card.sim.TornException;

/**
 * §9.5/§9.15 failure-limit behaviour: replays every sequence of {@code verify-sequence.json}
 * (architecture §14.4 W3). {@code after-T-FAIL} tears are armed on the first persistent write after
 * T-FAIL's commit, its index measured by a dry run instead of a constant. A WAIT step also asserts
 * the 400 SHA-256 {@code doFinal} calls of 32 bytes and the absence of persistent writes (§16.1
 * item 7).
 */
final class FailureLimitTest {

    private static final byte INS_STATUS = 0x20;
    private static final byte INS_VERIFY = 0x22;
    private static final byte INS_WAIT = 0x25;

    private Card card;
    private Session session;

    private void fresh() throws Exception {
        card = Vecs.blankSelf();
        session = Vecs.loadWallet(card);
    }

    private Response inner(int ins, byte[] data) throws Exception {
        return Vecs.roundtrip(card, session, ins, 0, 0, data);
    }

    private void assertStatus(String expected) throws Exception {
        Response r = inner(INS_STATUS, new byte[0]);
        assertEquals(0x9000, r.sw());
        assertArrayEquals(Vecs.unhex(expected), r.data(), "status");
    }

    /**
     * The number of persistent writes T-FAIL makes, measured on a scratch card by a wrong-code
     * VERIFY away from the erase boundary: T-FAIL is the only transaction of such a VERIFY.
     */
    private int tfailWrites() throws Exception {
        Card scratch = Vecs.blankSelf();
        Session s = Vecs.loadWallet(scratch);
        Vecs.roundtrip(scratch, s, INS_VERIFY, 0, 0, Vecs.accessHashWrong());
        return scratch.writes();
    }

    private void verifyTornAfterTFail(byte[] code) throws Exception {
        card.tearAt(tfailWrites() + 1);
        assertThrows(
                TornException.class, () -> card.transmit(session.wrap(INS_VERIFY, 0, 0, code)));
        card.powerCycle();
        card.transmit(Spec.SELECT);
        session = Vecs.open(card);
    }

    @Test
    void sequences() throws Exception {
        Map<String, Object> doc = Vecs.load("verify-sequence.json");
        for (Map<String, Object> seq : Vecs.list(doc, "sequences")) {
            fresh();
            for (Map<String, Object> step : Vecs.list(seq, "steps")) {
                String command = (String) step.get("command");
                int repeat =
                        step.get("repeat") == null ? 1 : ((Number) step.get("repeat")).intValue();
                byte[] code =
                        "right".equals(step.get("code"))
                                ? Vecs.accessHash()
                                : Vecs.accessHashWrong();
                for (int i = 0; i < repeat; i++) {
                    if ("after-T-FAIL".equals(step.get("tear"))) {
                        verifyTornAfterTFail(code);
                    } else if (command.equals("OPEN")) {
                        session = Vecs.open(card);
                    } else {
                        byte[] data = command.equals("WAIT") ? new byte[0] : code;
                        Response r = inner(command.equals("VERIFY") ? INS_VERIFY : INS_WAIT, data);
                        assertEquals(
                                Integer.parseInt((String) step.get("sw"), 16),
                                r.sw(),
                                seq.get("name") + " " + command);
                    }
                }
                assertStatus((String) step.get("status"));
            }
        }
    }

    @Test
    void waitRuns400IterationsAndWritesNothing() throws Exception {
        fresh();
        assertEquals(0x9000, inner(INS_WAIT, new byte[0]).sw());
        assertEquals(400, card.digests(MessageDigest.ALG_SHA_256), "WAIT's 400 doFinal calls");
        assertEquals(400 * 32, card.digestBytes(MessageDigest.ALG_SHA_256));
        assertEquals(0, card.writes(), "WAIT has no persistent write (§16.1 item 7)");
        assertEquals(0, card.commits().size());
    }
}
