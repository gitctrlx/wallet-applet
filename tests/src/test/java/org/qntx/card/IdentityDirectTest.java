// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import static org.junit.jupiter.api.Assertions.assertEquals;

import javacard.framework.Applet;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import org.junit.jupiter.api.Test;
import org.qntx.card.sim.Card;
import org.qntx.card.tests.Spec;
import org.qntx.card.tests.Vecs;

/**
 * Direct calls into {@link Identity#verifyHash}: its coded {@code CHECK_FAIL} result must be the
 * constant, not just "not {@code CHECK_OK}", so the failure returns are asserted directly — through
 * APDUs every caller only compares against {@code CHECK_OK}.
 */
final class IdentityDirectTest {

    @Test
    void outOfRangeScalarIsCodedMalformed() throws Exception {
        Card card = Vecs.blankSelf();
        Applet applet = card.applet(Spec.WALLET_AID);
        Identity id = Internals.identity(applet);
        ECPublicKey pub = Internals.idPublic(applet);
        // r = 0 cannot be DER-encoded: the scalar check answers MALFORMED before the engine runs
        assertEquals(
                Const.CHECK_MALFORMED,
                id.verifyHash(pub, new byte[32], (short) 0, new byte[64], (short) 0));
    }

    @Test
    void aBadButWellFormedSignatureIsCodedFail() throws Exception {
        Card card = Vecs.blankSelf();
        Applet applet = card.applet(Spec.WALLET_AID);
        Identity id = Internals.identity(applet);
        ECPublicKey pub = Internals.idPublic(applet);
        byte[] rs = new byte[64];
        rs[31] = 1; // r = 1, s = 1: in range but not a signature over this hash
        rs[63] = 1;
        assertEquals(Const.CHECK_FAIL, id.verifyHash(pub, new byte[32], (short) 0, rs, (short) 0));
    }

    @Test
    void anUninitializedKeyIsCodedFailNotAnEscape() throws Exception {
        Card card = Vecs.blankSelf();
        Applet applet = card.applet(Spec.WALLET_AID);
        Identity id = Internals.identity(applet);
        // an EC key with no point set: ecdsa.init throws CryptoException, which verifyHash
        // must translate into CHECK_FAIL (§16.3: no engine exception escapes)
        ECPublicKey unset =
                (ECPublicKey)
                        KeyBuilder.buildKey(
                                KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false);
        byte[] rs = new byte[64];
        rs[31] = 1;
        rs[63] = 1;
        assertEquals(
                Const.CHECK_FAIL, id.verifyHash(unset, new byte[32], (short) 0, rs, (short) 0));
    }
}
