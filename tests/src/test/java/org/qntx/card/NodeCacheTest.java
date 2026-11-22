// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import javacard.framework.Applet;
import javacard.security.MessageDigest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.qntx.card.host.Bip32;
import org.qntx.card.host.Paths;
import org.qntx.card.host.Response;
import org.qntx.card.host.Session;
import org.qntx.card.host.Slip10;
import org.qntx.card.sim.Card;
import org.qntx.card.sim.Fault;
import org.qntx.card.tests.Spec;
import org.qntx.card.tests.Vecs;

/**
 * The §5.3 node caches: identical outputs cold and warm, no stale parent key leaking into a cold
 * derivation (the PUBLIC_KEY m/44'/60'/0'/0/0 → m/84'/0'/0'/0/0 case), independent caches per
 * curve, and the warm-leaf cost of one HMAC-SHA512 plus a single PLAIN_XY.
 */
final class NodeCacheTest {

    private Card card;
    private Session session;

    @AfterEach
    void disarm() {
        Fault.reset();
    }

    private Applet applet() {
        return card.applet(Spec.WALLET_AID);
    }

    private void verified() throws Exception {
        card = Vecs.blankSelf();
        session = Vecs.loadWallet(card);
        assertEquals(0x9000, Vecs.roundtrip(card, session, 0x22, 0, 0, Vecs.accessHash()).sw());
    }

    private Response pk(int curve, String path) throws Exception {
        return Vecs.roundtrip(card, session, 0x30, curve, 0, Paths.wire(path));
    }

    private static byte[] secpExpected(String path) {
        Bip32.Node node = Bip32.derive(Vecs.seed(), path);
        byte[] out = new byte[65];
        System.arraycopy(node.publicKey(), 0, out, 0, 33);
        System.arraycopy(node.chainCode(), 0, out, 33, 32);
        return out;
    }

    private static byte[] edExpected(String path) {
        return Slip10.wei(Slip10.derive(Vecs.seed(), path).privateKey());
    }

    /**
     * Warms the secp256k1 cache on m/44'/60'/0'/0/0 (parent pub cached), then derives
     * m/84'/0'/0'/0/0 cold: its non-hardened intermediate step must NOT reuse the cached pub.
     */
    @Test
    void staleParentPubIsNotReused() throws Exception {
        verified();
        assertArrayEquals(secpExpected("m/44'/60'/0'/0/0"), pk(0, "m/44'/60'/0'/0/0").data());
        // cold path whose intermediate step m/84'/0'/0'/0 is non-hardened
        assertArrayEquals(secpExpected("m/84'/0'/0'/0/0"), pk(0, "m/84'/0'/0'/0/0").data());
        // and the new parent is the one cached now
        assertArrayEquals(secpExpected("m/84'/0'/0'/0/1"), pk(0, "m/84'/0'/0'/0/1").data());
    }

    @Test
    void interleavedCurvesKeepSeparateCaches() throws Exception {
        verified();
        assertArrayEquals(secpExpected("m/44'/60'/0'/0/0"), pk(0, "m/44'/60'/0'/0/0").data());
        assertArrayEquals(edExpected("m/44'/501'/0'/0'"), pk(1, "m/44'/501'/0'/0'").data());
        // warm children of both cached parents interleave correctly
        assertArrayEquals(secpExpected("m/44'/60'/0'/0/1"), pk(0, "m/44'/60'/0'/0/1").data());
        assertArrayEquals(edExpected("m/44'/501'/0'/1'"), pk(1, "m/44'/501'/0'/1'").data());
        assertArrayEquals(secpExpected("m/44'/60'/0'/0/2"), pk(0, "m/44'/60'/0'/0/2").data());
    }

    @Test
    void warmLeafCostsOneHmacAndOneMul() throws Exception {
        verified();
        assertEquals(0x9000, pk(0, "m/44'/60'/0'/0/0").sw()); // cold: caches the parent
        Fault.countCalls();
        // warm non-hardened leaf: one HMAC-SHA512 (2 doFinal) + one PLAIN_XY for the output
        assertEquals(0x9000, pk(0, "m/44'/60'/0'/0/1").sw());
        assertEquals(2, card.digests(MessageDigest.ALG_SHA_512), "one HMAC-SHA512");
        assertEquals(1, Fault.calls("Secp256k1.mul"), "one PLAIN_XY for the output key");
        Fault.reset();

        // a warm ed25519 leaf: one HMAC-SHA512 + SHA-512(sk)
        assertEquals(0x9000, pk(1, "m/44'/501'/0'/0'").sw());
        assertEquals(0x9000, pk(1, "m/44'/501'/0'/1'").sw());
        assertEquals(3, card.digests(MessageDigest.ALG_SHA_512), "HMAC + SHA-512(sk)");
    }

    @Test
    void verifyEraseAndTeardownWipeTheCaches() throws Exception {
        verified();
        assertEquals(0x9000, pk(0, "m/44'/60'/0'/0/0").sw());
        assertEquals(0x9000, pk(1, "m/44'/501'/0'/0'").sw());
        assertNotZero(Internals.secpCacheBytes(applet()));
        assertNotZero(Internals.edCacheBytes(applet()));
        // a fresh VERIFY wipes both caches (step 1)
        assertEquals(0x9000, Vecs.roundtrip(card, session, 0x22, 0, 0, Vecs.accessHash()).sw());
        assertArrayEquals(new byte[138], Internals.secpCacheBytes(applet()));
        assertArrayEquals(new byte[105], Internals.edCacheBytes(applet()));

        assertEquals(0x9000, pk(0, "m/44'/60'/0'/0/0").sw());
        assertNotZero(Internals.secpCacheBytes(applet()));
        assertEquals(0x9000, Vecs.roundtrip(card, session, 0x24, 0, 0, new byte[0]).sw());
        assertArrayEquals(new byte[138], Internals.secpCacheBytes(applet()));

        // teardown: verified again on a fresh wallet, derive, then deselect
        session = Vecs.open(card);
        assertEquals(0x9000, Vecs.roundtrip(card, session, 0x21, 1, 0, createData()).sw());
        assertEquals(0x9000, pk(0, "m/44'/60'/0'/0/0").sw());
        assertNotZero(Internals.secpCacheBytes(applet()));
        card.transmit(Spec.SELECT);
        assertArrayEquals(new byte[138], Internals.secpCacheBytes(applet()));
        assertArrayEquals(new byte[105], Internals.edCacheBytes(applet()));
    }

    private static byte[] createData() {
        byte[] data = new byte[96];
        System.arraycopy(Vecs.accessHash(), 0, data, 0, 32);
        System.arraycopy(Vecs.seed(), 0, data, 32, 64);
        return data;
    }

    private static void assertNotZero(byte[] data) {
        for (byte b : data) {
            if (b != 0) {
                return;
            }
        }
        throw new AssertionError("expected nonzero data");
    }
}
