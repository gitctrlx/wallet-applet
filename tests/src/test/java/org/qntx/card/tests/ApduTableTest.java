// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.tests;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.qntx.card.host.Bip340;
import org.qntx.card.host.Crypto;
import org.qntx.card.host.Ecdsa;
import org.qntx.card.host.Open;
import org.qntx.card.host.Response;
import org.qntx.card.host.Session;
import org.qntx.card.host.Wei25519Map;
import org.qntx.card.sim.Card;

/**
 * Replays every case of spec/vectors/apdu.json: the §9.1 outer commands, the §9.2 checking order
 * inside session records and the wallet commands of §9.3–9.8 and §9.15. {@code LOADED} cases run on
 * a card created with {@link Vecs#loadWallet}; {@code verified} sessions VERIFY the case vector's
 * access hash first.
 */
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

    private static void run(Map<String, Object> group, Map<String, Object> c) throws Exception {
        String name = group.get("name") + "." + c.get("name");
        String life = (String) c.get("life");
        int expectedSw = Integer.parseInt((String) c.get("sw"), 16);
        Card card = Vecs.factory();
        byte[] a = tryA(card); // GET_IDENTITY works only in FACTORY, so read it first
        if (life.equals("BLANK") || life.equals("LOADED")) {
            Vecs.blankFor(card, a);
        }
        Session session = life.equals("LOADED") ? Vecs.loadWallet(card) : null;
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
        // inner cases run inside a command record on the open session of the setup
        if (session == null) {
            session = Vecs.open(card);
        }
        if (c.get("session").equals("verified") || c.get("session").equals("streaming")) {
            Response v = Vecs.roundtrip(card, session, 0x22, 0, 0, Vecs.accessHash());
            assertEquals(0x9000, v.sw(), name + ": setup VERIFY");
        }
        if (c.get("session").equals("streaming")) {
            // §9.2 state "streaming": a verified session with an armed Ed25519 stream
            Response b = Vecs.roundtrip(card, session, 0x33, 0, 0, Vecs.pathEdSolana());
            assertEquals(0x9000, b.sw(), name + ": setup SIGN_ED25519 begin");
        }
        byte[] plain = Vecs.resolveApdu((String) c.get("apdu"), card, a);
        byte[] data = Arrays.copyOfRange(plain, 3, plain.length);
        Response r =
                Vecs.roundtrip(
                        card, session, plain[0] & 0xFF, plain[1] & 0xFF, plain[2] & 0xFF, data);
        assertEquals(expectedSw, r.sw(), name);
        Object response = c.get("response");
        if (response != null) {
            assertTemplate((String) response, r.data(), card, a, name);
        }
    }

    private static byte[] tryA(Card card) {
        byte[] rapdu = card.transmit(Vecs.unhex("80E0000000"));
        return Vecs.sw(rapdu) == 0x9000 ? Arrays.copyOf(rapdu, 33) : new byte[33];
    }

    private static void checkResponse(String sym, byte[] rapdu, byte[] a, byte[] apdu, String name)
            throws Exception {
        if (sym.equals("{A}")) {
            assertArrayEquals(a, Arrays.copyOf(rapdu, 33), name);
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
        assertTemplate(sym, Arrays.copyOf(rapdu, rapdu.length - 2), null, a, name);
    }

    /**
     * Matches a response template of hex literals and {@code {symbols}} against the inner payload.
     * {@code {masterPublicKey.any}} accepts any 33-byte compressed secp256k1 point.
     */
    private static void assertTemplate(
            String template, byte[] actual, Card card, byte[] a, String name) {
        int pos = 0;
        int i = 0;
        while (i < template.length()) {
            if (template.charAt(i) == '{') {
                int close = template.indexOf('}', i);
                String sym = template.substring(i + 1, close);
                if (sym.equals("masterPublicKey.any")) {
                    assertTrue(actual.length - pos >= 33, name + ": response too short");
                    byte[] pk = Arrays.copyOfRange(actual, pos, pos + 33);
                    assertTrue(pk[0] == 2 || pk[0] == 3, name + ": masterPublicKey.any prefix");
                    Crypto.decompress(pk); // throws unless x is on the curve
                    pos += 33;
                } else if (sym.startsWith("sig.ecdsa.")) {
                    // 64 bytes r ‖ s, verified with the host helper under the template key
                    assertTrue(actual.length - pos >= 64, name + ": response too short");
                    byte[] sig = Arrays.copyOfRange(actual, pos, pos + 64);
                    String keyName =
                            switch (sym.substring("sig.ecdsa.".length())) {
                                case "bip84Account" -> "btc-bip84-account";
                                default -> sym.substring("sig.ecdsa.".length());
                            };
                    byte[] pk =
                            Crypto.decompress(Vecs.hex(Vecs.secpTemplate(keyName), "publicKey"));
                    assertTrue(
                            Ecdsa.verify(pk, Vecs.digest(), sig),
                            name + ": invalid ECDSA signature under " + keyName);
                    pos += 64;
                } else if (sym.startsWith("sig.bip340.")) {
                    // 64 bytes R_x ‖ s under the BIP-340 output key of the template
                    assertTrue(actual.length - pos >= 64, name + ": response too short");
                    byte[] sig = Arrays.copyOfRange(actual, pos, pos + 64);
                    byte[] pk = Vecs.hex(Vecs.secpTemplate("btc-bip86"), "publicKey");
                    byte[] internal = Arrays.copyOfRange(pk, 1, 33);
                    byte[] out =
                            sym.equals("sig.bip340.bip86")
                                    ? Bip340.outputKey(Crypto.decompress(pk), Vecs.tweakBip86())
                                    : internal;
                    assertTrue(
                            Bip340.verify(out, Vecs.message(), sig),
                            name + ": invalid BIP-340 signature under " + sym);
                    pos += 64;
                } else if (sym.equals("wei.any")) {
                    // 64 bytes X ‖ Y of a Wei25519 point other than the base point
                    assertTrue(actual.length - pos >= 64, name + ": response too short");
                    byte[] wei = Arrays.copyOfRange(actual, pos, pos + 64);
                    Wei25519Map.encode(wei); // throws unless X ‖ Y is on Wei25519
                    assertTrue(
                            !Arrays.equals(wei, Vecs.weiBase()),
                            name + ": wei.any must not be the base point");
                    pos += 64;
                } else if (sym.equals("ed25519.S.any")) {
                    // 32 bytes le32(S) with int_le(S) < l
                    assertTrue(actual.length - pos >= 32, name + ": response too short");
                    byte[] s = Arrays.copyOfRange(actual, pos, pos + 32);
                    byte[] be = new byte[32];
                    for (int j = 0; j < 32; j++) {
                        be[j] = s[31 - j];
                    }
                    assertTrue(
                            new java.math.BigInteger(1, be).compareTo(Vecs.ED25519_L) < 0,
                            name + ": S out of range");
                    pos += 32;
                } else {
                    byte[] want = Vecs.symbol(sym, card, a);
                    assertSlice(want, actual, pos, name + ": {" + sym + "}");
                    pos += want.length;
                }
                i = close + 1;
            } else {
                int next = template.indexOf('{', i);
                String lit = next < 0 ? template.substring(i) : template.substring(i, next);
                byte[] want = Vecs.unhex(lit);
                assertSlice(want, actual, pos, name);
                pos += want.length;
                i = next < 0 ? template.length() : next;
            }
        }
        assertEquals(actual.length, pos, name + ": response length");
    }

    private static void assertSlice(byte[] want, byte[] actual, int pos, String name) {
        assertTrue(actual.length - pos >= want.length, name + ": response too short");
        assertArrayEquals(want, Arrays.copyOfRange(actual, pos, pos + want.length), name);
    }
}
