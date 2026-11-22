// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.util.Arrays;
import java.util.Map;
import javacard.framework.Applet;
import org.junit.jupiter.api.Test;
import org.qntx.card.sim.Card;
import org.qntx.card.tests.Spec;
import org.qntx.card.tests.Vecs;

/**
 * {@link Wei25519#mulBase} against {@code derivation.json wei25519} (architecture §14.4 W8): the
 * base point itself, the eight vector points by their {@code scalar}, and every slip10/template
 * {@code wei} recomputed through the same clamp+reverse+reduce the PUBLIC_KEY path applies.
 */
final class Wei25519Test {

    private Applet applet;

    private byte[] mulBase(byte[] scalar) {
        byte[] out = new byte[65];
        Internals.wei(applet).mulBase(scalar, (short) 0, out, (short) 0);
        return out;
    }

    /** The Wei scalar of an ed25519 node: {@code clamp(SHA-512(k)[0..32))} reversed, mod ℓ. */
    private byte[] scalarOf(byte[] privateKey) {
        byte[] h = new byte[64];
        try {
            java.security.MessageDigest sha = java.security.MessageDigest.getInstance("SHA-512");
            h = sha.digest(privateKey);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
        h[0] &= 0xF8;
        h[31] &= 0x7F;
        h[31] |= 0x40;
        byte[] be = new byte[32];
        for (int i = 0; i < 32; i++) {
            be[i] = h[31 - i];
        }
        ModArith m = Internals.modArith(applet);
        m.reduce(ModArith.MOD_L, be, (short) 0);
        return be;
    }

    private static byte[] wei(byte[] uncompressed) {
        return Arrays.copyOfRange(uncompressed, 1, 65);
    }

    @Test
    void baseAndPoints() {
        Card card = Vecs.blankSelf();
        applet = card.applet(Spec.WALLET_AID);
        Map<String, Object> w = Vecs.obj(Vecs.load("derivation.json"), "wei25519");
        // scalar 1 gives the base point W(B)
        byte[] one = new byte[32];
        one[31] = 1;
        assertArrayEquals(Vecs.hex(Vecs.obj(w, "base"), "wei"), wei(mulBase(one)), "base");
        for (Map<String, Object> p : Vecs.list(w, "points")) {
            assertArrayEquals(
                    Vecs.hex(p, "wei"),
                    wei(mulBase(Vecs.hex(p, "scalar"))),
                    (String) p.get("name"));
        }
    }

    @Test
    void slip10AndTemplateWei() {
        Card card = Vecs.blankSelf();
        applet = card.applet(Spec.WALLET_AID);
        Map<String, Object> doc = Vecs.load("derivation.json");
        for (Map<String, Object> v : Vecs.list(doc, "slip10")) {
            for (Map<String, Object> node : Vecs.list(v, "nodes")) {
                byte[] scalar = scalarOf(Vecs.hex(node, "privateKey"));
                assertArrayEquals(
                        Vecs.hex(node, "wei"), wei(mulBase(scalar)), (String) node.get("path"));
            }
        }
        Map<String, Object> templates = Vecs.obj(doc, "templates");
        for (Map<String, Object> t : Vecs.list(templates, "ed25519")) {
            byte[] scalar = scalarOf(Vecs.hex(t, "privateKey"));
            assertArrayEquals(Vecs.hex(t, "wei"), wei(mulBase(scalar)), (String) t.get("name"));
        }
    }
}
