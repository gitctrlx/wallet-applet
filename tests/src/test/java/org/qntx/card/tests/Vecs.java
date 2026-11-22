// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.tests;

import com.fasterxml.jackson.jr.ob.JSON;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import org.qntx.card.WalletApplet;
import org.qntx.card.host.Certificates;
import org.qntx.card.host.Crypto;
import org.qntx.card.host.Ids;
import org.qntx.card.host.Open;
import org.qntx.card.host.Response;
import org.qntx.card.host.Session;
import org.qntx.card.sim.Card;

/**
 * The committed vectors of spec/vectors plus the card/session plumbing the command tests share.
 * Test CA material comes from {@code cert.json} (ca1 personalizes the card under test).
 */
public final class Vecs {
    public static final SecureRandom RND = new SecureRandom();
    private static final Path DIR = Path.of(System.getProperty("qntx.vectors", "spec/vectors"));

    private Vecs() {}

    public static Map<String, Object> load(String name) {
        try {
            return JSON.std.mapFrom(Files.readAllBytes(DIR.resolve(name)));
        } catch (IOException e) {
            throw new IllegalStateException("cannot read vector file " + name, e);
        }
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> obj(Map<String, Object> doc, String key) {
        return (Map<String, Object>) doc.get(key);
    }

    @SuppressWarnings("unchecked")
    public static List<Map<String, Object>> list(Map<String, Object> doc, String key) {
        return (List<Map<String, Object>>) doc.get(key);
    }

    public static byte[] hex(Map<String, Object> obj, String key) {
        return HexFormat.of().parseHex((String) obj.get(key));
    }

    public static byte[] unhex(String s) {
        return HexFormat.of().parseHex(s);
    }

    public static int sw(byte[] rapdu) {
        return ((rapdu[rapdu.length - 2] & 0xFF) << 8) | (rapdu[rapdu.length - 1] & 0xFF);
    }

    /** cert.json's ca1 private scalar: the batch CA of every test card. */
    public static BigInteger caPrivate() {
        Map<String, Object> cert = load("cert.json");
        return new BigInteger(1, hex(list(cert, "cas").get(0), "private"));
    }

    public static BigInteger ca2Private() {
        Map<String, Object> cert = load("cert.json");
        return new BigInteger(1, hex(list(cert, "cas").get(1), "private"));
    }

    /** cert.json's ca1 public key, the anchor the test cards are personalized under. */
    public static byte[] caPublic() {
        return hex(list(load("cert.json"), "cas").get(0), "public");
    }

    public static byte[] ca2Public() {
        return hex(list(load("cert.json"), "cas").get(1), "public");
    }

    /** cert.json's card2 certificate: valid under ca1 for a different identity. */
    public static byte[] certOtherA() {
        for (Map<String, Object> v : list(load("cert.json"), "verify")) {
            if (v.get("name").equals("card2-under-ca1")) {
                return hex(v, "cert");
            }
        }
        throw new IllegalStateException("cert.json lacks card2-under-ca1");
    }

    /** A freshly installed, selected card in FACTORY. */
    public static Card factory() {
        Card card = new Card();
        card.install(Spec.WALLET_AID, WalletApplet.class);
        card.transmit(Spec.SELECT);
        return card;
    }

    /** The card's compressed identity key from GET_IDENTITY (FACTORY only). */
    public static byte[] cardA(Card card) {
        byte[] rapdu = card.transmit(unhex("80E0000000"));
        if (sw(rapdu) != 0x9000) {
            throw new IllegalStateException(
                    "GET_IDENTITY failed: " + Integer.toHexString(sw(rapdu)));
        }
        return Arrays.copyOf(rapdu, 33);
    }

    /** A card personalized under ca1 (BLANK); returns the card and its A/cert. */
    public static Card blank(byte[] cert) {
        Card card = factory();
        byte[] rapdu = card.transmit(personalizeApdu(cert));
        if (sw(rapdu) != 0x9000) {
            throw new IllegalStateException(
                    "PERSONALIZE failed: " + Integer.toHexString(sw(rapdu)));
        }
        return card;
    }

    /** The common case: a fresh card personalized with a cert for its own A under ca1. */
    public static Card blankSelf() {
        Card card = factory();
        return blankFor(card, cardA(card));
    }

    public static Card blankFor(Card card, byte[] a) {
        byte[] rapdu = card.transmit(personalizeApdu(certFor(a)));
        if (sw(rapdu) != 0x9000) {
            throw new IllegalStateException(
                    "PERSONALIZE failed: " + Integer.toHexString(sw(rapdu)));
        }
        return card;
    }

    /** cert = A ‖ Sign(ca1, "qntx-card/v1/cert" ‖ A) for the card's own A. */
    public static byte[] certFor(byte[] a) {
        return Certificates.issue(caPrivate(), a);
    }

    public static byte[] personalizeApdu(byte[] cert) {
        byte[] apdu = new byte[5 + 162];
        apdu[0] = (byte) 0x80;
        apdu[1] = (byte) 0xE2;
        apdu[4] = (byte) 162;
        System.arraycopy(cert, 0, apdu, 5, 97);
        System.arraycopy(caPublic(), 0, apdu, 102, 65);
        return apdu;
    }

    /** OPEN on the card and host-verify the response; the shared session. */
    public static Session open(Card card) throws Exception {
        Open.Request req = Open.request(RND);
        byte[] rapdu = card.transmit(req.apdu());
        return Open.response(req.secret(), req.apdu(), rapdu, List.of(caPublic()));
    }

    /** A command record round trip: returns the inner {@link Response}. */
    public static Response roundtrip(
            Card card, Session session, int ins, int p1, int p2, byte[] data) throws Exception {
        byte[] rapdu = card.transmit(session.wrap(ins, p1, p2, data));
        return session.unwrap(rapdu);
    }

    /**
     * Resolves an apdu.json {@code {symbol}} placeholder for the card under test. Symbols not
     * listed need no resolution in the cases that use them ({@code openResponse} is matched
     * structurally, {@code record0} comes from record.json).
     */
    public static byte[] symbol(String name, Card card, byte[] a) {
        return switch (name) {
            case "A" -> a;
            case "cert" -> certFor(a);
            case "cert.otherA" -> certOtherA();
            case "cert.otherCa" -> Certificates.issue(ca2Private(), a);
            case "caKey" -> caPublic();
            case "caKey.prefix03" -> mutate(caPublic(), 0, (byte) 0x03);
            case "caKey.xIsP" -> withCoord(caPublic(), 1);
            case "caKey.yIsP" -> withCoord(caPublic(), 33);
            case "caKey.offCurve" -> mutate(caPublic(), 64, (byte) (caPublic()[64] ^ 1));
            case "hostEph" -> hex(load("session.json"), "hostEph");
            case "hostEph.prefix02" -> mutate(hex(load("session.json"), "hostEph"), 0, (byte) 0x02);
            case "hostEph.offCurve" -> {
                byte[] e = hex(load("session.json"), "hostEph").clone();
                e[64] ^= 1;
                yield e;
            }
            case "record0" ->
                    Arrays.copyOfRange(
                            hex(list(load("record.json"), "commands").get(0), "apdu"), 5, 29);
            default -> throw new IllegalArgumentException("unknown symbol " + name);
        };
    }

    /** Substitutes {@code {name}} placeholders of an apdu.json APDU template. */
    public static byte[] resolveApdu(String template, Card card, byte[] a) {
        StringBuilder out = new StringBuilder();
        int i = 0;
        while (i < template.length()) {
            if (template.charAt(i) == '{') {
                int close = template.indexOf('}', i);
                String name = template.substring(i + 1, close);
                for (byte b : symbol(name, card, a)) {
                    out.append(String.format("%02x", b));
                }
                i = close + 1;
            } else {
                int next = template.indexOf('{', i);
                out.append(template, i, next < 0 ? template.length() : next);
                i = next < 0 ? template.length() : next;
            }
        }
        return unhex(out.toString());
    }

    public static String shortIdOf(byte[] a) {
        return Ids.shortId(a);
    }

    private static byte[] mutate(byte[] base, int off, byte v) {
        byte[] out = base.clone();
        out[off] = v;
        return out;
    }

    private static byte[] withCoord(byte[] base, int off) {
        byte[] out = base.clone();
        byte[] p = new byte[32];
        byte[] b = Crypto.DOMAIN.getCurve().getField().getCharacteristic().toByteArray();
        System.arraycopy(
                b,
                Math.max(0, b.length - 32),
                p,
                Math.max(0, 32 - b.length),
                Math.min(b.length, 32));
        System.arraycopy(p, 0, out, off, 32);
        return out;
    }
}
