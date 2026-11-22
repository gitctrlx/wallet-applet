// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: MIT OR Apache-2.0
package org.qntx.card.vectors;

import java.nio.charset.StandardCharsets;
import java.util.List;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

/**
 * {@code access.json}: the access-code rules of spec/protocol.md §7.1 — 6–64 characters of
 * printable ASCII hashed with Argon2id (m = 65536 KiB, t = 3, p = 4, T = 32, version 0x13) over the
 * per-card salt {@code "qntx-card/v1/access" ‖ ID(A)}, and the codes a host MUST reject before
 * hashing.
 */
final class AccessDoc {
    private static final byte[] LABEL = Vec.ascii("qntx-card/v1/access");
    private static final int M = 65536;
    private static final int T = 3;
    private static final int P = 4;
    private static final int TAG = 32;

    private AccessDoc() {}

    static Object document() {
        byte[] card1 = Ids.cardId(Crypto.compress(Crypto.publicKey(CertDoc.CARD1)));
        byte[] card2 = Ids.cardId(Crypto.compress(Crypto.publicKey(CertDoc.CARD2)));
        String printable = new String(Vec.seq(0x20, 64), StandardCharsets.US_ASCII);
        List<Object> valid =
                List.of(
                        valid("six-digits-card1", "123456", card1),
                        valid("six-digits-card2", "123456", card2),
                        valid("printable-64-card1", printable, card1));
        List<Object> rejected =
                List.of(
                        rejected("five-chars", "12345", "length"),
                        rejected("sixty-five-chars", "a".repeat(65), "length"),
                        rejected("non-ascii", "12345é", "character"),
                        rejected("control-tab", "12345\t6", "character"),
                        rejected("del", "123456\u007f", "character"));
        return Vec.object(
                "params",
                        Vec.object(
                                "saltLabel", Vec.hex(LABEL),
                                "m", M,
                                "t", T,
                                "p", P,
                                "T", TAG,
                                "version", Argon2Parameters.ARGON2_VERSION_13),
                "valid", valid,
                "rejected", rejected);
    }

    private static Object valid(String name, String code, byte[] cardId) {
        String reason = invalidReason(code);
        if (reason != null) {
            throw new IllegalStateException("valid case rejected by §7.1 rules: " + name);
        }
        byte[] salt = new byte[LABEL.length + 16];
        System.arraycopy(LABEL, 0, salt, 0, LABEL.length);
        System.arraycopy(cardId, 0, salt, LABEL.length, 16);
        return Vec.object(
                "name", name,
                "code", code,
                "codeHex", Vec.hex(code.getBytes(StandardCharsets.UTF_8)),
                "cardId", Vec.hex(cardId),
                "salt", Vec.hex(salt),
                "accessHash", Vec.hex(argon2id(code.getBytes(StandardCharsets.UTF_8), salt)));
    }

    private static Object rejected(String name, String code, String reason) {
        String actual = invalidReason(code);
        if (!reason.equals(actual)) {
            throw new IllegalStateException(
                    "rejected case " + name + " expected " + reason + ", got " + actual);
        }
        return Vec.object(
                "name",
                name,
                "codeHex",
                Vec.hex(code.getBytes(StandardCharsets.UTF_8)),
                "reason",
                reason);
    }

    /** {@code null} when {@code code} satisfies §7.1, else the reason a host rejects it. */
    private static String invalidReason(String code) {
        if (code.length() < 6 || code.length() > 64) {
            return "length";
        }
        for (int i = 0; i < code.length(); i++) {
            char c = code.charAt(i);
            if (c < 0x20 || c > 0x7E) {
                return "character";
            }
        }
        return null;
    }

    private static byte[] argon2id(byte[] password, byte[] salt) {
        Argon2BytesGenerator g = new Argon2BytesGenerator();
        g.init(
                new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                        .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                        .withMemoryAsKB(M)
                        .withIterations(T)
                        .withParallelism(P)
                        .withSalt(salt)
                        .build());
        byte[] out = new byte[TAG];
        g.generateBytes(password, out);
        return out;
    }
}
