// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: MIT OR Apache-2.0
package org.qntx.card.vectors;

import java.util.List;

/**
 * {@code kdf.json}: the NIST SP 800-38B App. D.1 AES-CMAC examples (an independent oracle asserted
 * against the published tags), the one-step KDF of SP 800-56C Rev. 2 §4.1 option 1 and the
 * counter-mode KDF108 of SP 800-108r1 §4.1 (spec/protocol.md §1, §8.1, §10.1).
 */
final class KdfDoc {
    /** NIST SP 800-38B D.1 AES-128 key and the message stream of examples 1–4. */
    private static final String CMAC_KEY = "2b7e151628aed2a6abf7158809cf4f3c";

    private static final String[] CMAC_PARTS = {
        "6bc1bee22e409f96e93d7e117393172a",
        "ae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411",
        "e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
    };
    private static final int[] CMAC_LENS = {0, 16, 40, 64};
    private static final String[] CMAC_TAGS = {
        "bb1d6929e95937287fa37d129b756746",
        "070a16b46b4d4144f79bdd9dd04a287c",
        "dfa66747de9ae63030ca32611497c827",
        "51f0bebf7e3b9d92fc49741779363cfe",
    };

    private static final byte[] SESSION_LABEL = Vec.ascii("qntx-card/v1/kdf-session");
    private static final byte[] TRANSFER_LABEL = Vec.ascii("qntx-card/v1/kdf-transfer");
    private static final byte[] WRAP_LABEL = Vec.ascii("qntx-card/v1/wrap");

    private KdfDoc() {}

    static Object document() {
        byte[] z = Vec.det("kdf/z");
        byte[] ctx = Vec.det("kdf/ctx");
        List<Object> kdf =
                List.of(
                        kdf(z, SESSION_LABEL, ctx, 64),
                        kdf(Vec.det("kdf/z-transfer"), TRANSFER_LABEL, ctx, 32),
                        kdf(z, SESSION_LABEL, ctx, 33),
                        kdf(z, SESSION_LABEL, new byte[0], 16));
        List<Object> kdf108 =
                List.of(
                        kdf108(Vec.det("kdf108/key/0", 16), ctx),
                        kdf108(Vec.det("kdf108/key/1", 16), ctx));
        return Vec.object("cmac", cmacCases(), "kdf", kdf, "kdf108", kdf108);
    }

    /** NIST examples 1–4; the computed tag is asserted against the published value first. */
    private static List<Object> cmacCases() {
        byte[] key = Vec.unhex(CMAC_KEY);
        StringBuilder stream = new StringBuilder();
        return java.util.stream.IntStream.range(0, 4)
                .<Object>mapToObj(
                        i -> {
                            if (i > 0) {
                                stream.append(CMAC_PARTS[i - 1]);
                            }
                            byte[] message = Vec.unhex(stream.toString());
                            byte[] tag = Crypto.cmac(key, message);
                            if (!Vec.hex(tag).equals(CMAC_TAGS[i])) {
                                throw new IllegalStateException(
                                        "CMAC mismatch, example " + (i + 1));
                            }
                            return Vec.object(
                                    "key",
                                    CMAC_KEY,
                                    "message",
                                    Vec.hex(message),
                                    "tag",
                                    CMAC_TAGS[i]);
                        })
                .toList();
    }

    private static Object kdf(byte[] z, byte[] label, byte[] ctx, int len) {
        return Vec.object(
                "z", Vec.hex(z),
                "label", Vec.hex(label),
                "ctx", Vec.hex(ctx),
                "len", len,
                "out", Vec.hex(Crypto.kdf(z, label, ctx, len)));
    }

    private static Object kdf108(byte[] key, byte[] ctx) {
        return Vec.object(
                "key", Vec.hex(key),
                "label", Vec.hex(WRAP_LABEL),
                "ctx", Vec.hex(ctx),
                "out", Vec.hex(Crypto.kdf108(key, WRAP_LABEL, ctx)));
    }
}
