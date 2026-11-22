// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: MIT OR Apache-2.0
package org.qntx.card.vectors;

import java.util.Arrays;
import java.util.List;

/**
 * {@code wrap.json}: seed wrapping of spec/protocol.md §7.2 and §10.1 — {@code K_enc ‖ K_mac =
 * KDF108(wrapKey, "qntx-card/v1/wrap", accessHash)}, {@code ct = CBC(K_enc, 0¹⁶, seed)}, {@code tag
 * = CMAC(K_mac, ct)} and the fingerprint {@code SHA-256("qntx-card/v1/fingerprint" ‖ seed)}.
 */
final class WrapDoc {
    private static final byte[] WRAP_LABEL = Vec.ascii("qntx-card/v1/wrap");
    private static final byte[] FP_LABEL = Vec.ascii("qntx-card/v1/fingerprint");
    private static final byte[] ZERO_IV = new byte[16];

    private WrapDoc() {}

    static Object document() {
        return Vec.object(
                "wrapLabel",
                Vec.hex(WRAP_LABEL),
                "fingerprintLabel",
                Vec.hex(FP_LABEL),
                "cases",
                List.of(
                        wrapCase("wrap-1"),
                        wrapCase("wrap-2"),
                        wrapCase("wrap-3"),
                        wrap(
                                "wrap-template-seed",
                                Vec.det("wrap/template/wrapKey", 16),
                                Vec.det("wrap/template/accessHash"),
                                DerivationDoc.TEMPLATE_SEED)));
    }

    private static Object wrapCase(String name) {
        return wrap(
                name,
                Vec.det(name.replace('-', '/') + "/wrapKey", 16),
                Vec.det(name.replace('-', '/') + "/accessHash"),
                Vec.det(name.replace('-', '/') + "/seed", 64));
    }

    private static Object wrap(String name, byte[] wrapKey, byte[] accessHash, byte[] seed) {
        byte[] keys = Crypto.kdf108(wrapKey, WRAP_LABEL, accessHash);
        byte[] kEnc = Arrays.copyOfRange(keys, 0, 16);
        byte[] kMac = Arrays.copyOfRange(keys, 16, 32);
        byte[] ct = Crypto.aesCbc(kEnc, ZERO_IV, seed, true);
        byte[] tag = Crypto.cmac(kMac, ct);
        byte[] fp = Crypto.sha256(FP_LABEL, seed);
        return Vec.object(
                "name", name,
                "wrapKey", Vec.hex(wrapKey),
                "accessHash", Vec.hex(accessHash),
                "seed", Vec.hex(seed),
                "kEnc", Vec.hex(kEnc),
                "kMac", Vec.hex(kMac),
                "ct", Vec.hex(ct),
                "tag", Vec.hex(tag),
                "fp", Vec.hex(fp));
    }
}
