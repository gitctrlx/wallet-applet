// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.host;

import java.util.Locale;

/** Card identifiers of spec/protocol.md §1: {@code ID(A)} and the human short ID. */
public final class Ids {
    private Ids() {}

    /** {@code ID(A) = SHA-256(A)[0..16)} for the compressed identity key {@code A(33)}. */
    public static byte[] cardId(byte[] a) {
        byte[] id = new byte[16];
        System.arraycopy(Crypto.sha256(a), 0, id, 0, 16);
        return id;
    }

    /** {@code "XXXX-XXXX"}, uppercase hex of {@code ID(A)[0..4)}. */
    public static String shortId(byte[] a) {
        byte[] id = cardId(a);
        String hex = String.format(Locale.ROOT, "%02X%02X%02X%02X", id[0], id[1], id[2], id[3]);
        return hex.substring(0, 4) + "-" + hex.substring(4);
    }
}
