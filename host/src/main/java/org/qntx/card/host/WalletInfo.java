// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.host;

import java.util.ArrayList;
import java.util.List;

/**
 * The {@code WalletInfo} response of spec/protocol.md §9.2, returned by {@code CREATE}, {@code
 * VERIFY} and {@code IMPORT}: {@code masterPublicKey(33) ‖ origin(1) ‖ c(1) ‖ ID₁(16) ‖ … ‖
 * ID_c(16)} — length {@code 35 + 16c} with {@code c ∈ [1, 3]}.
 */
public record WalletInfo(byte[] masterPublicKey, int origin, List<byte[]> members) {

    /** Parses and validates the wire form; {@code IllegalArgumentException} on any violation. */
    public static WalletInfo parse(byte[] data) {
        if (data == null || data.length < 51) {
            throw new IllegalArgumentException("WalletInfo must be at least 51 bytes");
        }
        int c = data[34] & 0xFF;
        if (c < 1 || c > 3 || data.length != 35 + 16 * c) {
            throw new IllegalArgumentException("bad WalletInfo member count or length");
        }
        if (data[33] != 0x01 && data[33] != 0x02) {
            throw new IllegalArgumentException("WalletInfo origin must be 0x01 or 0x02");
        }
        if (data[0] != 0x02 && data[0] != 0x03) {
            throw new IllegalArgumentException("masterPublicKey must be a compressed point");
        }
        byte[] master = new byte[33];
        System.arraycopy(data, 0, master, 0, 33);
        List<byte[]> members = new ArrayList<>(c);
        for (int i = 0; i < c; i++) {
            byte[] id = new byte[16];
            System.arraycopy(data, 35 + 16 * i, id, 0, 16);
            members.add(id);
        }
        return new WalletInfo(master, data[33] & 0xFF, List.copyOf(members));
    }
}
