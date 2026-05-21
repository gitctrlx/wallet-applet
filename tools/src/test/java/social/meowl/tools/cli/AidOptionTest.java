/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.cli;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import social.meowl.tools.core.MeowlAid;

/** Tests for the {@link AidOption} mixin. */
class AidOptionTest {

    @Test
    @DisplayName("default value parses to the canonical meowl AID")
    void defaultIsCanonical() {
        AidOption option = new AidOption();
        assertArrayEquals(MeowlAid.defaultBytes(), option.bytes());
    }

    @Test
    @DisplayName("a custom AID parses correctly")
    void customAid() {
        AidOption option = new AidOption();
        option.aid = "F06D656F776C02";
        assertArrayEquals(
                new byte[] {
                    (byte) 0xF0, 0x6D, 0x65, 0x6F, 0x77, 0x6C, 0x02,
                },
                option.bytes());
    }

    @Test
    @DisplayName("invalid hex propagates as IllegalArgumentException")
    void invalidHex() {
        AidOption option = new AidOption();
        option.aid = "ZZZZZZZZZZ";
        assertThrows(IllegalArgumentException.class, option::bytes);
    }

    @Test
    @DisplayName("AID outside the ISO 7816-5 length window is rejected")
    void illegalLength() {
        AidOption option = new AidOption();
        option.aid = "AB"; // 1 byte — below MIN_LEN
        assertThrows(IllegalArgumentException.class, option::bytes);
    }
}
