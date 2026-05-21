/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.core;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** Tests for {@link MeowlAid}. */
class MeowlAidTest {

    @Test
    @DisplayName("default AID is the 7-byte F0 + \"meowl\" + 0x01 sequence")
    void defaultBytes() {
        byte[] expected = {(byte) 0xF0, 0x6D, 0x65, 0x6F, 0x77, 0x6C, 0x01};
        assertArrayEquals(expected, MeowlAid.defaultBytes());
    }

    @Test
    @DisplayName("default AID hex constant matches the byte representation")
    void defaultHexMatches() {
        assertEquals("F06D656F776C01", MeowlAid.DEFAULT_HEX);
        assertArrayEquals(MeowlAid.defaultBytes(), Hex.decode(MeowlAid.DEFAULT_HEX));
    }

    @Test
    @DisplayName("defaultBytes() returns a defensive copy")
    void defensiveCopy() {
        byte[] a = MeowlAid.defaultBytes();
        byte[] b = MeowlAid.defaultBytes();
        assertNotSame(a, b);
        a[0] = 0x00;
        assertEquals((byte) 0xF0, MeowlAid.defaultBytes()[0]);
    }

    @ParameterizedTest
    @ValueSource(ints = {MeowlAid.MIN_LEN, 7, 10, MeowlAid.MAX_LEN})
    @DisplayName("parse accepts AIDs of legal length")
    void parseAcceptsLegalLength(int length) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length; i++) sb.append("AB");
        byte[] parsed = MeowlAid.parse(sb.toString());
        assertEquals(length, parsed.length);
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 1, MeowlAid.MIN_LEN - 1, MeowlAid.MAX_LEN + 1, 32})
    @DisplayName("parse rejects AIDs outside the ISO 7816-5 length window")
    void parseRejectsIllegalLength(int length) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length; i++) sb.append("AB");
        assertThrows(IllegalArgumentException.class, () -> MeowlAid.parse(sb.toString()));
    }

    @Test
    @DisplayName("parse rejects malformed hex with the same error class")
    void parseRejectsMalformed() {
        assertThrows(IllegalArgumentException.class, () -> MeowlAid.parse("ZZZZZZZZZZ"));
    }

    @Test
    @DisplayName("isDefault flags only the canonical default AID")
    void isDefault() {
        assertTrue(MeowlAid.isDefault(MeowlAid.defaultBytes()));
        assertFalse(
                MeowlAid.isDefault(new byte[] {(byte) 0xF0, 0x6D, 0x65, 0x6F, 0x77, 0x6C, 0x02}));
        assertFalse(MeowlAid.isDefault(new byte[] {0x00}));
    }
}
