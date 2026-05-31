/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.core;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Unit tests for the host-side {@link Ndef} URI-record codec. */
class NdefTest {

    /**
     * The applet's install-time default: {@code NLEN=17} + URI record for {@code
     * https://meowl.social}.
     */
    private static final byte[] DEFAULT_FILE = {
        (byte) 0x00,
        (byte) 0x11,
        (byte) 0xD1,
        (byte) 0x01,
        (byte) 0x0D,
        (byte) 0x55,
        (byte) 0x04,
        'm',
        'e',
        'o',
        'w',
        'l',
        '.',
        's',
        'o',
        'c',
        'i',
        'a',
        'l'
    };

    @Test
    @DisplayName("encodes https://meowl.social to the applet's default NDEF file byte-for-byte")
    void encodesDefaultRecord() {
        assertArrayEquals(DEFAULT_FILE, Ndef.encodeUriFile("https://meowl.social"));
    }

    @Test
    @DisplayName("decodes the default NDEF file back to its URI")
    void decodesDefaultRecord() {
        assertEquals("https://meowl.social", Ndef.decodeUriFile(DEFAULT_FILE));
    }

    @Test
    @DisplayName("round-trips a meowl profile link")
    void roundTripsProfileLink() {
        String uri = "https://meowl.social/p/nprofile1qqsabc123";
        assertEquals(uri, Ndef.decodeUriFile(Ndef.encodeUriFile(uri)));
    }

    @Test
    @DisplayName("applies the longest matching abbreviation prefix")
    void appliesLongestPrefix() {
        byte[] file = Ndef.encodeUriFile("https://www.example.com");
        assertEquals((byte) 0x02, file[6], "prefix code should be https://www.");
        assertEquals("https://www.example.com", Ndef.decodeUriFile(file));
    }

    @Test
    @DisplayName("falls back to the no-prefix code for unknown schemes")
    void noPrefixFallback() {
        byte[] file = Ndef.encodeUriFile("nostr:npub1xyz");
        assertEquals((byte) 0x00, file[6], "prefix code should be none");
        assertEquals("nostr:npub1xyz", Ndef.decodeUriFile(file));
    }

    @Test
    @DisplayName("rejects an empty URI")
    void rejectsEmptyUri() {
        assertThrows(IllegalArgumentException.class, () -> Ndef.encodeUriFile(""));
    }

    @Test
    @DisplayName("rejects a URI too long for a short record")
    void rejectsTooLong() {
        String uri = "https://" + "a".repeat(256);
        assertThrows(IllegalArgumentException.class, () -> Ndef.encodeUriFile(uri));
    }

    @Test
    @DisplayName("rejects decoding a non-URI record")
    void rejectsNonUriRecord() {
        byte[] notUri = {
            (byte) 0x00,
            (byte) 0x05,
            (byte) 0xD1,
            (byte) 0x01,
            (byte) 0x01,
            (byte) 0x54,
            (byte) 0x00
        };
        assertThrows(IllegalArgumentException.class, () -> Ndef.decodeUriFile(notUri));
    }
}
