/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import static org.junit.jupiter.api.Assertions.assertEquals;

import javacard.framework.ISO7816;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class MeowlAppletBufferWipeTest {

    @Test
    @DisplayName("secure-channel plaintext wipe preserves outbound envelope bytes")
    void secureChannelPlaintextWipePreservesOutboundEnvelopeBytes() {
        byte[] buffer = filled(96, (byte) 0x5A);
        short plainLen = 64;
        short envelopeLen = 48;

        MeowlApplet.wipeSecureChannelRequestTail(buffer, plainLen, envelopeLen);

        for (short i = 0; i < envelopeLen; i++) {
            assertEquals((byte) 0x5A, buffer[i], "envelope byte " + i);
        }
        for (short i = envelopeLen; i < (short) (ISO7816.OFFSET_CDATA + plainLen); i++) {
            assertEquals((byte) 0, buffer[i], "plaintext tail byte " + i);
        }
    }

    @Test
    @DisplayName("secure-channel exception path wipes the whole staged inner plaintext")
    void secureChannelExceptionPathWipesWholeStagedInnerPlaintext() {
        byte[] buffer = filled(64, (byte) 0x33);
        short plainLen = 20;

        MeowlApplet.wipeSecureChannelRequestTail(buffer, plainLen, (short) 0);

        for (short i = 0; i < ISO7816.OFFSET_CDATA; i++) {
            assertEquals((byte) 0x33, buffer[i], "outer header byte " + i);
        }
        for (short i = ISO7816.OFFSET_CDATA; i < (short) (ISO7816.OFFSET_CDATA + plainLen); i++) {
            assertEquals((byte) 0, buffer[i], "plaintext byte " + i);
        }
    }

    private static byte[] filled(int length, byte value) {
        byte[] out = new byte[length];
        for (int i = 0; i < out.length; i++) {
            out[i] = value;
        }
        return out;
    }
}
