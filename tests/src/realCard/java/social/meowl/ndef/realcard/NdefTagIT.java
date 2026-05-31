/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.ndef.realcard;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import social.meowl.wallet.realcard.support.RealCardClient;

/**
 * Real-card integration tests for the meowl NDEF Type 4 tag, driven over PCSC via {@link
 * RealCardClient}. The NDEF CAP must already be installed under the NFC Forum well-known instance
 * AID {@code D2760000850101} (e.g. {@code make install-ndef}).
 *
 * <p>These tests mutate the tag's NDEF file, so {@link #tearDown()} restores the install-time
 * default, leaving the card pointing at {@code https://meowl.social}.
 */
class NdefTagIT {

    private static final byte[] NDEF_AID = {(byte) 0xD2, 0x76, 0x00, 0x00, (byte) 0x85, 0x01, 0x01};

    private static final int FILE_CC = 0xE103;
    private static final int FILE_NDEF = 0xE104;
    private static final int SW_OK = 0x9000;
    private static final int MAX_BLOCK = 255;

    /** Install-time default: {@code NLEN=17} + URI record for {@code https://meowl.social}. */
    private static final byte[] DEFAULT_NDEF = {
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

    private RealCardClient card;

    @BeforeEach
    void setUp() {
        card = RealCardClient.connect(NDEF_AID);
    }

    @AfterEach
    void tearDown() {
        if (card != null) {
            try {
                writeNdef(DEFAULT_NDEF);
            } catch (RuntimeException ignored) {
                // best-effort restore; the next test's @BeforeEach surfaces real problems
            }
            card.close();
        }
    }

    @Test
    @DisplayName("Capability Container advertises an open, writable 1024-byte NDEF file")
    void capabilityContainerIsWritable() {
        selectFile(FILE_CC);
        byte[] cc = readBinary(0, 15);
        assertEquals((byte) 0x00, cc[14], "write access must be granted");
        assertEquals((byte) 0x04, cc[11], "max NDEF size hi byte (0x0400 = 1024)");
        assertEquals((byte) 0x00, cc[12], "max NDEF size lo byte");
    }

    @Test
    @DisplayName("the freshly installed tag serves the default meowl.social record")
    void defaultRecordPresent() {
        // Restore first so the assertion is independent of prior test ordering.
        writeNdef(DEFAULT_NDEF);
        assertArrayEquals(DEFAULT_NDEF, readNdef());
    }

    @Test
    @DisplayName("UPDATE_BINARY writes a profile URI that reads back byte-for-byte")
    void writesAndReadsBackUri() {
        byte[] record = uriRecord("meowl.social/p/itTEST");
        writeNdef(record);
        assertArrayEquals(record, readNdef());
    }

    private byte[] readNdef() {
        selectFile(FILE_NDEF);
        byte[] header = readBinary(0, 2);
        int nlen = ((header[0] & 0xFF) << 8) | (header[1] & 0xFF);
        byte[] out = new byte[2 + nlen];
        out[0] = header[0];
        out[1] = header[1];
        int off = 0;
        while (off < nlen) {
            byte[] part = readBinary(2 + off, Math.min(MAX_BLOCK, nlen - off));
            System.arraycopy(part, 0, out, 2 + off, part.length);
            off += part.length;
        }
        return out;
    }

    private void writeNdef(byte[] file) {
        selectFile(FILE_NDEF);
        updateBinary(0, new byte[] {0x00, 0x00});
        byte[] body = Arrays.copyOfRange(file, 2, file.length);
        int off = 0;
        while (off < body.length) {
            int chunk = Math.min(MAX_BLOCK, body.length - off);
            updateBinary(2 + off, Arrays.copyOfRange(body, off, off + chunk));
            off += chunk;
        }
        updateBinary(0, new byte[] {file[0], file[1]});
    }

    private void selectFile(int fileId) {
        ResponseAPDU r =
                card.transmit(
                        new CommandAPDU(
                                new byte[] {
                                    0x00,
                                    (byte) 0xA4,
                                    0x00,
                                    0x0C,
                                    0x02,
                                    (byte) (fileId >> 8),
                                    (byte) fileId
                                }));
        assertEquals(SW_OK, r.getSW(), "SELECT file");
    }

    private byte[] readBinary(int offset, int le) {
        ResponseAPDU r =
                card.transmit(
                        new CommandAPDU(
                                new byte[] {
                                    0x00,
                                    (byte) 0xB0,
                                    (byte) (offset >> 8),
                                    (byte) offset,
                                    (byte) le
                                }));
        assertEquals(SW_OK, r.getSW(), "READ_BINARY");
        return r.getData();
    }

    private void updateBinary(int offset, byte[] data) {
        byte[] apdu = new byte[5 + data.length];
        apdu[0] = 0x00;
        apdu[1] = (byte) 0xD6;
        apdu[2] = (byte) (offset >> 8);
        apdu[3] = (byte) offset;
        apdu[4] = (byte) data.length;
        System.arraycopy(data, 0, apdu, 5, data.length);
        assertEquals(SW_OK, card.transmit(new CommandAPDU(apdu)).getSW(), "UPDATE_BINARY");
    }

    private static byte[] uriRecord(String rest) {
        byte[] tail = rest.getBytes(StandardCharsets.US_ASCII);
        int payloadLen = 1 + tail.length;
        byte[] out = new byte[2 + 5 + tail.length];
        int i = 0;
        out[i++] = 0x00;
        out[i++] = (byte) (5 + tail.length);
        out[i++] = (byte) 0xD1;
        out[i++] = 0x01;
        out[i++] = (byte) payloadLen;
        out[i++] = 0x55;
        out[i++] = 0x04;
        System.arraycopy(tail, 0, out, i, tail.length);
        return out;
    }
}
