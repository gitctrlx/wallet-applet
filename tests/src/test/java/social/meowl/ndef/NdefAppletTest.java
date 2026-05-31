/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.ndef;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import java.util.Arrays;
import javacard.framework.AID;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Full APDU-level coverage of {@link NdefApplet} driven through jcardsim's {@code CardSimulator}.
 *
 * <p>NDEF carries no card-only cryptography, so the simulator is a faithful oracle for the entire
 * NFC Forum Type 4 read/write surface: application select, {@code SELECT} by file id, {@code
 * READ_BINARY} and {@code UPDATE_BINARY} against the Capability Container ({@code E103}) and the
 * NDEF file ({@code E104}), plus every bounds and access guard.
 */
class NdefAppletTest {

    private static final AID APPLET_AID = AIDUtil.create("F06D656F776C0301");

    private static final int FILE_CC = 0xE103;
    private static final int FILE_NDEF = 0xE104;

    private static final int CLA = 0x00;
    private static final int INS_SELECT = 0xA4;
    private static final int INS_READ_BINARY = 0xB0;
    private static final int INS_UPDATE_BINARY = 0xD6;
    private static final int SELECT_P1_BY_FILE_ID = 0x00;
    private static final int SELECT_P2_FIRST_OR_ONLY = 0x0C;

    private static final int SW_OK = 0x9000;
    private static final int SW_WRONG_LENGTH = 0x6700;
    private static final int SW_CONDITIONS_NOT_SATISFIED = 0x6985;
    private static final int SW_FILE_NOT_FOUND = 0x6A82;
    private static final int SW_INCORRECT_P1P2 = 0x6A86;
    private static final int SW_WRONG_P1P2 = 0x6B00;
    private static final int SW_INS_NOT_SUPPORTED = 0x6D00;

    /**
     * Capability Container after the read/write upgrade: write access {@code 00}, size {@code
     * 0400}.
     */
    private static final byte[] EXPECTED_CC = {
        (byte) 0x00,
        (byte) 0x0F, // CCLEN = 15
        (byte) 0x20, // mapping version 2.0
        (byte) 0x00,
        (byte) 0xFF, // MLe = 255
        (byte) 0x00,
        (byte) 0xFF, // MLc = 255
        (byte) 0x04,
        (byte) 0x06, // NDEF File Control TLV
        (byte) 0xE1,
        (byte) 0x04, // file id E104
        (byte) 0x04,
        (byte) 0x00, // max NDEF size = 1024
        (byte) 0x00, // read access granted
        (byte) 0x00 // write access granted
    };

    /**
     * Default payload seeded at install: {@code NLEN=17} + URI record for {@code
     * https://meowl.social}.
     */
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

    private CardSimulator sim;

    @BeforeEach
    void installAndSelect() {
        sim = new CardSimulator();
        sim.installApplet(APPLET_AID, NdefApplet.class);
        sim.selectApplet(APPLET_AID);
    }

    @Test
    @DisplayName("READ_BINARY of the Capability Container returns the read/write CC verbatim")
    void readsCapabilityContainer() {
        assertSw(SW_OK, selectFile(FILE_CC));
        ResponseAPDU read = readBinary(0, EXPECTED_CC.length);
        assertSw(SW_OK, read);
        assertArrayEquals(EXPECTED_CC, read.getData());
    }

    @Test
    @DisplayName("READ_BINARY of the NDEF file returns the default meowl.social record")
    void readsDefaultNdef() {
        assertSw(SW_OK, selectFile(FILE_NDEF));
        ResponseAPDU read = readBinary(0, DEFAULT_NDEF.length);
        assertSw(SW_OK, read);
        assertArrayEquals(DEFAULT_NDEF, read.getData());
    }

    @Test
    @DisplayName("UPDATE_BINARY rewrites the NDEF file and reads back byte-for-byte")
    void updatesAndReadsBack() {
        byte[] record = uriRecord("a.bc");
        assertSw(SW_OK, selectFile(FILE_NDEF));
        assertSw(SW_OK, updateBinary(0, record));

        ResponseAPDU read = readBinary(0, record.length);
        assertSw(SW_OK, read);
        assertArrayEquals(record, read.getData());
    }

    @Test
    @DisplayName("UPDATE_BINARY honours the NFC Forum write procedure (NLEN=0, payload, NLEN)")
    void honoursNfcForumWriteProcedure() {
        byte[] record = uriRecord("meowl.social/p/x");
        byte[] body = Arrays.copyOfRange(record, 2, record.length);
        byte[] nlen = {record[0], record[1]};

        assertSw(SW_OK, selectFile(FILE_NDEF));
        assertSw(SW_OK, updateBinary(0, new byte[] {0x00, 0x00})); // clear NLEN
        assertSw(SW_OK, updateBinary(2, body)); // write payload
        assertSw(SW_OK, updateBinary(0, nlen)); // commit NLEN

        ResponseAPDU read = readBinary(0, record.length);
        assertSw(SW_OK, read);
        assertArrayEquals(record, read.getData());
    }

    @Test
    @DisplayName("UPDATE_BINARY against the read-only Capability Container is rejected")
    void rejectsCapabilityContainerWrite() {
        assertSw(SW_OK, selectFile(FILE_CC));
        assertSw(SW_CONDITIONS_NOT_SATISFIED, updateBinary(0, new byte[] {0x00}));
    }

    @Test
    @DisplayName("UPDATE_BINARY without a selected file is rejected")
    void rejectsWriteWithoutSelection() {
        assertSw(SW_CONDITIONS_NOT_SATISFIED, updateBinary(0, new byte[] {0x00}));
    }

    @Test
    @DisplayName("READ_BINARY without a selected file is rejected")
    void rejectsReadWithoutSelection() {
        assertSw(SW_CONDITIONS_NOT_SATISFIED, readBinary(0, 2));
    }

    @Test
    @DisplayName("UPDATE_BINARY past the end of the file is rejected on offset and on length")
    void rejectsOutOfBoundsWrite() {
        assertSw(SW_OK, selectFile(FILE_NDEF));
        assertSw(SW_WRONG_P1P2, updateBinary(1024, new byte[] {0x01})); // offset == size
        assertSw(SW_WRONG_LENGTH, updateBinary(1023, new byte[] {0x01, 0x02, 0x03})); // spills over
    }

    @Test
    @DisplayName("SELECT of an unknown file id returns file-not-found")
    void rejectsUnknownFile() {
        assertSw(SW_FILE_NOT_FOUND, selectFile(0xE105));
    }

    @Test
    @DisplayName("SELECT with a non-Type-4 P1/P2 is rejected")
    void rejectsWrongSelectParameters() {
        ResponseAPDU r =
                sim.transmitCommand(
                        new CommandAPDU(
                                CLA,
                                INS_SELECT,
                                SELECT_P1_BY_FILE_ID,
                                0x00,
                                new byte[] {(byte) 0xE1, (byte) 0x04}));
        assertSw(SW_INCORRECT_P1P2, r);
    }

    @Test
    @DisplayName("SELECT with a file id that is not two bytes is rejected")
    void rejectsWrongSelectLength() {
        ResponseAPDU r =
                sim.transmitCommand(
                        new CommandAPDU(
                                CLA,
                                INS_SELECT,
                                SELECT_P1_BY_FILE_ID,
                                SELECT_P2_FIRST_OR_ONLY,
                                new byte[] {(byte) 0xE1}));
        assertSw(SW_WRONG_LENGTH, r);
    }

    @Test
    @DisplayName("An unallocated instruction returns INS-not-supported")
    void rejectsUnknownInstruction() {
        assertSw(SW_INS_NOT_SUPPORTED, sim.transmitCommand(new CommandAPDU(CLA, 0x12, 0x00, 0x00)));
    }

    private ResponseAPDU selectFile(int fileId) {
        return sim.transmitCommand(
                new CommandAPDU(
                        CLA,
                        INS_SELECT,
                        SELECT_P1_BY_FILE_ID,
                        SELECT_P2_FIRST_OR_ONLY,
                        new byte[] {(byte) (fileId >> 8), (byte) fileId}));
    }

    private ResponseAPDU readBinary(int offset, int le) {
        return sim.transmitCommand(
                new CommandAPDU(CLA, INS_READ_BINARY, (offset >> 8) & 0xFF, offset & 0xFF, le));
    }

    private ResponseAPDU updateBinary(int offset, byte[] data) {
        return sim.transmitCommand(
                new CommandAPDU(CLA, INS_UPDATE_BINARY, (offset >> 8) & 0xFF, offset & 0xFF, data));
    }

    /**
     * Builds an {@code NLEN}-prefixed single NDEF URI record with the {@code "https://"} prefix
     * code.
     */
    private static byte[] uriRecord(String rest) {
        byte[] tail = rest.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        int payloadLen = 1 + tail.length; // URI prefix byte + tail
        byte[] out = new byte[2 + 5 + tail.length];
        int i = 0;
        out[i++] = 0x00;
        out[i++] = (byte) (5 + tail.length); // NLEN = record length
        out[i++] = (byte) 0xD1; // MB | ME | SR, TNF = well-known
        out[i++] = 0x01; // type length
        out[i++] = (byte) payloadLen; // payload length
        out[i++] = 0x55; // 'U'
        out[i++] = 0x04; // "https://"
        System.arraycopy(tail, 0, out, i, tail.length);
        return out;
    }

    private static void assertSw(int expected, ResponseAPDU response) {
        assertEquals(
                String.format("%04X", expected),
                String.format("%04X", response.getSW()),
                "status word");
    }
}
