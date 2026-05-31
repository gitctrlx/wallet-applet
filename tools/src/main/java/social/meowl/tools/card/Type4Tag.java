/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.card;

import apdu4j.core.CommandAPDU;
import apdu4j.core.ResponseAPDU;
import java.util.Arrays;
import java.util.Objects;
import social.meowl.tools.core.MeowlSw;
import social.meowl.tools.core.ProtocolException;

/**
 * NFC Forum Type 4 file I/O over an already-selected {@link MeowlCard}.
 *
 * <p>Drives the read/write half of the Type 4 protocol — {@code SELECT} by file id, {@code
 * READ_BINARY} and {@code UPDATE_BINARY} — against the meowl NDEF tag's NDEF elementary file
 * ({@code E104}). The caller is responsible for having SELECTed the NDEF applet first. Writes
 * follow the NFC Forum procedure (clear {@code NLEN}, write the message, commit {@code NLEN}) so a
 * tear leaves an empty-but-valid tag rather than a half-written message.
 */
public final class Type4Tag {

    private static final int CLA_ISO = 0x00;
    private static final int INS_SELECT = 0xA4;
    private static final int INS_READ_BINARY = 0xB0;
    private static final int INS_UPDATE_BINARY = 0xD6;
    private static final int P1_SELECT_BY_FILE_ID = 0x00;
    private static final int P2_FIRST_OR_ONLY = 0x0C;

    /** NDEF elementary file id referenced by the Capability Container. */
    public static final int FILE_NDEF = 0xE104;

    /**
     * Per-frame read/write ceiling advertised by the Capability Container ({@code MLe}/{@code
     * MLc}).
     */
    private static final int MAX_BLOCK = 255;

    private final MeowlCard card;

    public Type4Tag(MeowlCard card) {
        this.card = Objects.requireNonNull(card, "card");
    }

    /** Reads the whole NDEF file: the 2-byte {@code NLEN} prefix plus that many message bytes. */
    public byte[] readNdef() {
        selectFile(FILE_NDEF);
        byte[] header = readBinary(0, 2);
        int nlen = ((header[0] & 0xFF) << 8) | (header[1] & 0xFF);
        byte[] out = new byte[2 + nlen];
        out[0] = header[0];
        out[1] = header[1];
        int off = 0;
        while (off < nlen) {
            byte[] part = readBinary(2 + off, Math.min(MAX_BLOCK, nlen - off));
            if (part.length == 0) {
                throw new IllegalStateException("READ_BINARY returned no data at offset " + off);
            }
            System.arraycopy(part, 0, out, 2 + off, part.length);
            off += part.length;
        }
        return out;
    }

    /**
     * Writes a full NDEF file image ({@code NLEN} prefix + message) using the NFC Forum procedure.
     */
    public void writeNdef(byte[] file) {
        if (file.length < 2) {
            throw new IllegalArgumentException("NDEF file image shorter than its NLEN prefix");
        }
        selectFile(FILE_NDEF);
        updateBinary(0, new byte[] {0x00, 0x00}); // invalidate
        byte[] body = Arrays.copyOfRange(file, 2, file.length);
        int off = 0;
        while (off < body.length) {
            int chunk = Math.min(MAX_BLOCK, body.length - off);
            updateBinary(2 + off, Arrays.copyOfRange(body, off, off + chunk));
            off += chunk;
        }
        updateBinary(0, new byte[] {file[0], file[1]}); // commit NLEN
    }

    private void selectFile(int fileId) {
        byte[] apdu = {
            (byte) CLA_ISO,
            (byte) INS_SELECT,
            (byte) P1_SELECT_BY_FILE_ID,
            (byte) P2_FIRST_OR_ONLY,
            0x02,
            (byte) (fileId >> 8),
            (byte) fileId
        };
        require(
                card.transmit(new CommandAPDU(apdu)),
                "SELECT file 0x" + Integer.toHexString(fileId));
    }

    private byte[] readBinary(int offset, int le) {
        byte[] apdu = {
            (byte) CLA_ISO, (byte) INS_READ_BINARY, (byte) (offset >> 8), (byte) offset, (byte) le
        };
        ResponseAPDU resp = card.transmit(new CommandAPDU(apdu));
        require(resp, "READ_BINARY @" + offset);
        return resp.getData();
    }

    private void updateBinary(int offset, byte[] data) {
        byte[] apdu = new byte[5 + data.length];
        apdu[0] = (byte) CLA_ISO;
        apdu[1] = (byte) INS_UPDATE_BINARY;
        apdu[2] = (byte) (offset >> 8);
        apdu[3] = (byte) offset;
        apdu[4] = (byte) data.length;
        System.arraycopy(data, 0, apdu, 5, data.length);
        require(card.transmit(new CommandAPDU(apdu)), "UPDATE_BINARY @" + offset);
    }

    private static void require(ResponseAPDU resp, String op) {
        if (!MeowlSw.isSuccess(resp.getSW())) {
            throw new ProtocolException(resp.getSW(), op + " failed");
        }
    }
}
