/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.ndef;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

/**
 * NFC Forum Type 4 Tag applet for the meowl card — an openly readable and writable tag.
 *
 * <p>Its job is NFC discovery: when a phone taps a meowl card, the OS reads this Type 4 tag and
 * follows the embedded URI record so the right app opens without the user launching anything. The
 * tag ships pointing at {@code https://meowl.social}; the meowl app overwrites it with the holder's
 * decentralised profile link (an {@code https://} URL carrying their Nostr {@code nprofile}). It is
 * a self-contained CAP carrying no meowl wallet or backup code — install it alongside whichever
 * functional applet a given card hosts.
 *
 * <p>The tag is selected by the phone's NFC stack via the NFC Forum well-known application AID
 * {@code D2760000850101}; the GP {@code install [for install]} step assigns that instance AID even
 * though the CAP declares a meowl-namespaced AID. After application selection the reader speaks the
 * Type 4 file protocol: {@code SELECT} (by file id), {@code READ_BINARY} and {@code UPDATE_BINARY}
 * against the Capability Container ({@code E103}) and the NDEF file ({@code E104}).
 *
 * <p>The NDEF file is openly writable ({@code UPDATE_BINARY}, no authentication) by design: the
 * payload is a public profile pointer, holders rewrite their own card from the app, and anti-clone
 * is an app/relay concern rather than a tag one. The Capability Container is read-only.
 */
public final class NdefApplet extends Applet {

    /** ISO 7816-4 {@code READ BINARY} instruction. */
    private static final byte INS_READ_BINARY = (byte) 0xB0;

    /** ISO 7816-4 {@code UPDATE BINARY} instruction. */
    private static final byte INS_UPDATE_BINARY = (byte) 0xD6;

    /** {@code SELECT} P1: select by EF identifier. */
    private static final byte SELECT_P1_BY_FILE_ID = (byte) 0x00;

    /** {@code SELECT} P2: first or only occurrence, return no FCI. */
    private static final byte SELECT_P2_FIRST_OR_ONLY = (byte) 0x0C;

    /** Sentinel for "no elementary file currently selected". */
    private static final short FILE_ID_NONE = (short) 0xFFFF;

    /** Capability Container file identifier (NFC Forum Type 4 Tag). */
    private static final short FILE_ID_CC = (short) 0xE103;

    /** NDEF file identifier referenced by the Capability Container. */
    private static final short FILE_ID_NDEF = (short) 0xE104;

    /** Maximum bytes returned per {@code READ BINARY} (CC {@code MLe}). */
    private static final short MAX_READ_LEN = (short) 255;

    /** Size of the writable NDEF elementary file (matches the Capability Container max size). */
    private static final short NDEF_FILE_SIZE = (short) 1024;

    /**
     * Capability Container (15 bytes, mapping version 2.0). Declares a single NDEF file {@code
     * E104} with free read and write access; the CC itself is read-only.
     */
    private static final byte[] CC_FILE = {
        (byte) 0x00,
        (byte) 0x0F, // CCLEN = 15
        (byte) 0x20, // mapping version 2.0
        (byte) 0x00,
        (byte) 0xFF, // MLe = 255 (max READ BINARY response)
        (byte) 0x00,
        (byte) 0xFF, // MLc = 255 (max UPDATE BINARY command)
        (byte) 0x04,
        (byte) 0x06, // NDEF File Control TLV: T = 0x04, L = 6
        (byte) 0xE1,
        (byte) 0x04, // NDEF file id = E104
        (byte) 0x04,
        (byte) 0x00, // max NDEF file size = 1024
        (byte) 0x00, // read access: granted
        (byte) 0x00 // write access: granted
    };

    /**
     * Default NDEF payload seeded into the writable file at install: a 2-byte length prefix ({@code
     * NLEN}) followed by a single well-known URI record for {@code https://meowl.social} (URI
     * prefix code {@code 0x04} = {@code "https://"}). The meowl app overwrites this with the
     * holder's link.
     */
    private static final byte[] DEFAULT_NDEF = {
        (byte) 0x00,
        (byte) 0x11, // NLEN = 17
        (byte) 0xD1, // MB | ME | SR, TNF = NFC Forum well-known type
        (byte) 0x01, // type length = 1
        (byte) 0x0D, // payload length = 13
        (byte) 0x55, // type = 'U' (URI record)
        (byte) 0x04, // URI prefix 0x04 = "https://"
        (byte) 'm',
        (byte) 'e',
        (byte) 'o',
        (byte) 'w',
        (byte) 'l',
        (byte) '.',
        (byte) 's',
        (byte) 'o',
        (byte) 'c',
        (byte) 'i',
        (byte) 'a',
        (byte) 'l'
    };

    /** Currently selected EF, reset on every (re)selection of the applet. */
    private short selectedFile;

    /** Writable NDEF file: {@code NLEN} prefix plus payload, seeded with {@link #DEFAULT_NDEF}. */
    private final byte[] ndefFile;

    private NdefApplet() {
        selectedFile = FILE_ID_NONE;
        ndefFile = new byte[NDEF_FILE_SIZE];
        Util.arrayCopyNonAtomic(
                DEFAULT_NDEF, (short) 0, ndefFile, (short) 0, (short) DEFAULT_NDEF.length);
        register();
    }

    /** GlobalPlatform install entry point. */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new NdefApplet();
    }

    @Override
    public boolean select() {
        selectedFile = FILE_ID_NONE;
        return true;
    }

    @Override
    public void process(APDU apdu) {
        if (selectingApplet()) {
            selectedFile = FILE_ID_NONE;
            return;
        }

        byte[] buffer = apdu.getBuffer();
        switch (buffer[ISO7816.OFFSET_INS]) {
            case ISO7816.INS_SELECT:
                processSelect(apdu);
                break;
            case INS_READ_BINARY:
                processReadBinary(apdu);
                break;
            case INS_UPDATE_BINARY:
                processUpdateBinary(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    /** Handles {@code SELECT} by EF identifier for the CC and NDEF files. */
    private void processSelect(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        apdu.setIncomingAndReceive();

        if (buffer[ISO7816.OFFSET_P1] != SELECT_P1_BY_FILE_ID
                || buffer[ISO7816.OFFSET_P2] != SELECT_P2_FIRST_OR_ONLY) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        if (buffer[ISO7816.OFFSET_LC] != (byte) 2) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        short fileId = Util.getShort(buffer, ISO7816.OFFSET_CDATA);
        if (fileId != FILE_ID_CC && fileId != FILE_ID_NDEF) {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }
        selectedFile = fileId;
    }

    /** Streams the selected EF back to the reader, honouring the requested offset and length. */
    private void processReadBinary(APDU apdu) {
        byte[] data;
        if (selectedFile == FILE_ID_CC) {
            data = CC_FILE;
        } else if (selectedFile == FILE_ID_NDEF) {
            data = ndefFile;
        } else {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            return;
        }

        byte[] buffer = apdu.getBuffer();
        short offset = Util.getShort(buffer, ISO7816.OFFSET_P1);
        short dataLen = (short) data.length;
        if (offset < 0 || offset >= dataLen) {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }

        short le = apdu.setOutgoing();
        if (le > MAX_READ_LEN) {
            le = MAX_READ_LEN;
        }
        short available = (short) (dataLen - offset);
        if (le == 0 || le > available) {
            le = available;
        }

        apdu.setOutgoingLength(le);
        apdu.sendBytesLong(data, offset, le);
    }

    /** Writes into the NDEF file at the requested offset; the read-only CC rejects writes. */
    private void processUpdateBinary(APDU apdu) {
        if (selectedFile != FILE_ID_NDEF) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        byte[] buffer = apdu.getBuffer();
        short offset = Util.getShort(buffer, ISO7816.OFFSET_P1);
        short lc = apdu.setIncomingAndReceive();
        short size = (short) ndefFile.length;
        if (offset < 0 || offset >= size) {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }
        short limit = (short) (offset + lc);
        if (limit < 0 || limit > size) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, ndefFile, offset, lc);
    }
}
