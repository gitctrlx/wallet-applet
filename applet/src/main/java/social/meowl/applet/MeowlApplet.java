/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;

/**
 * Skeleton applet for the meowl.social hardware wallet.
 *
 * <p>Replace the placeholder INS handlers with the wallet's real protocol
 * (key derivation, signing, secure channel, etc.). This class intentionally
 * stays minimal so that it compiles for {@code targetsdk} 3.0.5 and can be
 * loaded onto a wide range of cards.
 */
public final class MeowlApplet extends Applet {

    /** CLA byte reserved for meowl wallet commands. */
    public static final byte CLA_MEOWL = (byte) 0x80;

    /** INS: get applet & protocol version. */
    public static final byte INS_GET_INFO = (byte) 0x01;
    /** INS: verify user PIN. */
    public static final byte INS_VERIFY_PIN = (byte) 0x20;

    /** PIN policy. */
    private static final byte PIN_MAX_TRIES = (byte) 3;
    private static final byte PIN_MAX_LENGTH = (byte) 8;

    /** Big-endian protocol version exposed via INS_GET_INFO. */
    private static final byte[] VERSION = {(byte) 0x00, (byte) 0x01}; // 0.1

    private final OwnerPIN pin;

    private MeowlApplet(byte[] bArray, short bOffset, byte bLength) {
        this.pin = new OwnerPIN(PIN_MAX_TRIES, PIN_MAX_LENGTH);

        // Optional install parameters layout (GlobalPlatform):
        //   [AID len][AID...][Control len][Control...][AppData len][AppData...]
        // For this skeleton we just register with the applet's own AID.
        register();
    }

    /** GlobalPlatform install entry point. */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new MeowlApplet(bArray, bOffset, bLength);
    }

    @Override
    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }

        byte[] buffer = apdu.getBuffer();
        if (buffer[ISO7816.OFFSET_CLA] != CLA_MEOWL) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        switch (buffer[ISO7816.OFFSET_INS]) {
            case INS_GET_INFO:
                getInfo(apdu);
                break;
            case INS_VERIFY_PIN:
                verifyPin(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void getInfo(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short len = (short) VERSION.length;
        JCSystem.beginTransaction();
        try {
            buffer[0] = VERSION[0];
            buffer[1] = VERSION[1];
        } finally {
            JCSystem.commitTransaction();
        }
        apdu.setOutgoingAndSend((short) 0, len);
    }

    private void verifyPin(APDU apdu) {
        if (pin.getTriesRemaining() == 0) {
            ISOException.throwIt(ISO7816.SW_FILE_INVALID);
        }
        short len = apdu.setIncomingAndReceive();
        if (len < 1 || len > PIN_MAX_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        if (!pin.check(apdu.getBuffer(), ISO7816.OFFSET_CDATA, (byte) len)) {
            // Encode remaining tries in the trailer (ISO 7816-4 style: 63 Cx).
            ISOException.throwIt((short) (0x63C0 | pin.getTriesRemaining()));
        }
    }
}
