// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.sim.probe;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.security.CryptoException;
import javacard.security.KeyBuilder;
import javacard.security.RSAPrivateKey;
import javacardx.crypto.Cipher;

/**
 * Probe applet for the raw RSA NOPAD path: loads modulus and exponent onto a persistent private
 * key, then runs {@code doFinal} over the command payload. {@link CryptoException} reasons surface
 * as {@code 0x6F10 | reason} so tests can tell ILLEGAL_VALUE (0x6F11) apart from a generic failure.
 */
public final class RsaProbe extends Applet {

    private static final byte INS_SET_MODULUS = 0x40;
    private static final byte INS_SET_EXPONENT = 0x41;
    private static final byte INS_MODPOW = 0x42;

    private final RSAPrivateKey key;
    private final Cipher cipher;

    private RsaProbe() {
        key = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, (short) 512, false);
        cipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new RsaProbe().register();
    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }
        byte[] buffer = apdu.getBuffer();
        byte ins = buffer[ISO7816.OFFSET_INS];
        switch (ins) {
            case INS_SET_MODULUS:
                {
                    short lc = apdu.setIncomingAndReceive();
                    key.setModulus(buffer, ISO7816.OFFSET_CDATA, lc);
                    return;
                }
            case INS_SET_EXPONENT:
                {
                    short lc = apdu.setIncomingAndReceive();
                    key.setExponent(buffer, ISO7816.OFFSET_CDATA, lc);
                    return;
                }
            case INS_MODPOW:
                {
                    short lc = apdu.setIncomingAndReceive();
                    try {
                        cipher.init(key, Cipher.MODE_DECRYPT);
                        short len =
                                cipher.doFinal(
                                        buffer,
                                        ISO7816.OFFSET_CDATA,
                                        lc,
                                        buffer,
                                        ISO7816.OFFSET_CDATA);
                        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len);
                    } catch (CryptoException e) {
                        ISOException.throwIt((short) (0x6F10 + e.getReason()));
                    }
                    return;
                }
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }
}
