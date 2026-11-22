// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.sim.probe;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.security.CryptoException;
import javacard.security.ECPrivateKey;
import javacard.security.KeyBuilder;
import javacard.security.Signature;

/**
 * Probe for {@code Fault.armEcdsaFlip}: {@link #INS_SIGN} builds a fresh {@code ALG_ECDSA_SHA_256}
 * engine through {@code Memory.signature} and emits the DER signature of the 32-byte digest in the
 * command data, so each command counts one applet-created engine. {@link #INS_OTHER} creates a
 * non-ECDSA engine to prove other algorithms do not advance the counter. {@link CryptoException}
 * reasons surface as {@code 0x6F10 | reason}.
 */
public final class FlipProbe extends Applet {

    private static final byte INS_SET_DOMAIN = 0x50;
    private static final byte INS_SET_S = 0x51;
    private static final byte INS_SIGN = 0x60;
    private static final byte INS_OTHER = 0x61;

    private final ECPrivateKey priv;
    private final Signature sig;

    private FlipProbe() {
        priv =
                (ECPrivateKey)
                        KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, (short) 256, false);
        sig = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new FlipProbe().register();
    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }
        byte[] buffer = apdu.getBuffer();
        try {
            switch (buffer[ISO7816.OFFSET_INS]) {
                case INS_SET_DOMAIN:
                    apdu.setIncomingAndReceive();
                    priv.setFieldFP(buffer, ISO7816.OFFSET_CDATA, (short) 32);
                    priv.setA(buffer, (short) (ISO7816.OFFSET_CDATA + 32), (short) 32);
                    priv.setB(buffer, (short) (ISO7816.OFFSET_CDATA + 64), (short) 32);
                    priv.setG(buffer, (short) (ISO7816.OFFSET_CDATA + 96), (short) 65);
                    priv.setR(buffer, (short) (ISO7816.OFFSET_CDATA + 161), (short) 32);
                    priv.setK((short) 1);
                    return;
                case INS_SET_S:
                    apdu.setIncomingAndReceive();
                    priv.setS(buffer, ISO7816.OFFSET_CDATA, (short) 32);
                    return;
                case INS_SIGN:
                    {
                        apdu.setIncomingAndReceive();
                        Signature sig = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
                        sig.init(priv, Signature.MODE_SIGN);
                        short len =
                                sig.signPreComputedHash(
                                        buffer,
                                        ISO7816.OFFSET_CDATA,
                                        (short) 32,
                                        buffer,
                                        (short) 0);
                        apdu.setOutgoingAndSend((short) 0, len);
                        return;
                    }
                case INS_OTHER:
                    Signature.getInstance(Signature.ALG_AES_CMAC_128, false);
                    return;
                default:
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
        } catch (CryptoException e) {
            ISOException.throwIt((short) (0x6F10 + e.getReason()));
        }
    }
}
