// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.sim.probe;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.security.CryptoException;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;

/**
 * Probe applet for EC point validation and the PLAIN_XY / PACE_GM agreements. Domain parameters
 * arrive as one TLV-free blob: p‖a‖b‖G‖r‖k (32‖32‖32‖65‖32‖1), applied to both keys. {@link
 * CryptoException} reasons surface as {@code 0x6F10 | reason}.
 */
public final class EcProbe extends Applet {

    private static final byte INS_SET_DOMAIN = 0x50;
    private static final byte INS_SET_S = 0x51;
    private static final byte INS_SET_W = 0x52;
    private static final byte INS_AGREE_XY = 0x53;
    private static final byte INS_AGREE_GM = 0x54;

    private final ECPrivateKey priv;
    private final ECPublicKey pub;
    private final KeyAgreement plainXy;
    private final KeyAgreement paceGm;

    private EcProbe() {
        priv =
                (ECPrivateKey)
                        KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, (short) 256, false);
        pub = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, (short) 256, false);
        plainXy = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY, false);
        paceGm = KeyAgreement.getInstance(KeyAgreement.ALG_EC_PACE_GM, false);
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new EcProbe().register();
    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }
        byte[] buffer = apdu.getBuffer();
        byte ins = buffer[ISO7816.OFFSET_INS];
        try {
            switch (ins) {
                case INS_SET_DOMAIN:
                    apdu.setIncomingAndReceive();
                    setDomain(priv, buffer);
                    setDomain(pub, buffer);
                    return;
                case INS_SET_S:
                    apdu.setIncomingAndReceive();
                    priv.setS(buffer, ISO7816.OFFSET_CDATA, (short) 32);
                    return;
                case INS_SET_W:
                    {
                        short lc = apdu.setIncomingAndReceive();
                        pub.setW(buffer, ISO7816.OFFSET_CDATA, lc);
                        return;
                    }
                case INS_AGREE_XY:
                    {
                        short lc = apdu.setIncomingAndReceive();
                        plainXy.init(priv);
                        short len =
                                plainXy.generateSecret(
                                        buffer,
                                        ISO7816.OFFSET_CDATA,
                                        lc,
                                        buffer,
                                        ISO7816.OFFSET_CDATA);
                        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len);
                        return;
                    }
                case INS_AGREE_GM:
                    {
                        short lc = apdu.setIncomingAndReceive();
                        paceGm.init(priv);
                        short len =
                                paceGm.generateSecret(
                                        buffer,
                                        ISO7816.OFFSET_CDATA,
                                        lc,
                                        buffer,
                                        ISO7816.OFFSET_CDATA);
                        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len);
                        return;
                    }
                default:
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
        } catch (CryptoException e) {
            ISOException.throwIt((short) (0x6F10 + e.getReason()));
        }
    }

    private void setDomain(ECKey key, byte[] buffer) {
        // blob layout: p‖a‖b‖G‖r (32‖32‖32‖65‖32) then k as P2
        key.setFieldFP(buffer, ISO7816.OFFSET_CDATA, (short) 32);
        key.setA(buffer, (short) (ISO7816.OFFSET_CDATA + 32), (short) 32);
        key.setB(buffer, (short) (ISO7816.OFFSET_CDATA + 64), (short) 32);
        key.setG(buffer, (short) (ISO7816.OFFSET_CDATA + 96), (short) 65);
        key.setR(buffer, (short) (ISO7816.OFFSET_CDATA + 161), (short) 32);
        key.setK((short) 1);
    }
}
