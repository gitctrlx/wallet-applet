// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.sim.probe;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.SystemException;
import javacard.framework.Util;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

/**
 * Probe for measured transient-memory accounting (architecture section 8 patch 6, audit-impl
 * memory.out). Install allocates the measured mix; install parameters inject failure modes:
 * params[0]=1 allocates a 4000 B transient array (over the 3990 B pool), params[1]=1 builds an
 * unmeasured engine, params[2]=1 an unmeasured transient key type, params[3]=1 an unmeasured key
 * size. {@link SystemException} surfaces as {@code 0x6F20 | reason}, {@link IllegalStateException}
 * as {@code 0x6F43}.
 */
public final class MemProbe extends Applet {

    private static final byte INS_REPORT = 0x10;
    private static final byte INS_ALLOC = 0x11;
    private static final byte INS_UNMEASURED = 0x12;

    private final Object[] kept;

    private MemProbe(byte[] bArray, short bOffset, byte bLength) {
        // GlobalPlatform data: len(aid) aid 00 len(params) params
        short pOff = (short) (bOffset + 1 + bArray[bOffset] + 1);
        short pLen = (short) (bArray[pOff] & 0xFF);
        if (pLen > 0 && bArray[(short) (pOff + 1)] == 1) {
            JCSystem.makeTransientByteArray((short) 4000, JCSystem.CLEAR_ON_RESET);
        }
        if (pLen > 1 && bArray[(short) (pOff + 2)] == 1) {
            MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
        }
        if (pLen > 2 && bArray[(short) (pOff + 3)] == 1) {
            KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE_TRANSIENT_RESET, (short) 512, false);
        }
        if (pLen > 3 && bArray[(short) (pOff + 4)] == 1) {
            KeyBuilder.buildKey(
                    KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT, (short) 384, false);
        }
        kept = new Object[9];
        kept[0] = JCSystem.makeTransientByteArray((short) 100, JCSystem.CLEAR_ON_DESELECT);
        kept[1] = JCSystem.makeTransientShortArray((short) 50, JCSystem.CLEAR_ON_RESET);
        kept[2] = JCSystem.makeTransientBooleanArray((short) 30, JCSystem.CLEAR_ON_DESELECT);
        kept[3] = JCSystem.makeTransientObjectArray((short) 10, JCSystem.CLEAR_ON_RESET);
        kept[4] =
                KeyBuilder.buildKey(
                        KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT, (short) 256, false);
        kept[5] = KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_RESET, (short) 128, false);
        kept[6] = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        kept[7] = Signature.getInstance(Signature.ALG_AES_CMAC_128, false);
        kept[8] = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        MessageDigest.getInstance(MessageDigest.ALG_SHA_512, false);
        KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY, false);
        KeyAgreement.getInstance(KeyAgreement.ALG_EC_PACE_GM, false);
        RandomData.getInstance(RandomData.ALG_KEYGENERATION);
        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new MemProbe(bArray, bOffset, bLength);
    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }
        byte[] buffer = apdu.getBuffer();
        byte ins = buffer[ISO7816.OFFSET_INS];
        try {
            switch (ins) {
                case INS_REPORT:
                    Util.setShort(
                            buffer,
                            ISO7816.OFFSET_CDATA,
                            JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT));
                    Util.setShort(
                            buffer,
                            (short) (ISO7816.OFFSET_CDATA + 2),
                            JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_TRANSIENT_RESET));
                    apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) 4);
                    return;
                case INS_ALLOC:
                    JCSystem.makeTransientByteArray(
                            Util.makeShort(buffer[ISO7816.OFFSET_P1], buffer[ISO7816.OFFSET_P2]),
                            JCSystem.CLEAR_ON_RESET);
                    return;
                case INS_UNMEASURED:
                    MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
                    return;
                default:
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
        } catch (SystemException e) {
            ISOException.throwIt((short) (0x6F20 + e.getReason()));
        } catch (IllegalStateException e) {
            ISOException.throwIt((short) 0x6F43);
        }
    }
}
