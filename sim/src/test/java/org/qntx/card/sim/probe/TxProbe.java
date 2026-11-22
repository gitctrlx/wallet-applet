// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.sim.probe;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.TransactionException;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;

/**
 * Probe applet for transaction rollback, commit-buffer accounting and key-object transaction
 * participation. Persistent key objects are created at install; commands drive {@code begin}/{@code
 * commit}/ {@code abort} around a single write each.
 */
public final class TxProbe extends Applet {

    private static final byte INS_TX_STORE = 0x21;
    private static final byte INS_TX_COPY = 0x22;
    private static final byte INS_TX_COPY_NA = 0x23;
    private static final byte INS_TX_NESTED = 0x24;
    private static final byte INS_TX_SETKEY = 0x25;
    private static final byte INS_TX_SETS = 0x26;
    private static final byte INS_TX_SETW = 0x27;
    private static final byte INS_TX_SETEXP = 0x28;
    private static final byte INS_TX_CLEARKEY = 0x29;
    private static final byte INS_TX_GENPAIR = 0x2A;
    private static final byte INS_TX_UNUSED = 0x2B;
    private static final byte INS_TX_SPAN = 0x2C;
    private static final byte INS_TX_FILL = 0x2D;
    private static final byte INS_TX_BUF_SETW = 0x2E;
    private static final byte INS_TX_OPEN = 0x2F;
    private static final byte INS_TX_WIDE = 0x38;
    private static final byte INS_TX_OPEN_SEND = 0x39;
    private static final byte INS_READ_BUF = 0x30;
    private static final byte INS_READ_SPAN = 0x31;
    private static final byte INS_READ_AES = 0x32;
    private static final byte INS_READ_S = 0x33;
    private static final byte INS_READ_W = 0x34;
    private static final byte INS_READ_EXP = 0x35;
    private static final byte INS_READ_PUB_MOD = 0x36;
    private static final byte INS_SET_AES = 0x37;
    private static final byte INS_TX_THROW = 0x3A;
    private static final byte INS_TX_SETA = 0x3B;
    private static final byte INS_READ_A = 0x3C;

    private static final short BUF_LEN = 272;
    private static final short SPAN_LEN = 600;

    private final byte[] buf;
    private final byte[] span;
    private final byte[] wide;
    private final byte[] tail;
    private final AESKey aesKey;
    private final ECPrivateKey ecPriv;
    private final ECPublicKey ecPub;
    private final RSAPrivateKey rsaPriv;
    private final KeyPair keyPair;

    private TxProbe() {
        buf = new byte[BUF_LEN];
        span = new byte[SPAN_LEN];
        wide = new byte[SPAN_LEN];
        tail = new byte[64];
        aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, (short) 128, false);
        ecPriv =
                (ECPrivateKey)
                        KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, (short) 256, false);
        ecPub = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, (short) 256, false);
        rsaPriv =
                (RSAPrivateKey)
                        KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, (short) 512, false);
        keyPair = new KeyPair(KeyPair.ALG_RSA, (short) 512);
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new TxProbe().register();
    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }
        byte[] buffer = apdu.getBuffer();
        byte ins = buffer[ISO7816.OFFSET_INS];
        byte p1 = buffer[ISO7816.OFFSET_P1];
        byte p2 = buffer[ISO7816.OFFSET_P2];
        switch (ins) {
            case INS_TX_STORE:
                JCSystem.beginTransaction();
                buf[0] = p2;
                finish(p1);
                return;
            case INS_TX_COPY:
                {
                    short lc = apdu.setIncomingAndReceive();
                    JCSystem.beginTransaction();
                    Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, buf, (short) 0, lc);
                    finish(p1);
                    return;
                }
            case INS_TX_COPY_NA:
                {
                    short lc = apdu.setIncomingAndReceive();
                    JCSystem.beginTransaction();
                    Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, buf, (short) 0, lc);
                    finish(p1);
                    return;
                }
            case INS_TX_NESTED:
                JCSystem.beginTransaction();
                try {
                    JCSystem.beginTransaction();
                    buffer[ISO7816.OFFSET_CDATA] = 0;
                } catch (TransactionException e) {
                    buffer[ISO7816.OFFSET_CDATA] = (byte) e.getReason();
                }
                JCSystem.commitTransaction();
                apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) 1);
                return;
            case INS_TX_SETKEY:
                {
                    short lc = apdu.setIncomingAndReceive();
                    JCSystem.beginTransaction();
                    aesKey.setKey(buffer, ISO7816.OFFSET_CDATA);
                    finish(p1);
                    return;
                }
            case INS_TX_SETS:
                {
                    apdu.setIncomingAndReceive();
                    JCSystem.beginTransaction();
                    ecPriv.setS(buffer, ISO7816.OFFSET_CDATA, (short) 32);
                    finish(p1);
                    return;
                }
            case INS_TX_SETW:
                {
                    short lc = apdu.setIncomingAndReceive();
                    JCSystem.beginTransaction();
                    ecPub.setW(buffer, ISO7816.OFFSET_CDATA, lc);
                    finish(p1);
                    return;
                }
            case INS_TX_SETEXP:
                {
                    short lc = apdu.setIncomingAndReceive();
                    JCSystem.beginTransaction();
                    rsaPriv.setExponent(buffer, ISO7816.OFFSET_CDATA, lc);
                    finish(p1);
                    return;
                }
            case INS_TX_CLEARKEY:
                JCSystem.beginTransaction();
                aesKey.clearKey();
                finish(p1);
                return;
            case INS_TX_GENPAIR:
                JCSystem.beginTransaction();
                keyPair.genKeyPair();
                finish(p1);
                return;
            case INS_TX_UNUSED:
                JCSystem.beginTransaction();
                buf[0] = 1;
                Util.setShort(buffer, ISO7816.OFFSET_CDATA, JCSystem.getUnusedCommitCapacity());
                JCSystem.commitTransaction();
                apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) 2);
                return;
            case INS_TX_SPAN:
                JCSystem.beginTransaction();
                span[0] = p2;
                span[400] = p2;
                finish((byte) 1);
                return;
            case INS_TX_WIDE:
                JCSystem.beginTransaction();
                span[0] = p2;
                span[512] = p2;
                finish((byte) 1);
                return;
            case INS_TX_FILL:
                JCSystem.beginTransaction();
                try {
                    buf[0] = 1;
                    span[0] = 1;
                    span[599] = 1;
                    wide[0] = 1;
                    wide[599] = 1;
                    tail[0] = 1;
                    buffer[ISO7816.OFFSET_CDATA] = 0;
                } catch (TransactionException e) {
                    buffer[ISO7816.OFFSET_CDATA] = (byte) e.getReason();
                }
                if (JCSystem.getTransactionDepth() != 0) {
                    JCSystem.abortTransaction();
                }
                apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) 1);
                return;
            case INS_TX_BUF_SETW:
                {
                    short lc = apdu.setIncomingAndReceive();
                    JCSystem.beginTransaction();
                    for (short i = 0; i < BUF_LEN; i++) {
                        buf[i] = 0x11;
                    }
                    ecPub.setW(buffer, ISO7816.OFFSET_CDATA, lc);
                    finish(p1);
                    return;
                }
            case INS_TX_OPEN:
                JCSystem.beginTransaction();
                buf[0] = p2;
                return;
            case INS_TX_THROW:
                JCSystem.beginTransaction();
                buf[0] = p2;
                // leaving process() by exception with the transaction
                // open aborts it like the normal-return path
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                return;
            case INS_TX_SETA:
                {
                    short lc = apdu.setIncomingAndReceive();
                    JCSystem.beginTransaction();
                    ecPub.setA(buffer, ISO7816.OFFSET_CDATA, lc);
                    finish(p1);
                    return;
                }
            case INS_TX_OPEN_SEND:
                // send a response prefix, then leave the transaction
                // open: the card auto-aborts and reports 6F00
                buffer[ISO7816.OFFSET_CDATA] = 0x41;
                buffer[(short) (ISO7816.OFFSET_CDATA + 1)] = 0x42;
                apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) 2);
                JCSystem.beginTransaction();
                buf[0] = p2;
                return;
            case INS_SET_AES:
                {
                    apdu.setIncomingAndReceive();
                    aesKey.setKey(buffer, ISO7816.OFFSET_CDATA);
                    return;
                }
            case INS_READ_BUF:
                Util.arrayCopy(buf, (short) 0, buffer, ISO7816.OFFSET_CDATA, (short) (p1 & 0xFF));
                apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) (p1 & 0xFF));
                return;
            case INS_READ_SPAN:
                Util.arrayCopy(span, (short) 0, buffer, ISO7816.OFFSET_CDATA, (short) (p1 & 0xFF));
                apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) (p1 & 0xFF));
                return;
            case INS_READ_AES:
                {
                    byte len = aesKey.getKey(buffer, ISO7816.OFFSET_CDATA);
                    apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len);
                    return;
                }
            case INS_READ_S:
                try {
                    short len = ecPriv.getS(buffer, ISO7816.OFFSET_CDATA);
                    apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len);
                } catch (CryptoException e) {
                    buffer[ISO7816.OFFSET_CDATA] = (byte) 0xEE;
                    apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) 1);
                }
                return;
            case INS_READ_W:
                try {
                    short len = ecPub.getW(buffer, ISO7816.OFFSET_CDATA);
                    apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len);
                } catch (CryptoException e) {
                    buffer[ISO7816.OFFSET_CDATA] = (byte) 0xEE;
                    apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) 1);
                }
                return;
            case INS_READ_EXP:
                try {
                    short len = rsaPriv.getExponent(buffer, ISO7816.OFFSET_CDATA);
                    apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len);
                } catch (CryptoException e) {
                    buffer[ISO7816.OFFSET_CDATA] = (byte) 0xEE;
                    apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) 1);
                }
                return;
            case INS_READ_A:
                try {
                    short len = ecPub.getA(buffer, ISO7816.OFFSET_CDATA);
                    apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len);
                } catch (CryptoException e) {
                    buffer[ISO7816.OFFSET_CDATA] = (byte) 0xEE;
                    apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) 1);
                }
                return;
            case INS_READ_PUB_MOD:
                {
                    short len =
                            ((RSAPublicKey) keyPair.getPublic())
                                    .getModulus(buffer, ISO7816.OFFSET_CDATA);
                    apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, len);
                    return;
                }
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void finish(byte commit) {
        if (commit == (byte) 1) {
            JCSystem.commitTransaction();
        } else {
            JCSystem.abortTransaction();
        }
    }
}
