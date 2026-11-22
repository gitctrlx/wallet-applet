// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.Signature;

/**
 * The card's secp256k1 identity (§5.1), its batch CA key and certificate (§5.2) and the
 * personalisation commands GET_IDENTITY (§14.1) and PERSONALIZE (§14.2). {@code idKey} is generated
 * in the constructor and never leaves the card; {@code caKey} is stored by T-PERSO.
 */
final class Identity {
    /** {@link Mem#W} offset of the SHA-256 input hash for sign/verify (below {@link Mem#W_DER}). */
    private static final short W_TH = 0;

    /** {@link Mem#P} offset of the uncompressed public-key scratch for {@link #identity}. */
    private static final short P_PUB = 65;

    private final Mem mem;
    private final State state;
    private final Secp256k1 secp;
    private final KeyPair idKey;
    private final ECPublicKey idPublic;
    private final ECPublicKey caKey;

    Identity(Mem mem, State state, Secp256k1 secp) {
        this.mem = mem;
        this.state = state;
        this.secp = secp;
        idKey =
                new KeyPair(
                        (ECPublicKey)
                                KeyBuilder.buildKey(
                                        KeyBuilder.TYPE_EC_FP_PUBLIC,
                                        KeyBuilder.LENGTH_EC_FP_256,
                                        false),
                        (ECPrivateKey)
                                KeyBuilder.buildKey(
                                        KeyBuilder.TYPE_EC_FP_PRIVATE,
                                        KeyBuilder.LENGTH_EC_FP_256,
                                        false));
        Secp256k1.setDomain((ECKey) idKey.getPublic());
        Secp256k1.setDomain((ECKey) idKey.getPrivate());
        idKey.genKeyPair();
        idPublic = (ECPublicKey) idKey.getPublic();
        caKey =
                (ECPublicKey)
                        KeyBuilder.buildKey(
                                KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false);
        Secp256k1.setDomain(caKey);
    }

    /** Writes {@code A}, the compressed identity public key (33 bytes). */
    void identity(byte[] out, short off) {
        idPublic.getW(mem.P, P_PUB);
        secp.compress(mem.P, P_PUB, out, off);
    }

    /** {@code out = ID(A) = SHA-256(A)[0..16)} (§2), the card's member ID. */
    void id(byte[] out, short off) {
        identity(mem.W, Mem.W_DER);
        mem.sha256.reset();
        mem.sha256.doFinal(mem.W, Mem.W_DER, Const.COMPRESSED_LEN, mem.W, W_TH);
        Util.arrayCopy(mem.W, W_TH, out, off, (short) 16);
    }

    /** GET_IDENTITY (§14.1): {@code life = FACTORY}, {@code P1 = P2 = 0}, no data; response A. */
    short getIdentity(APDU apdu, short lc) {
        byte[] buf = apdu.getBuffer();
        if (state.life() != Const.LIFE_FACTORY) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (buf[ISO7816.OFFSET_P1] != 0 || buf[ISO7816.OFFSET_P2] != 0) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        if (lc != 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        identity(buf, (short) 0);
        return Const.COMPRESSED_LEN;
    }

    /**
     * PERSONALIZE (§14.2): T-PERSO stores {@code cert} and {@code caKey} and moves {@code life} to
     * BLANK inside one transaction; any failed check aborts it. Returns {@code 0} (empty response).
     */
    short personalize(APDU apdu, short lc) {
        byte[] buf = apdu.getBuffer();
        if (state.life() != Const.LIFE_FACTORY) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (buf[ISO7816.OFFSET_P1] != 0 || buf[ISO7816.OFFSET_P2] != 0) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        if (lc != (short) 162) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        // data = cert(97) ‖ caKey(65); cert[0..33) must equal A
        identity(mem.P, (short) 0);
        if (Bytes.equal(buf, ISO7816.OFFSET_CDATA, mem.P, (short) 0, Const.COMPRESSED_LEN)
                != Const.CHECK_OK) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        // §16.5: setW does not check points, so caKey is checked explicitly, twice (§16.2 item 4)
        short caOff = (short) (ISO7816.OFFSET_CDATA + Const.CERT_LEN);
        short c1 = secp.onCurve(buf, caOff);
        if (c1 != Const.CHECK_OK) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        short c2 = secp.onCurve(buf, caOff);
        if (c2 != Const.CHECK_OK) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        JCSystem.beginTransaction();
        caKey.setW(buf, caOff, Const.POINT_LEN);
        state.write(State.OFF_CERT, buf, ISO7816.OFFSET_CDATA, Const.CERT_LEN);
        // the checked copy of A is buf[CDATA..+33): Mem.P[0..96) is onCurve's scratch;
        // the certificate signature is verified twice (architecture §6)
        short ok1 =
                verify(
                        caKey,
                        Const.LABEL_CERT,
                        buf,
                        ISO7816.OFFSET_CDATA,
                        Const.COMPRESSED_LEN,
                        buf,
                        (short) (ISO7816.OFFSET_CDATA + Const.COMPRESSED_LEN));
        if (ok1 != Const.CHECK_OK) {
            JCSystem.abortTransaction();
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        short ok2 =
                verify(
                        caKey,
                        Const.LABEL_CERT,
                        buf,
                        ISO7816.OFFSET_CDATA,
                        Const.COMPRESSED_LEN,
                        buf,
                        (short) (ISO7816.OFFSET_CDATA + Const.COMPRESSED_LEN));
        if (ok2 != Const.CHECK_OK) {
            JCSystem.abortTransaction();
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        // the guarded check, evaluated twice, immediately before the effect (§16.2 item 4);
        // the gate already passed, so a mismatch here is a detected fault, not bad data.
        // The exceptional exit leaves T-PERSO open and the platform aborts it itself,
        // answering 6F00 (JCRE 3.0.5 §7.6.2, sim patch 3)
        short l1 = state.life();
        if (l1 != Const.LIFE_FACTORY) {
            ISOException.throwIt(Const.SW_FAULT);
        }
        short l2 = state.life();
        if (l2 != Const.LIFE_FACTORY) {
            ISOException.throwIt(Const.SW_FAULT);
        }
        state.setLife(Const.LIFE_BLANK);
        JCSystem.commitTransaction();
        return 0;
    }

    /**
     * Signs the 32-byte precomputed hash with the identity key and returns {@code r ‖ s} (§1).
     * Every signature is self-verified before output (§16.2 item 5, AGENTS invariant 5); a failed
     * self-verification is a fault.
     */
    void signHash(byte[] hash, short hOff, byte[] out, short oOff) {
        Signature ecdsa = secp.ecdsa;
        ecdsa.init(idKey.getPrivate(), Signature.MODE_SIGN);
        short derLen = ecdsa.signPreComputedHash(hash, hOff, Const.HASH_LEN, mem.W, Mem.W_DER);
        secp.derToRs(mem.W, Mem.W_DER, derLen, out, oOff);
        short v = verifyHash(idPublic, hash, hOff, out, oOff);
        if (v != Const.CHECK_OK) {
            ISOException.throwIt(Const.SW_FAULT);
        }
    }

    /**
     * Hashes {@code SHA-256(label ‖ msg)} and verifies {@code r ‖ s} under {@code key}; coded
     * result, no exception on a bad signature.
     */
    short verify(
            ECPublicKey key,
            byte[] label,
            byte[] msg,
            short mOff,
            short mLen,
            byte[] rs,
            short rsOff) {
        mem.sha256.reset();
        mem.sha256.update(label, (short) 0, (short) label.length);
        mem.sha256.doFinal(msg, mOff, mLen, mem.W, W_TH);
        return verifyHash(key, mem.W, W_TH, rs, rsOff);
    }

    /**
     * Verifies {@code r ‖ s} over a 32-byte precomputed hash; {@code CHECK_MALFORMED} on an
     * out-of-range scalar (it cannot have come from a signature), {@code CHECK_FAIL} on a bad
     * signature or a {@link CryptoException} from the engine.
     */
    short verifyHash(ECPublicKey key, byte[] hash, short hOff, byte[] rs, short rsOff) {
        short derLen = secp.rsToDer(rs, rsOff, mem.W, Mem.W_DER);
        if (derLen == 0) {
            return Const.CHECK_MALFORMED;
        }
        try {
            secp.ecdsa.init(key, Signature.MODE_VERIFY);
            return secp.ecdsa.verifyPreComputedHash(
                            hash, hOff, Const.HASH_LEN, mem.W, Mem.W_DER, derLen)
                    ? Const.CHECK_OK
                    : Const.CHECK_FAIL;
        } catch (CryptoException e) {
            return Const.CHECK_FAIL;
        }
    }
}
