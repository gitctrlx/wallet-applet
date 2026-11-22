// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.Signature;

/**
 * secp256k1 domain (SEC 2 v2 §2.4.1), scalar multiplication through {@code
 * ALG_EC_SVDP_DH_PLAIN_XY}, compression, the explicit on-curve check of §16.5 and the DER ⇄ {@code
 * r ‖ s} codec of §1. Owns the shared {@code ALG_ECDSA_SHA_256} engine and the transient private
 * key every scalar multiplication is loaded into.
 */
final class Secp256k1 {
    /** Field prime {@code p}. */
    static final byte[] P = {
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFE, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFC, (byte) 0x2F,
    };

    /** Curve coefficient {@code a = 0}. */
    private static final byte[] A = new byte[32];

    /** Curve coefficient {@code b = 7}. */
    private static final byte[] B = {7};

    /** {@code b} as a 32-byte operand of {@link ModArith} for {@code x³ + 7}. */
    private static final byte[] B32 = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        7
    };

    /** Generator {@code G}, uncompressed. */
    static final byte[] G = {
        (byte) 0x04, (byte) 0x79, (byte) 0xBE, (byte) 0x66, (byte) 0x7E, (byte) 0xF9,
        (byte) 0xDC, (byte) 0xBB, (byte) 0xAC, (byte) 0x55, (byte) 0xA0, (byte) 0x62,
        (byte) 0x95, (byte) 0xCE, (byte) 0x87, (byte) 0x0B, (byte) 0x07, (byte) 0x02,
        (byte) 0x9B, (byte) 0xFC, (byte) 0xDB, (byte) 0x2D, (byte) 0xCE, (byte) 0x28,
        (byte) 0xD9, (byte) 0x59, (byte) 0xF2, (byte) 0x81, (byte) 0x5B, (byte) 0x16,
        (byte) 0xF8, (byte) 0x17, (byte) 0x98, (byte) 0x48, (byte) 0x3A, (byte) 0xDA,
        (byte) 0x77, (byte) 0x26, (byte) 0xA3, (byte) 0xC4, (byte) 0x65, (byte) 0x5D,
        (byte) 0xA4, (byte) 0xFB, (byte) 0xFC, (byte) 0x0E, (byte) 0x11, (byte) 0x08,
        (byte) 0xA8, (byte) 0xFD, (byte) 0x17, (byte) 0xB4, (byte) 0x48, (byte) 0xA6,
        (byte) 0x85, (byte) 0x54, (byte) 0x19, (byte) 0x9C, (byte) 0x47, (byte) 0xD0,
        (byte) 0x8F, (byte) 0xFB, (byte) 0x10, (byte) 0xD4, (byte) 0xB8,
    };

    /** Group order {@code n}. */
    static final byte[] N = {
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFE, (byte) 0xBA, (byte) 0xAE,
        (byte) 0xDC, (byte) 0xE6, (byte) 0xAF, (byte) 0x48, (byte) 0xA0, (byte) 0x3B,
        (byte) 0xBF, (byte) 0xD2, (byte) 0x5E, (byte) 0x8C, (byte) 0xD0, (byte) 0x36,
        (byte) 0x41, (byte) 0x41,
    };

    /**
     * {@link Mem#P} offsets of the {@link #onCurve} operands (all of {@link Mem#W} is ModArith's).
     */
    private static final short P_Y2 = 0;

    private static final short P_X2 = 32;
    private static final short P_RHS = 64;

    private final Mem mem;
    private final ModArith modArith;

    /** Shared with {@link Identity}: the only ECDSA engine (architecture.md §5.1). */
    final Signature ecdsa;

    /** Single-use scalar slot of {@link #mul}; wiped by {@link #wipeScalar}. */
    private final ECPrivateKey ephKey;

    private final KeyAgreement agreement;

    Secp256k1(Mem mem, ModArith modArith) {
        this.mem = mem;
        this.modArith = modArith;
        ecdsa = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        ephKey =
                (ECPrivateKey)
                        KeyBuilder.buildKey(
                                KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT,
                                KeyBuilder.LENGTH_EC_FP_256,
                                false);
        setDomain(ephKey);
        agreement = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY, false);
    }

    /** Loads the SEC 2 §2.4.1 parameters onto a key object. */
    static void setDomain(ECKey key) {
        key.setFieldFP(P, (short) 0, (short) P.length);
        key.setA(A, (short) 0, (short) A.length);
        key.setB(B, (short) 0, (short) B.length);
        key.setG(G, (short) 0, (short) G.length);
        key.setR(N, (short) 0, (short) N.length);
        key.setK((short) 1);
    }

    /** A fresh scalar {@code 1 ≤ int ≤ n − 1} (§8.1), redrawn while out of range. */
    void randomScalar(byte[] out, short off) {
        for (; ; ) {
            mem.random.nextBytes(out, off, (short) 32);
            short any = 0;
            for (short i = 0; i < 32; i++) {
                any |= out[(short) (off + i)];
            }
            if (any != 0 && compare(out, off, N, (short) 0) < 0) {
                return;
            }
        }
    }

    /**
     * {@code out = scalar·point} (65-byte uncompressed) via PLAIN_XY. Loads the scalar into the
     * transient key; a {@code CryptoException} (invalid point, §3 item 3) propagates to the caller,
     * which maps it.
     */
    void mul(byte[] scalar, short sOff, byte[] point, short pOff, byte[] out, short oOff) {
        ephKey.setS(scalar, sOff, (short) 32);
        agreement.init(ephKey);
        agreement.generateSecret(point, pOff, Const.POINT_LEN, out, oOff);
    }

    /** Overwrites the transient scalar slot; no {@code clearKey} anywhere (architecture.md §4). */
    void wipeScalar() {
        ephKey.setS(Const.ZEROS, (short) 0, (short) 32);
    }

    /** SEC 1 §2.3.3 compression of an uncompressed point. */
    void compress(byte[] point, short pOff, byte[] out, short oOff) {
        out[oOff] = (point[(short) (pOff + 64)] & 0x01) == 0 ? (byte) 0x02 : (byte) 0x03;
        Util.arrayCopy(point, (short) (pOff + 1), out, (short) (oOff + 1), (short) 32);
    }

    /**
     * The explicit on-curve check of §16.5 ({@code setW} does not check points): {@code point[0] =
     * 0x04}, both coordinates {@code < p} and {@code y² ≡ x³ + 7 (mod p)}. Coded result.
     */
    short onCurve(byte[] point, short off) {
        if (point[off] != 0x04) {
            return Const.CHECK_FAIL;
        }
        if (compare(point, (short) (off + 1), P, (short) 0) >= 0
                || compare(point, (short) (off + 33), P, (short) 0) >= 0) {
            return Const.CHECK_FAIL;
        }
        byte[] p = mem.P;
        modArith.square(point, (short) (off + 33), p, P_Y2);
        modArith.mul(point, (short) (off + 1), point, (short) (off + 1), p, P_X2);
        modArith.mul(p, P_X2, point, (short) (off + 1), p, P_RHS);
        modArith.addMod(p, P_RHS, B32, (short) 0, p, P_X2);
        return Bytes.equal(p, P_Y2, p, P_X2, (short) 32);
    }

    /**
     * Strict DER decode of the platform's ECDSA output into {@code r(32) ‖ s(32)}: SEQUENCE of two
     * positive INTEGERs of at most 33 bytes, a leading 0x00 only when the high bit needs it.
     * Anything unexpected is a platform fault ({@code 6F00}).
     */
    void derToRs(byte[] der, short dOff, short dLen, byte[] out, short oOff) {
        Util.arrayFillNonAtomic(out, oOff, (short) 64, (byte) 0);
        short i = dOff;
        short end = (short) (dOff + dLen);
        if (dLen < 8
                || der[i] != 0x30
                || (short) (der[(short) (i + 1)] & 0xFF) != (short) (dLen - 2)) {
            ISOException.throwIt(Const.SW_FAULT);
        }
        i += 2;
        i = integer(der, i, end, out, (short) (oOff + 32));
        i = integer(der, i, end, out, (short) (oOff + 64));
        if (i != end) {
            ISOException.throwIt(Const.SW_FAULT);
        }
    }

    /**
     * {@code r(32) ‖ s(32)} to DER; returns the DER length or 0 when {@code r} or {@code s} is
     * outside {@code [1, n−1]} (§1 {@code Verify} fails then; callers map 0 to CHECK_FAIL).
     */
    short rsToDer(byte[] rs, short rsOff, byte[] out, short oOff) {
        if (inRange(rs, rsOff) != Const.CHECK_OK
                || inRange(rs, (short) (rsOff + 32)) != Const.CHECK_OK) {
            return 0;
        }
        short rLen = intLen(rs, rsOff);
        short sLen = intLen(rs, (short) (rsOff + 32));
        short i = oOff;
        out[i] = 0x30;
        i++;
        out[i] = (byte) (2 + rLen + 2 + sLen);
        i++;
        i = putInt(rs, rsOff, out, i);
        i = putInt(rs, (short) (rsOff + 32), out, i);
        return (short) (i - oOff);
    }

    /** Writes one INTEGER element of the 32-byte {@code v}; returns the next offset. */
    private static short putInt(byte[] v, short vOff, byte[] out, short i) {
        short i0 = firstSignificant(v, vOff);
        short sigLen = (short) (32 - i0);
        short signByte = (short) ((v[(short) (vOff + i0)] & 0x80) >>> 7);
        out[i] = 0x02;
        i++;
        out[i] = (byte) (sigLen + signByte);
        i++;
        if (signByte != 0) {
            out[i] = 0;
            i++;
        }
        Util.arrayCopy(v, (short) (vOff + i0), out, i, sigLen);
        i += sigLen;
        return i;
    }

    /** DER INTEGER payload length of a 32-byte value: no leading zeros, sign byte when needed. */
    private static short intLen(byte[] v, short off) {
        short i0 = firstSignificant(v, off);
        return (short) (32 - i0 + ((v[(short) (off + i0)] & 0x80) != 0 ? 1 : 0));
    }

    /** Index of the first non-zero byte of the 32-byte value at {@code v[off..off+32)}. */
    private static short firstSignificant(byte[] v, short off) {
        short i = 0;
        while (i < 31 && v[(short) (off + i)] == 0) {
            i++;
        }
        return i;
    }

    /** {@code CHECK_OK} when the 32-byte value is in {@code [1, n−1]}. */
    private static short inRange(byte[] v, short off) {
        short any = 0;
        for (short i = 0; i < 32; i++) {
            any |= v[(short) (off + i)];
        }
        return any != 0 && compare(v, off, N, (short) 0) < 0 ? Const.CHECK_OK : Const.CHECK_FAIL;
    }

    /**
     * Parses one DER INTEGER into the right-aligned 32-byte slot {@code out}; -32 shift of next.
     */
    private static short integer(byte[] der, short i, short end, byte[] out, short outEnd) {
        if ((short) (i + 2) > end || der[i] != 0x02) {
            ISOException.throwIt(Const.SW_FAULT);
        }
        short len = (short) (der[(short) (i + 1)] & 0xFF);
        i += 2;
        if (len < 1 || len > 33 || (short) (i + len) > end) {
            ISOException.throwIt(Const.SW_FAULT);
        }
        if (len > 1 && der[i] == 0 && (der[(short) (i + 1)] & 0x80) == 0) {
            // non-minimal positive encoding
            ISOException.throwIt(Const.SW_FAULT);
        }
        if (len == 33 && der[i] != 0) {
            ISOException.throwIt(Const.SW_FAULT);
        }
        if (len != 33 && (short) (der[i] & 0x80) != 0) {
            // a negative INTEGER: the sign byte is missing
            ISOException.throwIt(Const.SW_FAULT);
        }
        short skip = (short) (len == 33 ? 1 : 0);
        Util.arrayCopy(
                der,
                (short) (i + skip),
                out,
                (short) (outEnd - (short) (len - skip)),
                (short) (len - skip));
        return (short) (i + len);
    }

    /** Lexicographic compare of two 32-byte big-endian values; <0, 0, >0. */
    private static short compare(byte[] a, short aOff, byte[] b, short bOff) {
        for (short i = 0; i < 32; i++) {
            short d = (short) ((a[(short) (aOff + i)] & 0xFF) - (b[(short) (bOff + i)] & 0xFF));
            if (d != 0) {
                return d;
            }
        }
        return 0;
    }
}
