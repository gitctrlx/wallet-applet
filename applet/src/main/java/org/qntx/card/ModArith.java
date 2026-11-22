// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import javacard.framework.Util;
import javacard.security.KeyBuilder;
import javacard.security.RSAPrivateKey;
import javacardx.crypto.Cipher;

/**
 * Constant-time arithmetic mod the secp256k1 field prime {@code p} (§16.2 item 7, §16.4). Squaring
 * is {@code x² mod m} through a {@code LENGTH_RSA_512} private key with modulus {@code 0³² ‖ p} and
 * exponent 2 (protocol.md §3 item 1); multiplication is {@code ((a + b)² − (a − b)²)/4} with {@code
 * a + b} reduced by one conditional subtraction of {@code p}, {@code a − b} computed as {@code a −
 * b + p} and reduced the same way, and division by 4 as two modular halvings. Fixed loop bounds and
 * masks; no branch or index depends on the operand values.
 *
 * <p>All of {@code Mem.W} is this class's working area: {@code W[0..128)} holds the RSA input and
 * output blocks and {@link #mul} uses {@code W[128..256)} for its four temporaries. Operands and
 * outputs of every operation must therefore live outside {@code Mem.W} (for example in {@code
 * Mem.P}).
 */
final class ModArith {
    /** RSA modulus {@code 0³² ‖ p}; the lower half doubles as the operand {@code p}. */
    private static final byte[] MOD_P = {
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFE,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFC,
        (byte) 0x2F,
    };

    /** Offset of {@code p} inside {@link #MOD_P}. */
    private static final short P = 32;

    /** {@code (p + 1)/2}, added to {@code x >> 1} when {@code x} is odd: {@code (x+p)/2 mod p}. */
    private static final byte[] HALF_P = {
        (byte) 0x7F, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x7F, (byte) 0xFF,
        (byte) 0xFE, (byte) 0x18,
    };

    private static final byte[] EXP2 = {2};

    /** {@link Mem#W} offsets of {@link #mul}'s temporaries. */
    private static final short T1 = 128;

    private static final short T2 = 160;
    private static final short T3 = 192;
    private static final short T4 = 224;

    /** Add/sub scratch (the difference to select from). */
    private static final short D = 0;

    /** RSA input block {@code 0³² ‖ operand} at {@link Mem#W}[0..64), output at [64..128). */
    private static final short RSA_IN = 0;

    private static final short RSA_OP = 32;
    private static final short RSA_OUT = 64;

    private final Mem mem;
    private final RSAPrivateKey rsa;
    private final Cipher rsaCipher;

    ModArith(Mem mem) {
        this.mem = mem;
        rsa =
                (RSAPrivateKey)
                        KeyBuilder.buildKey(
                                KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_512, false);
        rsa.setModulus(MOD_P, (short) 0, (short) MOD_P.length);
        rsa.setExponent(EXP2, (short) 0, (short) EXP2.length);
        rsaCipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
    }

    /** {@code out = x² mod p} for a 32-byte big-endian {@code x < p}. */
    void square(byte[] x, short xOff, byte[] out, short oOff) {
        byte[] w = mem.W;
        Util.arrayFillNonAtomic(w, RSA_IN, (short) 32, (byte) 0);
        Util.arrayCopy(x, xOff, w, RSA_OP, (short) 32);
        rsaCipher.init(rsa, Cipher.MODE_DECRYPT);
        rsaCipher.doFinal(w, RSA_IN, (short) 64, w, RSA_OUT);
        Util.arrayCopy(w, (short) (RSA_OUT + 32), out, oOff, (short) 32);
    }

    /** {@code out = a·b mod p} = {@code ((a+b)² − (a−b)²)/4 mod p}; operands 32-byte, below p. */
    void mul(byte[] a, short aOff, byte[] b, short bOff, byte[] out, short oOff) {
        byte[] w = mem.W;
        addMod(a, aOff, b, bOff, w, T1);
        subMod(a, aOff, b, bOff, w, T2);
        square(w, T1, w, T3);
        square(w, T2, w, T4);
        subMod(w, T3, w, T4, w, T1);
        half(w, T1, w, T2);
        half(w, T2, out, oOff);
    }

    /**
     * {@code out = (a + b) mod p} for operands below {@code p}: one conditional subtraction.
     * Internal scratch {@code W[0..32)}; {@code a}, {@code b} and {@code out} live outside it.
     */
    void addMod(byte[] a, short aOff, byte[] b, short bOff, byte[] out, short oOff) {
        byte[] w = mem.W;
        short carry = 0;
        for (short i = 31; i >= 0; i--) {
            short t =
                    (short)
                            ((a[(short) (aOff + i)] & 0xFF)
                                    + (b[(short) (bOff + i)] & 0xFF)
                                    + carry);
            out[(short) (oOff + i)] = (byte) t;
            carry = (short) (t >> 8);
        }
        // d = s − p; the 33-bit subtraction underflows exactly when carry = 0 and s < p
        short borrow = 0;
        for (short i = 31; i >= 0; i--) {
            short t =
                    (short)
                            ((out[(short) (oOff + i)] & 0xFF)
                                    - (MOD_P[(short) (P + i)] & 0xFF)
                                    - borrow);
            w[(short) (D + i)] = (byte) t;
            borrow = (short) ((t >> 8) & 1);
        }
        byte mask = (byte) ((borrow & (short) (carry ^ 1)) - 1);
        for (short i = 0; i < 32; i++) {
            short j = (short) (oOff + i);
            out[j] ^= (byte) (mask & (out[j] ^ w[(short) (D + i)]));
        }
    }

    /**
     * {@code out = (a − b) mod p} = {@code a − b + p} then conditionally reduced. Internal scratch
     * {@code W[0..32)}; {@code a}, {@code b} and {@code out} live outside it.
     */
    void subMod(byte[] a, short aOff, byte[] b, short bOff, byte[] out, short oOff) {
        byte[] w = mem.W;
        short borrow = 0;
        for (short i = 31; i >= 0; i--) {
            short t =
                    (short)
                            ((a[(short) (aOff + i)] & 0xFF)
                                    - (b[(short) (bOff + i)] & 0xFF)
                                    - borrow);
            out[(short) (oOff + i)] = (byte) t;
            borrow = (short) ((t >> 8) & 1);
        }
        // e = d + p (low 32 bytes); a borrow means d wrapped, so d + p is the result
        short carry = 0;
        for (short i = 31; i >= 0; i--) {
            short t =
                    (short)
                            ((out[(short) (oOff + i)] & 0xFF)
                                    + (MOD_P[(short) (P + i)] & 0xFF)
                                    + carry);
            w[(short) (D + i)] = (byte) t;
            carry = (short) (t >> 8);
        }
        byte mask = (byte) -borrow;
        for (short i = 0; i < 32; i++) {
            short j = (short) (oOff + i);
            out[j] ^= (byte) (mask & (out[j] ^ w[(short) (D + i)]));
        }
    }

    /**
     * {@code out = x/2 mod p}: {@code x >> 1} plus {@code (p+1)/2} when {@code x} is odd (mask, no
     * branch). {@code x} and {@code out} may alias.
     */
    void half(byte[] x, short xOff, byte[] out, short oOff) {
        byte mask = (byte) -((short) (x[(short) (xOff + 31)] & 0x01));
        for (short i = 31; i > 0; i--) {
            out[(short) (oOff + i)] =
                    (byte)
                            (((x[(short) (xOff + i)] & 0xFF) >>> 1)
                                    | ((x[(short) (xOff + i - 1)] & 0x01) << 7));
        }
        out[oOff] = (byte) ((x[xOff] & 0xFF) >>> 1);
        short carry = 0;
        for (short i = 31; i >= 0; i--) {
            short t =
                    (short) ((out[(short) (oOff + i)] & 0xFF) + (HALF_P[i] & mask & 0xFF) + carry);
            out[(short) (oOff + i)] = (byte) t;
            carry = (short) (t >> 8);
        }
    }
}
