// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import javacard.framework.Util;
import javacard.security.KeyBuilder;
import javacard.security.RSAPrivateKey;
import javacardx.crypto.Cipher;

/**
 * Constant-time arithmetic modulo the secp256k1 field prime {@code p}, the secp256k1 group order
 * {@code n} and the ed25519 prime-subgroup order {@code ℓ} (§16.2 item 7, §16.4). Squaring is
 * {@code x² mod m} through a {@code LENGTH_RSA_512} private key with modulus {@code 0³² ‖ m} and
 * exponent 2 (protocol.md §3 item 1); multiplication is {@code ((a + b)² − (a − b)²)/4} with {@code
 * a + b} reduced by one conditional subtraction of {@code m}, {@code a − b} computed as {@code a −
 * b + m} and reduced the same way, and division by 4 as two modular halvings. Fixed loop bounds and
 * masks; no branch or index depends on the operand values.
 *
 * <p>All of {@code Mem.W} is this class's working area: {@code W[0..128)} holds the RSA input and
 * output blocks and {@link #mul} uses {@code W[128..256)} for its four temporaries. Operands and
 * outputs of every operation must therefore live outside {@code Mem.W} (for example in {@code
 * Mem.P}). Operands are 32-byte big-endian and below {@code m} unless stated.
 */
final class ModArith {
    /** Modulus ids: the byte index of {@code p}, {@code n} and {@code ℓ}. */
    static final byte MOD_P = 0;

    static final byte MOD_N = 1;
    static final byte MOD_L = 2;

    /**
     * The three RSA moduli {@code 0³² ‖ m}, 64 bytes each, indexed by {@code m·64}; the lower half
     * of each doubles as the 32-byte operand {@code m} at {@code m·64 + 32}.
     */
    private static final byte[] MOD = {
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFE, (byte) 0xFF, (byte) 0xFF, (byte) 0xFC,
                (byte) 0x2F,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                (byte) 0xFE,
        (byte) 0xBA, (byte) 0xAE, (byte) 0xDC, (byte) 0xE6, (byte) 0xAF, (byte) 0x48, (byte) 0xA0,
                (byte) 0x3B,
        (byte) 0xBF, (byte) 0xD2, (byte) 0x5E, (byte) 0x8C, (byte) 0xD0, (byte) 0x36, (byte) 0x41,
                (byte) 0x41,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00,
        (byte) 0x10, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00,
        (byte) 0x14, (byte) 0xDE, (byte) 0xF9, (byte) 0xDE, (byte) 0xA2, (byte) 0xF7, (byte) 0x9C,
                (byte) 0xD6,
        (byte) 0x58, (byte) 0x12, (byte) 0x63, (byte) 0x1A, (byte) 0x5C, (byte) 0xF5, (byte) 0xD3,
                (byte) 0xED,
    };

    /** Offset of the 32-byte operand {@code m} inside its {@link #MOD} slot. */
    private static final short M32 = 32;

    /** {@code (m + 1)/2} per modulus, indexed by {@code m·32}. */
    private static final byte[] HALF = {
        (byte) 0x7F, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x7F, (byte) 0xFF, (byte) 0xFE,
                (byte) 0x18,
        (byte) 0x7F, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
                (byte) 0xFF,
        (byte) 0x5D, (byte) 0x57, (byte) 0x6E, (byte) 0x73, (byte) 0x57, (byte) 0xA4, (byte) 0x50,
                (byte) 0x1D,
        (byte) 0xDF, (byte) 0xE9, (byte) 0x2F, (byte) 0x46, (byte) 0x68, (byte) 0x1B, (byte) 0x20,
                (byte) 0xA1,
        (byte) 0x08, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00,
        (byte) 0x0A, (byte) 0x6F, (byte) 0x7C, (byte) 0xEF, (byte) 0x51, (byte) 0x7B, (byte) 0xCE,
                (byte) 0x6B,
        (byte) 0x2C, (byte) 0x09, (byte) 0x31, (byte) 0x8D, (byte) 0x2E, (byte) 0x7A, (byte) 0xE9,
                (byte) 0xF7,
    };

    /**
     * {@code 8ℓ, 4ℓ, 2ℓ, ℓ}, the conditional-subtraction operands of {@link #reduce} for {@link
     * #MOD_L}: since {@code 8ℓ < 2^255}, any 256-bit input lands below {@code ℓ} after at most
     * these four steps. {@code n} and {@code p} take one conditional subtraction of {@code m}.
     */
    private static final byte[] RED_L = {
        (byte) 0x80, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00,
        (byte) 0xA6, (byte) 0xF7, (byte) 0xCE, (byte) 0xF5, (byte) 0x17, (byte) 0xBC, (byte) 0xE6,
                (byte) 0xB2,
        (byte) 0xC0, (byte) 0x93, (byte) 0x18, (byte) 0xD2, (byte) 0xE7, (byte) 0xAE, (byte) 0x9F,
                (byte) 0x68,
        (byte) 0x40, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00,
        (byte) 0x53, (byte) 0x7B, (byte) 0xE7, (byte) 0x7A, (byte) 0x8B, (byte) 0xDE, (byte) 0x73,
                (byte) 0x59,
        (byte) 0x60, (byte) 0x49, (byte) 0x8C, (byte) 0x69, (byte) 0x73, (byte) 0xD7, (byte) 0x4F,
                (byte) 0xB4,
        (byte) 0x20, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00,
        (byte) 0x29, (byte) 0xBD, (byte) 0xF3, (byte) 0xBD, (byte) 0x45, (byte) 0xEF, (byte) 0x39,
                (byte) 0xAC,
        (byte) 0xB0, (byte) 0x24, (byte) 0xC6, (byte) 0x34, (byte) 0xB9, (byte) 0xEB, (byte) 0xA7,
                (byte) 0xDA,
        (byte) 0x10, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00,
        (byte) 0x14, (byte) 0xDE, (byte) 0xF9, (byte) 0xDE, (byte) 0xA2, (byte) 0xF7, (byte) 0x9C,
                (byte) 0xD6,
        (byte) 0x58, (byte) 0x12, (byte) 0x63, (byte) 0x1A, (byte) 0x5C, (byte) 0xF5, (byte) 0xD3,
                (byte) 0xED,
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
    private final RSAPrivateKey[] rsa;
    private final Cipher rsaCipher;

    ModArith(Mem mem) {
        this.mem = mem;
        rsa = new RSAPrivateKey[3];
        for (short m = 0; m < 3; m++) {
            rsa[m] =
                    (RSAPrivateKey)
                            KeyBuilder.buildKey(
                                    KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_512, false);
            rsa[m].setModulus(MOD, (short) (m * 64), (short) 64);
            rsa[m].setExponent(EXP2, (short) 0, (short) EXP2.length);
        }
        rsaCipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
    }

    /** {@code out = x² mod m} for a 32-byte big-endian {@code x < m}. */
    void square(byte m, byte[] x, short xOff, byte[] out, short oOff) {
        byte[] w = mem.W;
        Util.arrayFillNonAtomic(w, RSA_IN, (short) 32, (byte) 0);
        Util.arrayCopy(x, xOff, w, RSA_OP, (short) 32);
        rsaCipher.init(rsa[m], Cipher.MODE_DECRYPT);
        rsaCipher.doFinal(w, RSA_IN, (short) 64, w, RSA_OUT);
        Util.arrayCopy(w, (short) (RSA_OUT + 32), out, oOff, (short) 32);
    }

    /**
     * {@code out = a·b mod m} = {@code ((a+b)² − (a−b)²)/4 mod m}; operands 32-byte, below {@code
     * m}. Every RSA input is reduced below the modulus in constant time before {@code doFinal}
     * (§16.2 item 7).
     */
    void mul(byte m, byte[] a, short aOff, byte[] b, short bOff, byte[] out, short oOff) {
        byte[] w = mem.W;
        addMod(m, a, aOff, b, bOff, w, T1);
        subMod(m, a, aOff, b, bOff, w, T2);
        square(m, w, T1, w, T3);
        square(m, w, T2, w, T4);
        subMod(m, w, T3, w, T4, w, T1);
        half(m, w, T1, w, T2);
        half(m, w, T2, out, oOff);
    }

    /**
     * {@code out = (a + b) mod m} for operands below {@code m}: one conditional subtraction.
     * Internal scratch {@code W[0..32)}; {@code a}, {@code b} and {@code out} live outside it.
     */
    void addMod(byte m, byte[] a, short aOff, byte[] b, short bOff, byte[] out, short oOff) {
        byte[] w = mem.W;
        short modOff = (short) (m * 64 + M32);
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
        // d = s − m; the 33-bit subtraction underflows exactly when carry = 0 and s < m
        short borrow = 0;
        for (short i = 31; i >= 0; i--) {
            short t =
                    (short)
                            ((out[(short) (oOff + i)] & 0xFF)
                                    - (MOD[(short) (modOff + i)] & 0xFF)
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
     * {@code out = (a − b) mod m} = {@code a − b + m} then conditionally reduced. Internal scratch
     * {@code W[0..32)}; {@code a}, {@code b} and {@code out} live outside it.
     */
    void subMod(byte m, byte[] a, short aOff, byte[] b, short bOff, byte[] out, short oOff) {
        byte[] w = mem.W;
        short modOff = (short) (m * 64 + M32);
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
        // e = d + m (low 32 bytes); a borrow means d wrapped, so d + m is the result
        short carry = 0;
        for (short i = 31; i >= 0; i--) {
            short t =
                    (short)
                            ((out[(short) (oOff + i)] & 0xFF)
                                    + (MOD[(short) (modOff + i)] & 0xFF)
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
     * {@code out = x/2 mod m}: {@code x >> 1} plus {@code (m+1)/2} when {@code x} is odd (mask, no
     * branch). {@code x} and {@code out} may alias.
     */
    void half(byte m, byte[] x, short xOff, byte[] out, short oOff) {
        byte mask = (byte) -((short) (x[(short) (xOff + 31)] & 0x01));
        for (short i = 31; i > 0; i--) {
            out[(short) (oOff + i)] =
                    (byte)
                            (((x[(short) (xOff + i)] & 0xFF) >>> 1)
                                    | ((x[(short) (xOff + i - 1)] & 0x01) << 7));
        }
        out[oOff] = (byte) ((x[xOff] & 0xFF) >>> 1);
        short halfOff = (short) (m * 32);
        short carry = 0;
        for (short i = 31; i >= 0; i--) {
            short t =
                    (short)
                            ((out[(short) (oOff + i)] & 0xFF)
                                    + (HALF[(short) (halfOff + i)] & mask & 0xFF)
                                    + carry);
            out[(short) (oOff + i)] = (byte) t;
            carry = (short) (t >> 8);
        }
    }

    /** Coded {@code CHECK_OK} iff the 32-byte {@code x} is below {@code m}, constant time. */
    short below(byte m, byte[] x, short xOff) {
        short modOff = (short) (m * 64 + M32);
        short borrow = 0;
        for (short i = 31; i >= 0; i--) {
            short t =
                    (short)
                            ((x[(short) (xOff + i)] & 0xFF)
                                    - (MOD[(short) (modOff + i)] & 0xFF)
                                    - borrow);
            borrow = (short) ((t >> 8) & 1);
        }
        return borrow == 1 ? Const.CHECK_OK : Const.CHECK_FAIL;
    }

    /** Coded {@code CHECK_OK} iff the 32-byte {@code x} is all zero, constant time. */
    static short isZero(byte[] x, short xOff) {
        short any = 0;
        for (short i = 0; i < 32; i++) {
            any = (short) (any | (x[(short) (xOff + i)] & 0xFF));
        }
        return any == 0 ? Const.CHECK_OK : Const.CHECK_FAIL;
    }

    /**
     * {@code x ← x mod m} in place for <em>any</em> 256-bit {@code x}: constant-time conditional
     * subtractions of {@code 8ℓ, 4ℓ, 2ℓ, ℓ} for {@link #MOD_L} (whose range needs four steps), one
     * conditional subtraction of {@code m} for {@code n} and {@code p}. Internal scratch {@code
     * W[0..32)}; {@code x} lives outside it.
     */
    void reduce(byte m, byte[] x, short xOff) {
        if (m == MOD_L) {
            for (short i = 0; i < 4; i++) {
                condSub(x, xOff, RED_L, (short) (i * 32));
            }
        } else {
            condSub(x, xOff, MOD, (short) (m * 64 + M32));
        }
    }

    /**
     * {@code x ← x − s} iff {@code x ≥ s}, constant time: computes the difference, then selects it
     * under the borrow mask. Internal scratch {@code W[0..32)}.
     */
    private void condSub(byte[] x, short xOff, byte[] s, short sOff) {
        byte[] w = mem.W;
        short borrow = 0;
        for (short i = 31; i >= 0; i--) {
            short t =
                    (short)
                            ((x[(short) (xOff + i)] & 0xFF)
                                    - (s[(short) (sOff + i)] & 0xFF)
                                    - borrow);
            w[(short) (D + i)] = (byte) t;
            borrow = (short) ((t >> 8) & 1);
        }
        byte mask = (byte) (borrow - 1); // borrow 1 (x < s): keep x; borrow 0: take x − s
        for (short i = 0; i < 32; i++) {
            short j = (short) (xOff + i);
            x[j] ^= (byte) (mask & (x[j] ^ w[(short) (D + i)]));
        }
    }
}
