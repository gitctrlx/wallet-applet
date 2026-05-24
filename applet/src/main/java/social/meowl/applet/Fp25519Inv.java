/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.KeyBuilder;
import javacard.security.RSAPrivateKey;
import javacardx.crypto.Cipher;

/**
 * Modular inverse over {@code p = 2²⁵⁵ − 19} via Fermat: {@code a⁻¹ ≡ a^(p − 2) (mod p)}.
 *
 * <h2>Two execution paths, probed at install</h2>
 *
 * <p>The fast path turns the platform RSA engine into a 256-bit modular-exponentiation primitive: a
 * 512-bit {@link RSAPrivateKey} carries the zero-extended {@code p} as modulus and {@code p − 2} as
 * private exponent, and a single {@link Cipher#ALG_RSA_NOPAD} {@code doFinal} replaces the
 * 254-iteration software Fermat ladder. JCMathLib's {@code bigNatModInv} measures this at ~58 ms on
 * a JCOP4 P71 J3R200 — the same EC + RSA accelerator family as J3R180.
 *
 * <p>The slow path is a constant-time software Fermat ladder over the public exponent {@code p −
 * 2}. It is ~3 orders of magnitude slower (~2.5 s) but portable, and the only way the applet
 * survives on simulators (such as licel jcardsim) whose BouncyCastle backbone rejects an RSA key
 * whose modulus is not a composite of two primes.
 *
 * <p>The constructor probes the RSA engine with {@code 1 · 1⁻¹ ≡ 1 (mod p)}; if the round-trip
 * fails for any reason — typed exception, length mismatch, garbled output — the instance falls back
 * to the software ladder. Per-call cost of the probe decision is one boolean check.
 *
 * <h2>Scratch</h2>
 *
 * <p>Caller hands in a {@link #SCRATCH_LEN}-byte slice. Layout:
 *
 * <pre>
 *   scratch[ 0..64) — RSA input slot (top 32 zero bytes ‖ 32-byte operand)
 *   scratch[64..128) — RSA output slot (top 32 zero bytes ‖ 32-byte residue)
 * </pre>
 *
 * <p>The software fallback path uses {@code scratch[0..32]} as the running-power slot and {@code
 * scratch[32..96]} as the {@link Fp25519#mul} product slot, all within the same 128-byte budget.
 * The whole slice is wiped before {@link #inv} returns.
 */
public final class Fp25519Inv {

    /** RSA key bit length used to emulate a 256-bit modulus. */
    private static final short RSA_BIT_LEN = (short) 512;

    /** Byte width of the RSA modulus / exponent / operand window. */
    private static final short RSA_BYTE_LEN = (short) 64;

    /** Scratch budget covering both paths: 2 × 64-byte RSA buffers; software path lives in same. */
    public static final short SCRATCH_LEN = (short) (2 * RSA_BYTE_LEN);

    private static final short PADDED_OFFSET = (short) (RSA_BYTE_LEN - Fp25519.LEN);

    /** Software-path sub-offsets: a 32-byte staged copy plus a 64-byte product slot. */
    private static final short SOFT_PROD_OFF = (short) 0;

    private static final short SOFT_TMP_OFF = (short) 64;

    /**
     * 64-byte zero-extended {@code p} (modulus value). Materialised as a literal because the JC CAP
     * converter rejects {@code invokestatic} from {@code <clinit>}: building the array via a helper
     * method works on the JVM but fails offcard conversion.
     */
    private static final byte[] P_PADDED = {
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x7F, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xED,
    };

    /** 64-byte zero-extended {@code p − 2} (Fermat exponent). Same materialisation rationale. */
    private static final byte[] P_MINUS_2_PADDED = {
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x7F, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
        (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xEB,
    };

    private final RSAPrivateKey rsaKey;
    private final Cipher rsaCipher;
    private final boolean hardwareAvailable;

    /**
     * Allocates the RSA fixture and probes the engine. Construction never throws: if RSA fails, the
     * software fallback kicks in transparently at {@link #inv} time. The RSA modulus and exponent
     * are re-loaded inside every {@link #inv} call rather than once here, because JCMathLib's
     * JCOP4_P71 profile reports {@code DEFERRED_INITIALIZATION = true} on NXP P71 silicon (J3R180
     * family): RSA key state set at install time does not survive the first {@code select} and must
     * be rebuilt per call.
     */
    public Fp25519Inv() {
        RSAPrivateKey key = null;
        Cipher cipher = null;
        boolean ok = false;
        try {
            key =
                    (RSAPrivateKey)
                            KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, RSA_BIT_LEN, false);
            cipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
            ok = probe(cipher, key);
        } catch (Exception e) {
            ok = false;
        }
        this.rsaKey = ok ? key : null;
        this.rsaCipher = ok ? cipher : null;
        this.hardwareAvailable = ok;
    }

    /**
     * Round-trips {@code 1 · 1⁻¹ ≡ 1 (mod p)} through the engine; returns true iff every byte of
     * the output is the canonical Fp25519 one. The probe sets modulus + exponent inside this
     * routine, exercising the exact code path {@link #hardwareInv} will run at every {@code
     * encodeEdwards} — silicon that rejects the configuration here always rejects it later.
     */
    private static boolean probe(Cipher cipher, RSAPrivateKey key) {
        byte[] probeBuf;
        try {
            probeBuf = JCSystem.makeTransientByteArray(SCRATCH_LEN, JCSystem.CLEAR_ON_DESELECT);
        } catch (Exception e) {
            return false;
        }
        try {
            key.setModulus(P_PADDED, (short) 0, RSA_BYTE_LEN);
            key.setExponent(P_MINUS_2_PADDED, (short) 0, RSA_BYTE_LEN);
            short inOff = (short) 0;
            short outOff = RSA_BYTE_LEN;
            Util.arrayFillNonAtomic(probeBuf, inOff, RSA_BYTE_LEN, (byte) 0);
            probeBuf[(short) (inOff + RSA_BYTE_LEN - 1)] = (byte) 0x01;

            cipher.init(key, Cipher.MODE_DECRYPT);
            short produced = cipher.doFinal(probeBuf, inOff, RSA_BYTE_LEN, probeBuf, outOff);
            short shift = (short) (RSA_BYTE_LEN - produced);
            if (shift < 0 || shift > PADDED_OFFSET) {
                return false;
            }
            byte tailByte = probeBuf[(short) (outOff + RSA_BYTE_LEN - 1)];
            for (short i = 0; i < (short) (RSA_BYTE_LEN - 1); i++) {
                if (probeBuf[(short) (outOff + i)] != 0) {
                    return false;
                }
            }
            return tailByte == (byte) 0x01;
        } catch (Exception e) {
            return false;
        } finally {
            Util.arrayFillNonAtomic(probeBuf, (short) 0, SCRATCH_LEN, (byte) 0);
        }
    }

    /** Returns {@code true} if the platform RSA accelerator is in use, {@code false} otherwise. */
    public boolean isHardwareAccelerated() {
        return hardwareAvailable;
    }

    /**
     * {@code out ← a⁻¹ mod p}. Throws {@link Constants.Sw#INTERNAL_ERROR} on {@code a == 0}.
     *
     * @param a canonical 32-byte big-endian field element; UNMODIFIED
     * @param aOff start offset within {@code a}
     * @param out 32-byte big-endian destination; MAY alias {@code a}
     * @param outOff start offset within {@code out}
     * @param scratch caller-supplied workspace of at least {@link #SCRATCH_LEN} bytes
     * @param scOff start offset within {@code scratch}
     */
    public void inv(byte[] a, short aOff, byte[] out, short outOff, byte[] scratch, short scOff) {
        if (BigNat.ctIsZero(a, aOff, Fp25519.LEN) != 0) {
            ISOException.throwIt(Constants.Sw.INTERNAL_ERROR);
        }
        if (hardwareAvailable) {
            hardwareInv(a, aOff, out, outOff, scratch, scOff);
        } else {
            softwareInv(a, aOff, out, outOff, scratch, scOff);
        }
    }

    /**
     * RSA-NOPAD path: a single hardware modular exponentiation. {@code a^(p − 2) ≡ a⁻¹ (mod p)}.
     * The engine sometimes strips leading zero bytes from the output; the right-align block below
     * canonicalises the 64-byte slot back to its full width before the 32-byte tail is copied out.
     */
    private void hardwareInv(
            byte[] a, short aOff, byte[] out, short outOff, byte[] scratch, short scOff) {
        short inOff = scOff;
        short outBufOff = (short) (scOff + RSA_BYTE_LEN);
        Util.arrayFillNonAtomic(scratch, inOff, PADDED_OFFSET, (byte) 0);
        Util.arrayCopyNonAtomic(a, aOff, scratch, (short) (inOff + PADDED_OFFSET), Fp25519.LEN);

        // Re-set modulus/exponent on every call: J3R180 discards them across deselect, mirroring
        // the JCMathLib JCOP4_P71 DEFERRED_INITIALIZATION semantics.
        rsaKey.setModulus(P_PADDED, (short) 0, RSA_BYTE_LEN);
        rsaKey.setExponent(P_MINUS_2_PADDED, (short) 0, RSA_BYTE_LEN);
        rsaCipher.init(rsaKey, Cipher.MODE_DECRYPT);
        short produced = rsaCipher.doFinal(scratch, inOff, RSA_BYTE_LEN, scratch, outBufOff);
        if (produced != RSA_BYTE_LEN) {
            short shift = (short) (RSA_BYTE_LEN - produced);
            Util.arrayCopyNonAtomic(
                    scratch, outBufOff, scratch, (short) (outBufOff + shift), produced);
            Util.arrayFillNonAtomic(scratch, outBufOff, shift, (byte) 0);
        }
        Util.arrayCopyNonAtomic(
                scratch, (short) (outBufOff + PADDED_OFFSET), out, outOff, Fp25519.LEN);
        Util.arrayFillNonAtomic(scratch, scOff, SCRATCH_LEN, (byte) 0);
    }

    /**
     * Software fallback: left-to-right square-and-multiply over {@code p − 2}. Constant-time
     * because the exponent is a public constant: 256 squarings × 254 multiplications regardless of
     * the operand value.
     */
    private static void softwareInv(
            byte[] a, short aOff, byte[] out, short outOff, byte[] scratch, short scOff) {
        short prodOff = (short) (scOff + SOFT_PROD_OFF);
        short tmpOff = (short) (scOff + SOFT_TMP_OFF);

        Fp25519.copy(a, aOff, scratch, tmpOff);
        Fp25519.one(out, outOff);

        for (short byteIdx = 0; byteIdx < Fp25519.LEN; byteIdx++) {
            short eByte =
                    (short)
                            (P_MINUS_2_PADDED[(short) (PADDED_OFFSET + byteIdx)]
                                    & BigNat.DIGIT_MASK);
            for (short bit = 7; bit >= 0; bit--) {
                Fp25519.sqr(out, outOff, out, outOff, scratch, prodOff);
                if (((eByte >> bit) & 1) != 0) {
                    Fp25519.mul(out, outOff, scratch, tmpOff, out, outOff, scratch, prodOff);
                }
            }
        }
        Util.arrayFillNonAtomic(scratch, scOff, SCRATCH_LEN, (byte) 0);
    }
}
