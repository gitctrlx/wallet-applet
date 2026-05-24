/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.KeyBuilder;
import javacard.security.RSAPrivateKey;
import javacardx.crypto.Cipher;

/**
 * Modular inverse over {@code p = 2²⁵⁵ − 19} via Fermat: {@code a⁻¹ ≡ a^(p − 2) (mod p)}.
 *
 * <p>The platform RSA engine is repurposed as a 256-bit modular-exponentiation primitive: a 512-bit
 * {@link RSAPrivateKey} carries the zero-extended {@code p} as modulus and {@code p − 2} as private
 * exponent, and a single {@link Cipher#ALG_RSA_NOPAD} {@code doFinal} executes the entire Fermat
 * inversion in one hardware operation. JCMathLib's {@code bigNatModInv} measures this at ~58 ms on
 * a JCOP4 P71 J3R200 — the same EC + RSA accelerator family as the target J3R180 ({@code
 * 3rdparty/NXPJ3R180_NFC_1_ALGSUPPORT_*.csv} confirms both {@code ALG_RSA_NOPAD} and {@code
 * TYPE_RSA_PRIVATE LENGTH_RSA_512} are supported).
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
 * <p>The whole slice is wiped before {@link #inv} returns.
 */
public final class Fp25519Inv {

    /** RSA key bit length used to emulate a 256-bit modulus. */
    private static final short RSA_BIT_LEN = (short) 512;

    /** Byte width of the RSA modulus / exponent / operand window. */
    private static final short RSA_BYTE_LEN = (short) 64;

    /** Scratch budget: 2 × 64-byte RSA buffers (input slot + output slot). */
    public static final short SCRATCH_LEN = (short) (2 * RSA_BYTE_LEN);

    private static final short PADDED_OFFSET = (short) (RSA_BYTE_LEN - Fp25519.LEN);

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

    /**
     * Allocates the RSA fixture. The RSA modulus and exponent are re-loaded inside every {@link
     * #inv} call rather than once here, because JCMathLib's JCOP4_P71 profile reports {@code
     * DEFERRED_INITIALIZATION = true} on NXP P71 silicon (J3R180 family): RSA key state set at
     * install time does not survive the first {@code select} and must be rebuilt per call.
     */
    public Fp25519Inv() {
        this.rsaKey =
                (RSAPrivateKey)
                        KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, RSA_BIT_LEN, false);
        this.rsaCipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
    }

    /**
     * {@code out ← a⁻¹ mod p}. Throws {@link Constants#SW_INTERNAL_ERROR} on {@code a == 0}.
     *
     * <p>A single hardware modular exponentiation: {@code a^(p − 2) ≡ a⁻¹ (mod p)}. The engine
     * sometimes strips leading zero bytes from the output; the right-align block below
     * canonicalises the 64-byte slot back to its full width before the 32-byte tail is copied out.
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
            ISOException.throwIt(Constants.SW_INTERNAL_ERROR);
        }
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
}
