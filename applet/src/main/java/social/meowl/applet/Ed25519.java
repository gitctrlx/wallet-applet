/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.MessageDigest;

/**
 * Software RFC 8032 Ed25519 signing primitive.
 *
 * <p>JavaCard 3.0.5 ships no native Ed25519, so the entire signing pipeline lives in user code:
 * SHA-512 expansion of the SLIP-10 leaf seed (clamped per RFC 8032 §5.1.5), public-key derivation
 * via {@link Edwards25519#scalarMult} of the clamped scalar against the base point,
 * tagged-domain-separated SHA-512 calls for the deterministic ephemeral scalar {@code r} and the
 * challenge {@code k}, a second base-point scalar multiplication for {@code R = r · B}, a software
 * big-integer multiplication for {@code S = (r + k · s) mod ℓ}, and finally an RFC 8032 §5.1.2
 * little-endian compressed encoding of the signature.
 *
 * <p>Wire input: 32-byte SLIP-10 leaf private key plus the message bytes verbatim. RFC 8032
 * specifies that the message is hashed inside the algorithm, so the host supplies the raw payload
 * (this is the only path that produces a verifier-compatible signature for chains like Solana / Sui
 * / TON / Aptos that wrap the message in chain-specific framing the host already applied; per the
 * hash-only invariant of {@code docs/specs/meap-6.md} the card never parses the message).
 *
 * <p>Wire output: 64 bytes laid out as {@code R(32) ‖ S(32)}, both in RFC 8032 little-endian
 * compressed form.
 *
 * <p>All intermediate state (clamped scalar {@code s}, ephemeral {@code r}, challenge {@code k},
 * computed point coordinates, SHA-512 chunks) lives in a single {@link JCSystem#CLEAR_ON_DESELECT}
 * transient byte array and is wiped by an explicit {@code finally} clause at the end of {@link
 * #sign}; the {@code CLEAR_ON_DESELECT} lifecycle alone is not sufficient because a subsequent call
 * within the same session would otherwise see stale secrets in the slot.
 */
public final class Ed25519 {

    /** Length of the leaf private key (= SLIP-10 leaf {@code k_i}). */
    public static final short PRIVATE_KEY_LEN = (short) 32;

    /** Length of the compressed Ed25519 public key (RFC 8032 §5.1.2 encoded form). */
    public static final short PUBLIC_KEY_LEN = (short) 32;

    /** Bytes per point in {@code (X, Y, Z, T)} extended-coordinate layout. */
    public static final short POINT_LEN = (short) 128;

    /** Length of the encoded signature {@code R ‖ S}. */
    public static final short SIGNATURE_LEN = (short) 64;

    /**
     * Group order {@code ℓ = 2²⁵² + 27742317777372353535851937790883648493} as a 32-byte big-endian
     * constant. Used as the modulus when reducing the SHA-512-derived ephemeral scalar {@code r}
     * and the final {@code S = (r + k · s) mod ℓ}.
     */
    public static final byte[] GROUP_L = {
        (byte) 0x10, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x14, (byte) 0xDE, (byte) 0xF9, (byte) 0xDE,
        (byte) 0xA2, (byte) 0xF7, (byte) 0x9C, (byte) 0xD6,
        (byte) 0x58, (byte) 0x12, (byte) 0x63, (byte) 0x1A,
        (byte) 0x5C, (byte) 0xF5, (byte) 0xD3, (byte) 0xED,
    };

    private static final short SHA512_LEN = (short) 64;

    /*
     * Scratch layout — single transient byte array, all secret material wiped in finally.
     *
     *   [   0..  63] HASH_OUT  — SHA-512 output (h, then r-hash, then k-hash); 64-byte mult product
     *   [  64..  95] S_BE      — clamped private scalar in big-endian
     *   [  96.. 127] A_ENC     — compressed public key (RFC 8032 LE)
     *   [ 128.. 159] R_ENC     — compressed R (RFC 8032 LE)
     *   [ 160.. 191] R_BE      — ephemeral scalar r mod ℓ (BE)
     *   [ 192.. 223] K_BE      — challenge scalar k mod ℓ (BE); later (k · s) mod ℓ
     *   [ 224.. 255] S_OUT_BE  — final S = (r + k · s) mod ℓ (BE)
     *   [ 256.. 383] BASE_PT   — Edwards25519 base point in extended coords
     *   [ 384.. 511] POINT     — A then R, in extended coords
     *   [ 512..1023] WORKSPACE — scalar-mult / encode scratch (max 512 bytes)
     */
    private static final short HASH_OFF = (short) 0;

    private static final short S_BE_OFF = (short) 64;
    private static final short A_ENC_OFF = (short) 96;
    private static final short R_ENC_OFF = (short) 128;
    private static final short R_BE_OFF = (short) 160;
    private static final short K_BE_OFF = (short) 192;
    private static final short S_OUT_BE_OFF = (short) 224;
    private static final short BASE_PT_OFF = (short) 256;
    private static final short POINT_OFF = (short) 384;
    private static final short WORK_OFF = (short) 512;
    private static final short SCRATCH_LEN =
            (short) (WORK_OFF + Edwards25519.SCALAR_MULT_SCRATCH_LEN);

    private final MessageDigest sha512;
    private final byte[] scratch;

    /**
     * @param sharedScratch the singleton transient scratch buffer allocated by {@link MeowlApplet}.
     *     Must be at least {@link #SCRATCH_LEN} bytes. The same buffer is reused across signing INS
     *     handlers ({@link EcdsaK1}, {@link Schnorr}, this class) and the handshake scratch in
     *     {@link SecureChannel}, since APDU dispatch is single-threaded and no two of those flows
     *     can run concurrently. Of all four consumers Ed25519 has the largest scratch requirement
     *     ({@link #SCRATCH_LEN} = 1024 bytes), so the shared buffer is sized to match.
     */
    public Ed25519(byte[] sharedScratch) {
        if ((short) sharedScratch.length < SCRATCH_LEN) {
            ISOException.throwIt(Constants.SW_UNSUPPORTED_FEATURE);
        }
        try {
            this.sha512 = MessageDigest.getInstance(MessageDigest.ALG_SHA_512, false);
        } catch (Exception e) {
            ISOException.throwIt(Constants.SW_UNSUPPORTED_FEATURE);
            throw new RuntimeException(); // unreachable
        }
        this.scratch = sharedScratch;
    }

    /**
     * Derives the compressed Ed25519 public key from the supplied 32-byte leaf private key and
     * writes the 32-byte encoding to {@code outBuf} at {@code outOff}. Returns {@link
     * #PUBLIC_KEY_LEN}.
     */
    public short publicKey(byte[] skBuf, short skOff, byte[] outBuf, short outOff) {
        try {
            computePublicKey(skBuf, skOff);
            Util.arrayCopyNonAtomic(scratch, A_ENC_OFF, outBuf, outOff, PUBLIC_KEY_LEN);
            return PUBLIC_KEY_LEN;
        } finally {
            wipeScratch();
        }
    }

    /**
     * RFC 8032 §5.1.6 sign operation. Produces a 64-byte {@code R ‖ S} signature for the message
     * {@code msgBuf[msgOff..msgOff+msgLen]} under the SLIP-10 leaf private key {@code
     * skBuf[skOff..skOff+32]}. Writes the signature to {@code outBuf} at {@code outOff} and returns
     * {@link #SIGNATURE_LEN}.
     */
    public short sign(
            byte[] skBuf,
            short skOff,
            byte[] msgBuf,
            short msgOff,
            short msgLen,
            byte[] outBuf,
            short outOff) {
        try {
            //  1. h = SHA-512(sk); s ← clamp(h[0..32]) reversed to BE; A = s · B; A_enc =
            // encode(A).
            computePublicKey(skBuf, skOff);

            //  2. r = SHA-512(h[32..64] ‖ M)  (h[32..64] = prefix is still in
            // scratch[HASH_OFF+32]).
            sha512.reset();
            sha512.update(scratch, (short) (HASH_OFF + 32), (short) 32);
            sha512.doFinal(msgBuf, msgOff, msgLen, scratch, HASH_OFF);
            //     Reverse the 64-byte LE digest into BE then reduce mod ℓ.
            reverseBytes(scratch, HASH_OFF, SHA512_LEN);
            Bignat.mod(scratch, HASH_OFF, SHA512_LEN, GROUP_L, (short) 0, (short) 32);
            Util.arrayCopyNonAtomic(
                    scratch, (short) (HASH_OFF + 32), scratch, R_BE_OFF, (short) 32);

            //  3. R = r · B; R_enc = encode(R). The base point at BASE_PT_OFF was set in step 1
            //     and survives untouched: scalarMult never writes through its `in` parameter, and
            //     the SHA-512 / Bignat workspace from step 2 is anchored at HASH_OFF, well clear
            //     of BASE_PT_OFF. The POINT_OFF slot used to hold A is reused for R.
            Edwards25519.scalarMult(
                    scratch, R_BE_OFF, scratch, BASE_PT_OFF, scratch, POINT_OFF, scratch, WORK_OFF);
            Edwards25519.encodePoint(scratch, POINT_OFF, scratch, R_ENC_OFF, scratch, WORK_OFF);

            //  4. k = SHA-512(R_enc ‖ A_enc ‖ M) mod ℓ.
            sha512.reset();
            sha512.update(scratch, R_ENC_OFF, (short) 32);
            sha512.update(scratch, A_ENC_OFF, (short) 32);
            sha512.doFinal(msgBuf, msgOff, msgLen, scratch, HASH_OFF);
            reverseBytes(scratch, HASH_OFF, SHA512_LEN);
            Bignat.mod(scratch, HASH_OFF, SHA512_LEN, GROUP_L, (short) 0, (short) 32);
            Util.arrayCopyNonAtomic(
                    scratch, (short) (HASH_OFF + 32), scratch, K_BE_OFF, (short) 32);

            //  5. S = (r + k · s) mod ℓ.
            //     k_times_s_64 ← k · s (full 64-byte product) in scratch[HASH_OFF..HASH_OFF+64].
            Bignat.mult(scratch, K_BE_OFF, scratch, S_BE_OFF, (short) 32, scratch, HASH_OFF);
            Bignat.mod(scratch, HASH_OFF, SHA512_LEN, GROUP_L, (short) 0, (short) 32);
            //     k·s mod ℓ now lives at scratch[HASH_OFF+32..HASH_OFF+64]. Add r and reduce.
            Util.arrayCopyNonAtomic(scratch, R_BE_OFF, scratch, S_OUT_BE_OFF, (short) 32);
            boolean carry =
                    Bignat.add(scratch, S_OUT_BE_OFF, scratch, (short) (HASH_OFF + 32), (short) 32);
            //     Result is in [0, 2ℓ). Reduce: if carry || result ≥ ℓ, subtract ℓ.
            if (carry || !Bignat.lessThan(scratch, S_OUT_BE_OFF, GROUP_L, (short) 0, (short) 32)) {
                Bignat.sub(scratch, S_OUT_BE_OFF, GROUP_L, (short) 0, (short) 32);
            }

            //  6. Output R_enc ‖ S_LE. R_enc is already LE; reverse S_OUT_BE to LE in the output.
            Util.arrayCopyNonAtomic(scratch, R_ENC_OFF, outBuf, outOff, (short) 32);
            for (short i = 0; i < (short) 32; i++) {
                outBuf[(short) (outOff + 32 + i)] = scratch[(short) (S_OUT_BE_OFF + 31 - i)];
            }
            return SIGNATURE_LEN;
        } finally {
            wipeScratch();
        }
    }

    /**
     * Common path of {@link #publicKey} and {@link #sign} — populates {@code scratch[S_BE_OFF]}
     * with the clamped private scalar (BE), {@code scratch[HASH_OFF+32..HASH_OFF+64]} with the RFC
     * 8032 §5.1.6 prefix (h[32..64], reused in step 4 of the sign flow), and {@code
     * scratch[A_ENC_OFF]} with the compressed public-key encoding. Caller is responsible for the
     * {@link #wipeScratch} cleanup in a {@code finally} clause.
     */
    private void computePublicKey(byte[] skBuf, short skOff) {
        // h = SHA-512(sk), kept in scratch[HASH_OFF..HASH_OFF+64].
        sha512.reset();
        sha512.doFinal(skBuf, skOff, PRIVATE_KEY_LEN, scratch, HASH_OFF);
        // Clamp h[0..32] in place (LE bit positions per RFC 8032 §5.1.5):
        //   s_buf[0]  &= 248
        //   s_buf[31] &= 127
        //   s_buf[31] |= 64
        scratch[HASH_OFF] &= (byte) 248;
        scratch[(short) (HASH_OFF + 31)] &= (byte) 127;
        scratch[(short) (HASH_OFF + 31)] |= (byte) 64;
        // Reverse the clamped 32-byte LE scalar into S_BE.
        for (short i = 0; i < (short) 32; i++) {
            scratch[(short) (S_BE_OFF + i)] = scratch[(short) (HASH_OFF + 31 - i)];
        }
        // A = s · B, then encode A into scratch[A_ENC_OFF].
        Edwards25519.setBase(scratch, BASE_PT_OFF);
        Edwards25519.scalarMult(
                scratch, S_BE_OFF, scratch, BASE_PT_OFF, scratch, POINT_OFF, scratch, WORK_OFF);
        Edwards25519.encodePoint(scratch, POINT_OFF, scratch, A_ENC_OFF, scratch, WORK_OFF);
        // The clamped LE scalar at HASH_OFF[0..32] is no longer needed; the prefix at
        // HASH_OFF[32..64] is intact and will be used by the sign flow's r-hash step.
        Util.arrayFillNonAtomic(scratch, HASH_OFF, (short) 32, (byte) 0);
    }

    /** In-place big-endian / little-endian byte reversal of an {@code [off..off+len)} window. */
    private static void reverseBytes(byte[] buf, short off, short len) {
        short half = (short) (len / 2);
        for (short i = 0; i < half; i++) {
            short lo = (short) (off + i);
            short hi = (short) (off + len - 1 - i);
            byte tmp = buf[lo];
            buf[lo] = buf[hi];
            buf[hi] = tmp;
        }
    }

    private void wipeScratch() {
        Util.arrayFillNonAtomic(scratch, (short) 0, SCRATCH_LEN, (byte) 0);
    }
}
