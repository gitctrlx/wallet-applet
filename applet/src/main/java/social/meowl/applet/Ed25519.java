/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.MessageDigest;
import javacard.security.RandomData;

/**
 * Software RFC 8032 Ed25519 signing primitive (JavaCard 3.0.5 ships no native Ed25519). Pipeline:
 * SHA-512 expansion + clamping of the SLIP-10 leaf seed, scalar-mult against the base point for
 * {@code A} and the nonce point {@code R}, two tagged SHA-512 invocations for {@code r} and {@code
 * k}, and the software big-integer reduction {@code S = (r + k · s) mod ℓ}.
 *
 * <p>Wire contract — input {@code [SLIP-10 leaf priv(32), message(*)]}; the algorithm hashes the
 * message internally so the card never parses payloads (MEAP-6 hash-only invariant). Output is
 * {@code R(32) ‖ S(32)} in RFC 8032 §5.1.2 little-endian compressed form. All intermediate state
 * lives in a single {@link JCSystem#CLEAR_ON_DESELECT} scratch, wiped by a {@code finally} on every
 * code path.
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
     * constant. Modulus when reducing the ephemeral scalar {@code r} and the final {@code S}.
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
     *   [ 256.. 287] BLIND_FE  — fresh random field element r ∈ [1, p) for projective blinding
     *   [ 288.. 415] BASE_PT   — Edwards25519 base point in extended coords (re-blinded per call)
     *   [ 416.. 543] POINT     — A then R, in extended coords
     *   [ 544..1055] WORKSPACE — scalar-mult / encode scratch (max 512 bytes)
     */
    private static final short HASH_OFF = (short) 0;

    private static final short S_BE_OFF = (short) 64;
    private static final short A_ENC_OFF = (short) 96;
    private static final short R_ENC_OFF = (short) 128;
    private static final short R_BE_OFF = (short) 160;
    private static final short K_BE_OFF = (short) 192;
    private static final short S_OUT_BE_OFF = (short) 224;
    private static final short BLIND_FE_OFF = (short) 256;
    private static final short BLIND_FE_LEN = (short) 32;
    private static final short BASE_PT_OFF = (short) 288;
    private static final short POINT_OFF = (short) 416;
    private static final short WORK_OFF = (short) 544;
    private static final short SCRATCH_LEN =
            (short) (WORK_OFF + Edwards25519.SCALAR_MULT_SCRATCH_LEN);

    private final MessageDigest sha512;
    private final RandomData rng;
    private final byte[] scratch;

    /**
     * @param sharedScratch singleton transient scratch (≥ {@link #SCRATCH_LEN} = 1056 bytes)
     *     allocated by {@link MeowlApplet}. Ed25519 has the largest scratch requirement of all
     *     consumers so the shared buffer is sized to match.
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
        // MEAP-6: ALG_KEYGENERATION first (universal on JC 3.0.4+), ALG_TRNG fallback.
        RandomData candidate;
        try {
            candidate = RandomData.getInstance(RandomData.ALG_KEYGENERATION);
        } catch (Exception e) {
            candidate = RandomData.getInstance(RandomData.ALG_TRNG);
        }
        this.rng = candidate;
        this.scratch = sharedScratch;
    }

    /**
     * Derives the compressed Ed25519 public key from the 32-byte leaf private key.
     *
     * @return {@link #PUBLIC_KEY_LEN}
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
     * RFC 8032 §5.1.6 sign. Produces the 64-byte {@code R ‖ S} signature of {@code
     * msgBuf[msgOff..msgOff+msgLen]} under the SLIP-10 leaf private key {@code skBuf[skOff..+32]}.
     *
     * @return {@link #SIGNATURE_LEN}
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
            // 1. h = SHA-512(sk); s ← clamp(h[0..32]) reversed to BE; A = s · B; A_enc =
            //    encode(A).
            computePublicKey(skBuf, skOff);

            // 2. r = SHA-512(h[32..64] ‖ M)  (h[32..64] = prefix is still in
            //    scratch[HASH_OFF+32]).
            sha512.reset();
            sha512.update(scratch, (short) (HASH_OFF + 32), (short) 32);
            sha512.doFinal(msgBuf, msgOff, msgLen, scratch, HASH_OFF);
            //    Reverse the 64-byte LE digest into BE then reduce mod ℓ with constant-time
            //    Barrett (audit A-16). The SHA-512 input contains the secret RFC 8032 prefix
            //    h[32..64] derived from the leaf key, so the unreduced 64-byte dividend is
            //    SECRET and the wall-clock of the reduction MUST NOT leak its bit pattern.
            //    The 132-byte Barrett scratch reuses the head of WORK_OFF — scalar-mult won't
            //    run again until step 3 below, so the temporary aliasing is safe.
            reverseBytes(scratch, HASH_OFF, SHA512_LEN);
            BarrettL.reduce(scratch, HASH_OFF, scratch, WORK_OFF, scratch, R_BE_OFF);

            // 3. R = r · B; R_enc = encode(R). Reset the base point and re-blind it so the second
            //    scalar ladder runs on a coordinate trajectory uncorrelated with the first.
            Edwards25519.setBase(scratch, BASE_PT_OFF);
            blindBasePoint();
            Edwards25519.scalarMult(
                    scratch, R_BE_OFF, scratch, BASE_PT_OFF, scratch, POINT_OFF, scratch, WORK_OFF);
            Edwards25519.encodePoint(scratch, POINT_OFF, scratch, R_ENC_OFF, scratch, WORK_OFF);

            // 4. k = SHA-512(R_enc ‖ A_enc ‖ M) mod ℓ.
            //    Although the SHA-512 inputs are all public (R_enc, A_enc, M), Barrett's
            //    constant-time reducer is preferred here too — it keeps the sign path uniform,
            //    avoids a per-call branch on "is this scalar secret-derived", and Bignat.mod
            //    is being retired across the codebase as the variable-time long-division
            //    kernel was a maintenance liability (audit A-16). The WORK_OFF scratch is free
            //    again now that scalarMult / encodePoint completed in step 3.
            sha512.reset();
            sha512.update(scratch, R_ENC_OFF, (short) 32);
            sha512.update(scratch, A_ENC_OFF, (short) 32);
            sha512.doFinal(msgBuf, msgOff, msgLen, scratch, HASH_OFF);
            reverseBytes(scratch, HASH_OFF, SHA512_LEN);
            BarrettL.reduce(scratch, HASH_OFF, scratch, WORK_OFF, scratch, K_BE_OFF);

            // 5. S = (r + k · s) mod ℓ.
            //    k_times_s_64 ← k · s (full 64-byte product) in scratch[HASH_OFF..HASH_OFF+64];
            //    the product is a SECRET intermediate (k mixes with the SLIP-10-derived scalar
            //    s), so the reduction MUST be constant-time — the original Bignat.mod path
            //    leaked the full secret S bit-by-bit through the long-division loop iteration
            //    count. BarrettL.reduce writes the 32-byte residue directly into
            //    scratch[HASH_OFF+32..HASH_OFF+64], matching the slot the add step below reads.
            Bignat.mult(scratch, K_BE_OFF, scratch, S_BE_OFF, (short) 32, scratch, HASH_OFF);
            BarrettL.reduce(
                    scratch, HASH_OFF, scratch, WORK_OFF, scratch, (short) (HASH_OFF + 32));
            //    k·s mod ℓ now lives at scratch[HASH_OFF+32..HASH_OFF+64]. Add r and reduce.
            Util.arrayCopyNonAtomic(scratch, R_BE_OFF, scratch, S_OUT_BE_OFF, (short) 32);
            boolean carry =
                    Bignat.add(scratch, S_OUT_BE_OFF, scratch, (short) (HASH_OFF + 32), (short) 32);
            //    Result is in [0, 2ℓ). Reduce: subtract ℓ iff (carry == 1) OR (out >= ℓ). Branch-
            //    free so the timing does not depend on the secret-derived intermediate.
            short carryMask = (short) (carry ? -1 : 0);
            short lessMask =
                    Bignat.ctLessThan(scratch, S_OUT_BE_OFF, GROUP_L, (short) 0, (short) 32);
            short reduceMask = (short) (carryMask | ~lessMask);
            Bignat.condSubInPlace(
                    scratch, S_OUT_BE_OFF, GROUP_L, (short) 0, (short) 32, reduceMask);

            // 6. Output R_enc ‖ S_LE. R_enc is already LE; reverse S_OUT_BE to LE in the output.
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
     * Shared path for {@link #publicKey} and {@link #sign} — populates {@code scratch[S_BE_OFF]}
     * with the clamped private scalar (BE), {@code scratch[HASH_OFF+32..+64]} with the RFC 8032
     * prefix (reused by the sign r-hash step), and {@code scratch[A_ENC_OFF]} with the compressed
     * pubkey. Caller is responsible for the {@link #wipeScratch} finally clause.
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
        // A = s · B, then encode A into scratch[A_ENC_OFF]. The base point is freshly randomised
        // in projective coordinates before every scalarMult call so the variable-time Bignat.mod
        // kernel sees a different bit pattern per ladder iteration (Coron CHES 1999 §3.1).
        Edwards25519.setBase(scratch, BASE_PT_OFF);
        blindBasePoint();
        Edwards25519.scalarMult(
                scratch, S_BE_OFF, scratch, BASE_PT_OFF, scratch, POINT_OFF, scratch, WORK_OFF);
        Edwards25519.encodePoint(scratch, POINT_OFF, scratch, A_ENC_OFF, scratch, WORK_OFF);
        // The clamped LE scalar at HASH_OFF[0..32] is no longer needed; the prefix at
        // HASH_OFF[32..64] is intact and will be used by the sign flow's r-hash step.
        Util.arrayFillNonAtomic(scratch, HASH_OFF, (short) 32, (byte) 0);
    }

    /**
     * Samples a non-zero field element {@code r ∈ [1, p)} into {@code scratch[BLIND_FE_OFF]} and
     * applies the projective randomisation {@code (X, Y, Z, T) ↦ (rX, rY, rZ, rT)} to the base
     * point at {@code scratch[BASE_PT_OFF]}. Caller MUST have populated {@code BASE_PT} via {@link
     * Edwards25519#setBase} first.
     *
     * <p>The blind is drawn by clearing the top bit (so {@code r < 2²⁵⁵}, below {@code p = 2²⁵⁵ −
     * 19} with probability {@code 1 − 2⁻²⁵⁰}) and re-rolling on the {@code r ≥ p} and {@code r ==
     * 0} corner cases. Rejection probability per draw is {@code ≈ 20/2²⁵⁵}.
     */
    private void blindBasePoint() {
        while (true) {
            rng.nextBytes(scratch, BLIND_FE_OFF, BLIND_FE_LEN);
            scratch[BLIND_FE_OFF] &= (byte) 0x7F;
            if (Bignat.ctLessThan(
                            scratch, BLIND_FE_OFF, Field25519.FIELD_P, (short) 0, BLIND_FE_LEN)
                    == 0) {
                continue;
            }
            if (Bignat.ctIsZero(scratch, BLIND_FE_OFF, BLIND_FE_LEN) != 0) {
                continue;
            }
            break;
        }
        Edwards25519.randomizeProjective(
                scratch, BASE_PT_OFF, scratch, BLIND_FE_OFF, scratch, WORK_OFF);
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
