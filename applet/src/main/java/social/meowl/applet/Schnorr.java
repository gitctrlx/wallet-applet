/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.MessageDigest;
import javacard.security.RandomData;

/**
 * BIP-340 Schnorr signing primitive on secp256k1.
 *
 * <p>Tagged hashing, parity testing and modular arithmetic run in software on top of {@link
 * MessageDigest#ALG_SHA_256}, {@link BigNat} and {@link Barrett}; the two scalar multiplications
 * are delegated to the hardware EC coprocessor via the shared {@link Bip32#secp256k1()} engine.
 *
 * <p>Algorithm — <a
 * href="https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#default-signing">BIP-340
 * §3</a> verbatim, with {@code aux_rand} drawn from the JC platform RNG:
 *
 * <ol>
 *   <li>{@code d' = bip32.deriveLeafScalar(path)}; BIP-32 enforces {@code 0 < d' < n}.
 *   <li>{@code P = d' · G}; {@code d ← (y(P) odd ? n − d' : d')}.
 *   <li>{@code aux ← RNG(32)}, {@code t ← bytes(d) ⊕ tagged_hash("BIP0340/aux", aux)}.
 *   <li>{@code rand ← tagged_hash("BIP0340/nonce", t ‖ bytes(P) ‖ m)}.
 *   <li>{@code k' ← int(rand) mod n}; if {@code k' == 0} raise {@link Constants#SW_INTERNAL_ERROR}.
 *   <li>{@code R = k' · G}; {@code k ← (y(R) odd ? n − k' : k')}.
 *   <li>{@code e ← int(tagged_hash("BIP0340/challenge", bytes(R) ‖ bytes(P) ‖ m)) mod n}.
 *   <li>{@code s ← (k + e · d) mod n}; emit {@code bytes(R) ‖ s} (64 bytes).
 * </ol>
 *
 * <p>Both parity flips ({@code d} and {@code k}) use {@link BigNat#ctSelectNeg} — the conditional
 * negation is mask-driven so the wall-clock is independent of the y-parity bit. This closes audit
 * finding A-01 (variable-time {@code y(R)} flip leaking the nonce parity bit through a
 * per-signature timing oracle).
 *
 * <p>Tagged hashing follows BIP-340 §3.2: {@code SHA256(SHA256(tag) ‖ SHA256(tag) ‖ msg)}. The
 * three {@code SHA256(tag)} values are precomputed as {@link #HASH_OF_TAG_AUX} / {@link
 * #HASH_OF_TAG_NONCE} / {@link #HASH_OF_TAG_CHALLENGE} so they cost no SHA-256 invocation at sign
 * time.
 *
 * <h2>Scratch layout</h2>
 *
 * <p>All state lives in a 354-byte slice of the shared {@code CLEAR_ON_DESELECT} pool owned by
 * {@link MeowlApplet}, wiped by a {@code finally} on every code path.
 *
 * <pre>
 *   [  0.. 32) D_OFF    — d'  (later d after parity flip)
 *   [ 32.. 64) T_OFF    — t   = d ⊕ tagged_hash(aux)
 *   [ 64..129) P_OFF    — P   uncompressed: 0x04 ‖ x ‖ y
 *   [129..194) R_OFF    — R   uncompressed: 0x04 ‖ x ‖ y
 *   [194..226) E_OFF    — e   challenge mod n
 *   [226..258) K_OFF    — k'  (later k after parity flip)
 *   [258..290) M_OFF    — m   digest copy (input may share buffer with output)
 *   [290..354) WORK_OFF — 64-byte slot: e·d → k+e·d → (k+e·d) mod n. Leading 32 bytes hold the
 *                        BIP-340 aux randomness before the multiply.
 * </pre>
 */
public final class Schnorr {

    /** Pre-computed {@code SHA256("BIP0340/aux")}, big-endian. */
    static final byte[] HASH_OF_TAG_AUX = {
        (byte) 0xF1, (byte) 0xEF, (byte) 0x4E, (byte) 0x5E,
        (byte) 0xC0, (byte) 0x63, (byte) 0xCA, (byte) 0xDA,
        (byte) 0x6D, (byte) 0x94, (byte) 0xCA, (byte) 0xFA,
        (byte) 0x9D, (byte) 0x98, (byte) 0x7E, (byte) 0xA0,
        (byte) 0x69, (byte) 0x26, (byte) 0x58, (byte) 0x39,
        (byte) 0xEC, (byte) 0xC1, (byte) 0x1F, (byte) 0x97,
        (byte) 0x2D, (byte) 0x77, (byte) 0xA5, (byte) 0x2E,
        (byte) 0xD8, (byte) 0xC1, (byte) 0xCC, (byte) 0x90,
    };

    /** Pre-computed {@code SHA256("BIP0340/nonce")}, big-endian. */
    static final byte[] HASH_OF_TAG_NONCE = {
        (byte) 0x07, (byte) 0x49, (byte) 0x77, (byte) 0x34,
        (byte) 0xA7, (byte) 0x9B, (byte) 0xCB, (byte) 0x35,
        (byte) 0x5B, (byte) 0x9B, (byte) 0x8C, (byte) 0x7D,
        (byte) 0x03, (byte) 0x4F, (byte) 0x12, (byte) 0x1C,
        (byte) 0xF4, (byte) 0x34, (byte) 0xD7, (byte) 0x3E,
        (byte) 0xF7, (byte) 0x2D, (byte) 0xDA, (byte) 0x19,
        (byte) 0x87, (byte) 0x00, (byte) 0x61, (byte) 0xFB,
        (byte) 0x52, (byte) 0xBF, (byte) 0xEB, (byte) 0x2F,
    };

    /** Pre-computed {@code SHA256("BIP0340/challenge")}, big-endian. */
    static final byte[] HASH_OF_TAG_CHALLENGE = {
        (byte) 0x7B, (byte) 0xB5, (byte) 0x2D, (byte) 0x7A,
        (byte) 0x9F, (byte) 0xEF, (byte) 0x58, (byte) 0x32,
        (byte) 0x3E, (byte) 0xB1, (byte) 0xBF, (byte) 0x7A,
        (byte) 0x40, (byte) 0x7D, (byte) 0xB3, (byte) 0x82,
        (byte) 0xD2, (byte) 0xF3, (byte) 0xF2, (byte) 0xD8,
        (byte) 0x1B, (byte) 0xB1, (byte) 0x22, (byte) 0x4F,
        (byte) 0x49, (byte) 0xFE, (byte) 0x51, (byte) 0x8F,
        (byte) 0x6D, (byte) 0x48, (byte) 0xD3, (byte) 0x7C,
    };

    private static final short D_OFF = 0;
    private static final short T_OFF = 32;
    private static final short P_OFF = 64;
    private static final short R_OFF = 129;
    private static final short E_OFF = 194;
    private static final short K_OFF = 226;
    private static final short M_OFF = 258;
    private static final short WORK_OFF = 290;
    private static final short SCRATCH_LEN = 354;

    /** Size of an x/y coordinate, the SHA-256 digest, and a mod-n scalar — all 32 bytes. */
    private static final short COORD_LEN = 32;

    private final Bip32 bip32;
    private final Barrett barrettN;
    private final MessageDigest sha256;
    private final RandomData rng;
    private final byte[] scratch;

    /**
     * @param sharedScratch the singleton transient scratch (≥ {@link #SCRATCH_LEN} bytes) allocated
     *     by {@link MeowlApplet}. Reused by every signing INS and the {@link SecureChannel}
     *     handshake since APDU dispatch is single-threaded.
     */
    public Schnorr(Bip32 bip32, byte[] sharedScratch) {
        if ((short) sharedScratch.length < SCRATCH_LEN) {
            ISOException.throwIt(Constants.SW_UNSUPPORTED_FEATURE);
        }
        this.bip32 = bip32;
        this.barrettN = new Barrett(Secp256k1Curve.N, (short) 0, Secp256k1Curve.MU_N, (short) 0);
        try {
            this.sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
            RandomData candidate;
            try {
                candidate = RandomData.getInstance(RandomData.ALG_KEYGENERATION);
            } catch (Exception e) {
                candidate = RandomData.getInstance(RandomData.ALG_TRNG);
            }
            this.rng = candidate;
        } catch (Exception e) {
            throw Constants.fail(Constants.SW_UNSUPPORTED_FEATURE);
        }
        this.scratch = sharedScratch;
    }

    /**
     * Signs the 32-byte {@code digest} under the secp256k1 leaf key derived at {@code
     * pathBuf[pathOff..pathOff + 4·depth]} per BIP-340, writing {@code bytes(R) ‖ s} to {@code
     * outBuf}.
     *
     * @return {@link Constants#SIG_LEN_R_S}
     */
    public short signDigest(
            byte[] pathBuf,
            short pathOff,
            short depth,
            byte[] digestBuf,
            short digestOff,
            byte[] outBuf,
            short outOff) {
        try {
            // Stage the digest in our scratch first; the response (anchored at OFFSET_CDATA)
            // would otherwise overwrite the digest mid-flow.
            Util.arrayCopyNonAtomic(digestBuf, digestOff, scratch, M_OFF, COORD_LEN);

            // 1. Derive d' (BIP-32 enforces 0 < d' < n).
            bip32.deriveLeafScalar(pathBuf, pathOff, depth, scratch, D_OFF);

            // 2. P = d' · G; d = (y(P) odd ? n − d' : d').
            bip32.scalarMultG(scratch, D_OFF, scratch, P_OFF);
            //    y(P) parity is public (P appears in tagged_hash(challenge, …) and is recoverable
            //    from the signature); the mask-driven flip stays here purely for code-uniformity
            //    with the y(R) path below so both call sites are structurally identical.
            byte pyLastByte = scratch[(short) (P_OFF + Constants.EC_POINT_UNCOMPRESSED_LEN - 1)];
            short pParityMask = (short) -((pyLastByte & 0x01));
            BigNat.ctSelectNeg(scratch, D_OFF, Secp256k1Curve.N, (short) 0, COORD_LEN, pParityMask);

            // 3. t = bytes(d) ⊕ tagged_hash("BIP0340/aux", aux).
            //    aux staged at WORK_OFF; the slot is reused for the multiply-add later.
            rng.nextBytes(scratch, WORK_OFF, COORD_LEN);
            taggedHashStart(HASH_OF_TAG_AUX);
            sha256.doFinal(scratch, WORK_OFF, COORD_LEN, scratch, T_OFF);
            for (short i = 0; i < COORD_LEN; i++) {
                scratch[(short) (T_OFF + i)] ^= scratch[(short) (D_OFF + i)];
            }

            // 4. rand = tagged_hash("BIP0340/nonce", t ‖ bytes(P) ‖ m).
            taggedHashStart(HASH_OF_TAG_NONCE);
            sha256.update(scratch, T_OFF, COORD_LEN);
            sha256.update(scratch, (short) (P_OFF + 1), COORD_LEN); // P.x (skip 0x04 prefix)
            sha256.doFinal(scratch, M_OFF, COORD_LEN, scratch, K_OFF);

            // 5. k' = int(rand) mod n; reject k' == 0.
            //    rand < 2²⁵⁶ and n > 2²⁵⁵ so one conditional subtract suffices.
            short kLessN =
                    BigNat.ctLessThan(scratch, K_OFF, Secp256k1Curve.N, (short) 0, COORD_LEN);
            BigNat.ctSelectSub(
                    scratch, K_OFF, Secp256k1Curve.N, (short) 0, COORD_LEN, (short) ~kLessN);
            if (BigNat.ctIsZero(scratch, K_OFF, COORD_LEN) != 0) {
                ISOException.throwIt(Constants.SW_INTERNAL_ERROR);
            }

            // 6. R = k' · G; k = (y(R) odd ? n − k' : k').
            //    The y(R) parity is derived from the ephemeral nonce k' and therefore SECRET.
            //    Mask-driven ctSelectNeg avoids the 1-bit per-signature timing oracle that a
            //    branchful flip would expose.
            bip32.scalarMultG(scratch, K_OFF, scratch, R_OFF);
            byte ryLastByte = scratch[(short) (R_OFF + Constants.EC_POINT_UNCOMPRESSED_LEN - 1)];
            short rParityMask = (short) -((ryLastByte & 0x01));
            BigNat.ctSelectNeg(scratch, K_OFF, Secp256k1Curve.N, (short) 0, COORD_LEN, rParityMask);

            // 7. e = int(tagged_hash("BIP0340/challenge", R.x ‖ P.x ‖ m)) mod n.
            taggedHashStart(HASH_OF_TAG_CHALLENGE);
            sha256.update(scratch, (short) (R_OFF + 1), COORD_LEN); // R.x
            sha256.update(scratch, (short) (P_OFF + 1), COORD_LEN); // P.x
            sha256.doFinal(scratch, M_OFF, COORD_LEN, scratch, E_OFF);
            short eLessN =
                    BigNat.ctLessThan(scratch, E_OFF, Secp256k1Curve.N, (short) 0, COORD_LEN);
            BigNat.ctSelectSub(
                    scratch, E_OFF, Secp256k1Curve.N, (short) 0, COORD_LEN, (short) ~eLessN);

            // 7b. Emit bytes(R) now. R.x is the only thing we still need from R; the upcoming
            //     Barrett scratch aliases the head of R_OFF, so emit-then-clobber is simpler than
            //     carving a non-contiguous Barrett workspace.
            Util.arrayCopyNonAtomic(scratch, (short) (R_OFF + 1), outBuf, outOff, COORD_LEN);

            // 8. s = (k + e · d) mod n.
            // 8a. e · d (32×32 → 64) into WORK_OFF.
            BigNat.multAsymmetric(
                    scratch, E_OFF, COORD_LEN, scratch, D_OFF, COORD_LEN, scratch, WORK_OFF);
            // 8b. Add k (zero-extended to 64 bytes) into WORK[0..64]. ctAddLowerHalf walks every
            //     byte of the upper half unconditionally so the wall-clock is independent of
            //     where the carry chain stops.
            BigNat.ctAddLowerHalf(scratch, WORK_OFF, scratch, K_OFF, COORD_LEN);
            // 8c. Reduce WORK[0..64] mod n into the trailing 32 bytes of WORK with constant-time
            //     Barrett. The unreduced dividend k + e·d is a SECRET intermediate.
            //     The 132-byte Barrett scratch reuses scratch[D_OFF..D_OFF+132]; by this point d,
            //     t, P.x and R.x are no longer needed.
            barrettN.reduce(
                    scratch, WORK_OFF, scratch, D_OFF, scratch, (short) (WORK_OFF + COORD_LEN));

            // 9. Emit s (bytes(R) was emitted at step 7b before Barrett aliased R_OFF).
            Util.arrayCopyNonAtomic(
                    scratch,
                    (short) (WORK_OFF + COORD_LEN),
                    outBuf,
                    (short) (outOff + COORD_LEN),
                    COORD_LEN);

            return Constants.SIG_LEN_R_S;
        } finally {
            Util.arrayFillNonAtomic(scratch, (short) 0, SCRATCH_LEN, (byte) 0);
        }
    }

    /**
     * Initialises the SHA-256 state for a tagged-hash by feeding {@code SHA256(tag)} twice from one
     * of the precomputed constants. Caller continues with {@code update} / {@code doFinal}.
     */
    private void taggedHashStart(byte[] tagHash) {
        sha256.reset();
        sha256.update(tagHash, (short) 0, COORD_LEN);
        sha256.update(tagHash, (short) 0, COORD_LEN);
    }
}
