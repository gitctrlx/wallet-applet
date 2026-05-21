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
 * BIP-340 Schnorr signing primitive on secp256k1. JavaCard 3.0.5 ships no native BIP-340; only ECDH
 * scalar multiplication is platform-provided ({@code d' · G}, {@code k' · G}). Tagged hashing,
 * parity testing and modular arithmetic are implemented in software on top of {@link
 * MessageDigest#ALG_SHA_256} and {@link Bignat}.
 *
 * <p>Algorithm — <a
 * href="https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#default-signing">BIP-340
 * §3</a> verbatim, with {@code aux_rand} drawn from the JC platform RNG so the signature is
 * randomised:
 *
 * <ol>
 *   <li>{@code d' = bip32.deriveLeafScalar(path)}; BIP-32 already enforces {@code 0 < d' < n}.
 *   <li>{@code P = d' · G}; if {@code y(P)} is odd then {@code d ← n − d'} else {@code d ← d'}.
 *   <li>{@code aux ← RNG(32)}, {@code t ← bytes(d) ⊕ tagged_hash("BIP0340/aux", aux)}.
 *   <li>{@code rand ← tagged_hash("BIP0340/nonce", t ‖ bytes(P) ‖ m)}.
 *   <li>{@code k' ← int(rand) mod n}; if {@code k' == 0} fail with {@link
 *       Constants#SW_INTERNAL_ERROR}.
 *   <li>{@code R = k' · G}; if {@code y(R)} is odd then {@code k ← n − k'} else {@code k ← k'}.
 *   <li>{@code e ← int(tagged_hash("BIP0340/challenge", bytes(R) ‖ bytes(P) ‖ m)) mod n}.
 *   <li>{@code s ← (k + e · d) mod n}; emit {@code bytes(R) ‖ s} (64 bytes total).
 * </ol>
 *
 * <p>{@code bytes(X)} is the big-endian {@code x}-coordinate (SEC 1 §2.3.5 with implicit even
 * {@code y}); the parity flip in step 6 ensures the on-card output always has even-{@code y(R)}.
 * Tagged hashing follows BIP-340 §3.2: {@code SHA256(SHA256(tag) ‖ SHA256(tag) ‖ msg)}; the three
 * {@code SHA256(tag)} values are precomputed as {@link #HASH_OF_TAG_AUX}, {@link
 * #HASH_OF_TAG_NONCE} and {@link #HASH_OF_TAG_CHALLENGE}, saving three SHA-256 invocations per
 * signature compared to evaluating them at runtime (audit S3-08).
 *
 * <p>Every secret intermediate lives in a 354-byte {@code CLEAR_ON_DESELECT} scratch and is wiped
 * by a {@code finally} on every code path so no residue survives the call.
 */
public final class Schnorr {

    /**
     * Pre-computed {@code SHA256("BIP0340/aux")}, big-endian. Pinned here so every Schnorr
     * signature avoids three redundant SHA-256 invocations over the tag strings (audit S3-08). The
     * {@code SchnorrTagHashTest} sanity-check verifies these constants against a runtime SHA-256 of
     * the literal tag bytes so any typo trips on the first build.
     */
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

    /*
     * Scratch layout. Every signature lives entirely in this transient buffer:
     *   D_OFF        [0,32)    d'  (later d after parity flip)
     *   T_OFF        [32,64)   t   (= d ⊕ tagged_hash(aux))
     *   P_OFF        [64,129)  P   (uncompressed: 0x04 ‖ x ‖ y)
     *   R_OFF        [129,194) R   (uncompressed: 0x04 ‖ x ‖ y)
     *   E_OFF        [194,226) e   (challenge mod n)
     *   K_OFF        [226,258) k'  (later k after parity flip)
     *   M_OFF        [258,290) m   (digest copy — input may share buffer with output)
     *   WORK_OFF     [290,354) 64-byte workspace: e·d → k+e·d → (k+e·d) mod n
     *                          Before the multiply-add step, the same 32-byte slot at WORK_OFF
     *                          temporarily holds the BIP-340 aux randomness (consumed by the
     *                          synthetic-nonce hash before WORK is needed by `(k + e·d) mod n`).
     *
     * The previous revision reserved a 32-byte `HASH_TAG_OFF` slot to hold the running
     * SHA-256(tag) digest; that slot is gone since {@link #HASH_OF_TAG_AUX} / {@link
     * #HASH_OF_TAG_NONCE} / {@link #HASH_OF_TAG_CHALLENGE} are now precomputed constants fed
     * directly into {@link MessageDigest#update}, saving 32 bytes of transient RAM and three
     * SHA-256 invocations per signature (audit S3-08).
     */
    private static final short D_OFF = 0;
    private static final short T_OFF = 32;
    private static final short P_OFF = 64;
    private static final short R_OFF = 129;
    private static final short E_OFF = 194;
    private static final short K_OFF = 226;
    private static final short M_OFF = 258;
    private static final short WORK_OFF = 290;
    private static final short SCRATCH_LEN = 354;

    /** Size of a coordinate (x or y), the SHA-256 digest, and a mod-n scalar — all 32 bytes. */
    private static final short COORD_LEN = 32;

    private final Bip32 bip32;
    private final MessageDigest sha256;
    private final RandomData rng;
    private final byte[] scratch;

    /**
     * @param sharedScratch the singleton transient scratch buffer allocated by {@link MeowlApplet}.
     *     Must be at least {@link #SCRATCH_LEN} bytes. The same buffer is reused across signing INS
     *     handlers ({@link EcdsaK1}, {@link Ed25519}, this class) and the handshake scratch in
     *     {@link SecureChannel}, since APDU dispatch is single-threaded and no two of those flows
     *     can run concurrently.
     */
    public Schnorr(Bip32 bip32, byte[] sharedScratch) {
        if ((short) sharedScratch.length < SCRATCH_LEN) {
            ISOException.throwIt(Constants.SW_UNSUPPORTED_FEATURE);
        }
        this.bip32 = bip32;
        try {
            this.sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
            // Per MEAP-6 §Schnorr: aux randomness is drawn from the same RNG class chosen by
            // MasterSeed — ALG_KEYGENERATION first (universal on JC 3.0.4+), ALG_TRNG fallback.
            RandomData candidate;
            try {
                candidate = RandomData.getInstance(RandomData.ALG_KEYGENERATION);
            } catch (Exception e) {
                candidate = RandomData.getInstance(RandomData.ALG_TRNG);
            }
            this.rng = candidate;
        } catch (Exception e) {
            ISOException.throwIt(Constants.SW_UNSUPPORTED_FEATURE);
            throw new RuntimeException(); // unreachable
        }
        this.scratch = sharedScratch;
    }

    /**
     * Signs the 32-byte {@code digest} with the BIP-340 Schnorr scheme under the secp256k1 private
     * key derived at {@code pathBuf[pathOff..pathOff + 4*depth]}, writing {@code bytes(R) ‖ s} (64
     * bytes) to {@code outBuf} at {@code outOff}.
     *
     * @return the number of bytes written, {@link Constants#SIG_LEN_R_S}
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
            // Stage the digest in our own scratch first; the response (anchored at the same
            // OFFSET_CDATA as the inner data) may otherwise overwrite the digest mid-flow.
            Util.arrayCopyNonAtomic(digestBuf, digestOff, scratch, M_OFF, COORD_LEN);

            // === Step 1: derive d' (BIP-32 already enforces 0 < d' < n) ===
            bip32.deriveLeafScalar(pathBuf, pathOff, depth, scratch, D_OFF);

            // === Step 2: compute P = d' · G (uncompressed), then d = (y(P) odd ? n - d' : d') ===
            bip32.scalarMultG(scratch, D_OFF, scratch, P_OFF);
            // y(P) parity: last byte of the uncompressed encoding (0x04 ‖ x[32] ‖ y[32]).
            byte pyLastByte = scratch[(short) (P_OFF + Constants.EC_POINT_UNCOMPRESSED_LEN - 1)];
            if ((pyLastByte & 0x01) != 0) {
                ModN.negateMod(scratch, D_OFF);
            }

            // === Step 3: t = bytes(d) ⊕ tagged_hash("BIP0340/aux", aux) ===
            // aux is staged in WORK_OFF; the slot is reused for the multiply-add later.
            rng.nextBytes(scratch, WORK_OFF, COORD_LEN);
            taggedHashStart(HASH_OF_TAG_AUX);
            sha256.doFinal(scratch, WORK_OFF, COORD_LEN, scratch, T_OFF);
            for (short i = 0; i < COORD_LEN; i++) {
                scratch[(short) (T_OFF + i)] ^= scratch[(short) (D_OFF + i)];
            }

            // === Step 4: rand = tagged_hash("BIP0340/nonce", t ‖ bytes(P) ‖ m) ===
            taggedHashStart(HASH_OF_TAG_NONCE);
            sha256.update(scratch, T_OFF, COORD_LEN);
            sha256.update(scratch, (short) (P_OFF + 1), COORD_LEN); // P.x (skip the 0x04 prefix)
            sha256.doFinal(scratch, M_OFF, COORD_LEN, scratch, K_OFF);

            // === Step 5: k' = int(rand) mod n; reject k' == 0 ===
            // rand < 2^256 and n > 2^255 so a single conditional subtract of n suffices. We run
            // the subtract through a mask-derived predicate so the cost is constant regardless
            // of whether the unreduced value was below or above n (audit S2-03 mitigation).
            short kLessN =
                    Bignat.ctLessThan(scratch, K_OFF, ModN.SECP256K1_N, (short) 0, COORD_LEN);
            Bignat.condSubInPlace(
                    scratch, K_OFF, ModN.SECP256K1_N, (short) 0, COORD_LEN, (short) ~kLessN);
            if (Bignat.ctIsZero(scratch, K_OFF, COORD_LEN) != 0) {
                ISOException.throwIt(Constants.SW_INTERNAL_ERROR);
            }

            // === Step 6: R = k' · G; if y(R) is odd then k = n - k' ===
            bip32.scalarMultG(scratch, K_OFF, scratch, R_OFF);
            byte ryLastByte = scratch[(short) (R_OFF + Constants.EC_POINT_UNCOMPRESSED_LEN - 1)];
            if ((ryLastByte & 0x01) != 0) {
                ModN.negateMod(scratch, K_OFF);
            }

            // === Step 7: e = int(tagged_hash("BIP0340/challenge", R.x ‖ P.x ‖ m)) mod n ===
            taggedHashStart(HASH_OF_TAG_CHALLENGE);
            sha256.update(scratch, (short) (R_OFF + 1), COORD_LEN); // R.x
            sha256.update(scratch, (short) (P_OFF + 1), COORD_LEN); // P.x
            sha256.doFinal(scratch, M_OFF, COORD_LEN, scratch, E_OFF);
            short eLessN =
                    Bignat.ctLessThan(scratch, E_OFF, ModN.SECP256K1_N, (short) 0, COORD_LEN);
            Bignat.condSubInPlace(
                    scratch, E_OFF, ModN.SECP256K1_N, (short) 0, COORD_LEN, (short) ~eLessN);

            // === Step 8: s = (k + e · d) mod n ===
            // 8a) e · d (32×32 → 64) into WORK_OFF.
            Bignat.mult(scratch, E_OFF, scratch, D_OFF, COORD_LEN, scratch, WORK_OFF);
            // 8b) Add k into the lower 32 bytes of WORK; propagate any carry into the upper 32.
            //     The structural bound (k + e·d < n + (n-1)² < 2^512) guarantees the add never
            //     overflows the 64-byte buffer, so the carry-propagation loop is bounded.
            boolean carry =
                    Bignat.add(scratch, (short) (WORK_OFF + COORD_LEN), scratch, K_OFF, COORD_LEN);
            if (carry) {
                short i = (short) (WORK_OFF + COORD_LEN - 1);
                while (i >= WORK_OFF) {
                    short sum = (short) ((scratch[i] & 0xFF) + 1);
                    scratch[i] = (byte) sum;
                    if ((sum & 0x100) == 0) {
                        break;
                    }
                    i--;
                }
            }
            // 8c) Reduce: WORK[0..64] ← WORK[0..64] mod n; result in the trailing 32 bytes.
            Bignat.mod(
                    scratch,
                    WORK_OFF,
                    (short) (COORD_LEN * 2),
                    ModN.SECP256K1_N,
                    (short) 0,
                    COORD_LEN);

            // === Step 9: emit bytes(R) ‖ s into outBuf ===
            Util.arrayCopyNonAtomic(scratch, (short) (R_OFF + 1), outBuf, outOff, COORD_LEN);
            Util.arrayCopyNonAtomic(
                    scratch,
                    (short) (WORK_OFF + COORD_LEN),
                    outBuf,
                    (short) (outOff + COORD_LEN),
                    COORD_LEN);

            return Constants.SIG_LEN_R_S;
        } finally {
            // Wipe every byte of scratch on exit, including the d' / d / k / k' slots and the
            // tagged-hash workspace. CLEAR_ON_DESELECT alone is not sufficient — a subsequent
            // call within the same session would otherwise see stale secrets.
            Util.arrayFillNonAtomic(scratch, (short) 0, SCRATCH_LEN, (byte) 0);
        }
    }

    /**
     * Initialises the SHA-256 instance for a tagged-hash computation: seeds the digest state with
     * {@code SHA256(tag) ‖ SHA256(tag)} by reading the precomputed digest from one of {@link
     * #HASH_OF_TAG_AUX} / {@link #HASH_OF_TAG_NONCE} / {@link #HASH_OF_TAG_CHALLENGE} twice in a
     * row, leaving the caller free to {@link MessageDigest#update update} message segments and
     * finalise with {@link MessageDigest#doFinal doFinal}. The earlier revision called {@code
     * SHA256(tag)} live; the precomputed constants eliminate three SHA-256 invocations per
     * signature (audit S3-08).
     */
    private void taggedHashStart(byte[] tagHash) {
        sha256.reset();
        sha256.update(tagHash, (short) 0, COORD_LEN);
        sha256.update(tagHash, (short) 0, COORD_LEN);
    }
}
