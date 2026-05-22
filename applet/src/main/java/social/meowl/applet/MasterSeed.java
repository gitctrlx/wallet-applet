/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * Persistent master-seed storage and HD derivation root.
 *
 * <p>The raw BIP-39 seed is never retained: on import the card computes the two HMAC-SHA-512 chains
 * once and persists only the resulting master keying material:
 *
 * <pre>
 *   bip32Material  = HMAC-SHA-512("Bitcoin seed", seed)   // 64 bytes, k(32) || c(32)
 *   slip10Material = HMAC-SHA-512("ed25519 seed", seed)   // 64 bytes, k(32) || c(32)
 * </pre>
 *
 * <p>Lifecycle: {@link #importSeed} for a host-supplied seed, {@link #generateSeed} for a
 * card-internal CSPRNG seed (the only path on which raw seed bytes ever leave the card), and {@link
 * #wipe} as the reset-to-factory hook.
 */
public final class MasterSeed {

    /** HMAC label per BIP-32 §"Master key generation". */
    private static final byte[] HMAC_LABEL_BIP32 = {
        (byte) 'B',
        (byte) 'i',
        (byte) 't',
        (byte) 'c',
        (byte) 'o',
        (byte) 'i',
        (byte) 'n',
        (byte) ' ',
        (byte) 's',
        (byte) 'e',
        (byte) 'e',
        (byte) 'd',
    };

    /** HMAC label per SLIP-10 §1. */
    private static final byte[] HMAC_LABEL_SLIP10 = {
        (byte) 'e',
        (byte) 'd',
        (byte) '2',
        (byte) '5',
        (byte) '5',
        (byte) '1',
        (byte) '9',
        (byte) ' ',
        (byte) 's',
        (byte) 'e',
        (byte) 'e',
        (byte) 'd',
    };

    private static final short MASTER_LEN = (short) 64;

    /** Concatenated {@code k_master(32) || c_master(32)} for BIP-32 secp256k1. */
    private final byte[] bip32Material;

    /** Concatenated {@code k_master(32) || c_master(32)} for SLIP-10 Ed25519. */
    private final byte[] slip10Material;

    /** {@code [0] != 0} once a seed has been imported or generated. */
    private final byte[] seededFlag;

    private final HmacSha hmac;

    /**
     * @param sharedHmac512 a shared {@link HmacSha} engine configured for HMAC-SHA-512. The same
     *     instance is reused by {@link Bip32} and {@link Slip10} since on-card APDU handling is
     *     single-threaded — sharing one engine cuts the worst-case transient RAM cost on cards that
     *     lack native HMAC (the software path needs ~192 bytes per engine).
     */
    public MasterSeed(HmacSha sharedHmac512) {
        this.bip32Material = new byte[MASTER_LEN];
        this.slip10Material = new byte[MASTER_LEN];
        this.seededFlag = new byte[1];
        this.hmac = sharedHmac512;
    }

    /** Whether a seed has been imported or generated. */
    public boolean isSeeded() {
        return seededFlag[0] != 0;
    }

    /**
     * Installs a host-supplied seed and computes both master-key chains. <strong>Caller must
     * already hold a {@link JCSystem#beginTransaction() JavaCard transaction}</strong> so the
     * master material commit and the companion lifecycle advance ({@code SETUP_DONE → SEEDED}) land
     * atomically.
     *
     * <p>Per <a href="https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki">BIP-32</a>
     * §"Master key generation", if {@code parse256(I_L) == 0} or {@code parse256(I_L) ≥ n} the
     * resulting BIP-32 master key is invalid and the seed must be rejected. Throws {@link
     * Constants#SW_CONDITIONS_NOT_SATISFIED} so the host can replace the seed (the occurrence
     * probability for a uniform seed is below {@code 2⁻¹²⁷}). SLIP-10 imposes no such check on the
     * Ed25519 master, so the SLIP-10 derivation is accepted unconditionally.
     *
     * @param seedBuf buffer holding the seed
     * @param seedOff offset of the first seed byte
     * @param seedLen seed length in bytes; must lie in {@code [SEED_MIN_LEN, SEED_MAX_LEN]}
     */
    public void importSeed(byte[] seedBuf, short seedOff, short seedLen) {
        // Enforce the "caller must hold a JC transaction" contract at runtime: a half-mutated
        // MasterSeed surviving a torn power-off would brick the card.
        if (JCSystem.getTransactionDepth() == 0) {
            ISOException.throwIt(Constants.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (seededFlag[0] != 0) {
            ISOException.throwIt(Constants.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (seedLen < Constants.SEED_MIN_LEN || seedLen > Constants.SEED_MAX_LEN) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        hmacInto(
                HMAC_LABEL_BIP32,
                (short) HMAC_LABEL_BIP32.length,
                seedBuf,
                seedOff,
                seedLen,
                bip32Material,
                (short) 0);
        requireValidBip32MasterKey();
        hmacInto(
                HMAC_LABEL_SLIP10,
                (short) HMAC_LABEL_SLIP10.length,
                seedBuf,
                seedOff,
                seedLen,
                slip10Material,
                (short) 0);
        seededFlag[0] = 1;
    }

    /**
     * Generates a 64-byte seed using the platform CSPRNG, writes it into {@code outBuf} starting at
     * {@code outOff}, and uses the same bytes to compute both master-key chains. The caller is
     * expected to immediately emit the generated seed as the APDU response and to overwrite the
     * buffer afterwards; this method does not zero the output buffer.
     *
     * @return the number of seed bytes written, i.e. {@link Constants#SEED_GENERATED_LEN}
     */
    public short generateSeed(byte[] outBuf, short outOff) {
        // Same transaction-depth guard as importSeed — the caller's beginTransaction wrap is
        // load-bearing and was previously enforced only by code review.
        if (JCSystem.getTransactionDepth() == 0) {
            ISOException.throwIt(Constants.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (seededFlag[0] != 0) {
            ISOException.throwIt(Constants.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (outBuf == null
                || outOff < 0
                || (short) (outOff + Constants.SEED_GENERATED_LEN) > (short) outBuf.length) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        // Per MEAP-5 §GENERATE_SEED: prefer ALG_KEYGENERATION (universally available on JC 3.0.4+
        // and explicitly designed for cryptographic key material); fall back to ALG_TRNG only on
        // cards that restrict the keygen class.
        javacard.security.RandomData random;
        try {
            random =
                    javacard.security.RandomData.getInstance(
                            javacard.security.RandomData.ALG_KEYGENERATION);
        } catch (Exception e) {
            random =
                    javacard.security.RandomData.getInstance(javacard.security.RandomData.ALG_TRNG);
        }
        // Resample until the BIP-32 master k passes the parse256(I_L) ∈ (0, n) check. The bound
        // is below 2⁻¹²⁷ per draw so the loop terminates in a single iteration with overwhelming
        // probability; the cap (8 attempts) is purely defensive.
        for (short attempt = 0; attempt < (short) 8; attempt++) {
            random.nextBytes(outBuf, outOff, Constants.SEED_GENERATED_LEN);
            hmacInto(
                    HMAC_LABEL_BIP32,
                    (short) HMAC_LABEL_BIP32.length,
                    outBuf,
                    outOff,
                    Constants.SEED_GENERATED_LEN,
                    bip32Material,
                    (short) 0);
            if (ModN.lessThanN(bip32Material, (short) 0)
                    && !ModN.isZero(bip32Material, (short) 0)) {
                hmacInto(
                        HMAC_LABEL_SLIP10,
                        (short) HMAC_LABEL_SLIP10.length,
                        outBuf,
                        outOff,
                        Constants.SEED_GENERATED_LEN,
                        slip10Material,
                        (short) 0);
                seededFlag[0] = 1;
                return Constants.SEED_GENERATED_LEN;
            }
        }
        // Exhausted the resample budget; surface a clean SW so the host knows to retry. Wipe the
        // partially-written master material first so a torn rollback can't leak it.
        Util.arrayFillNonAtomic(bip32Material, (short) 0, MASTER_LEN, (byte) 0);
        Util.arrayFillNonAtomic(outBuf, outOff, Constants.SEED_GENERATED_LEN, (byte) 0);
        ISOException.throwIt(Constants.SW_CONDITIONS_NOT_SATISFIED);
        return 0; // unreachable
    }

    /**
     * Enforces BIP-32 §"Master key generation" validity on the {@code k_master} half of {@link
     * #bip32Material}: {@code 0 < parse256(I_L) < n}. Failure throws {@link
     * Constants#SW_CONDITIONS_NOT_SATISFIED} (occurrence probability is below {@code 2⁻¹²⁷}; the
     * host's expected response is to retry with a fresh seed).
     */
    private void requireValidBip32MasterKey() {
        if (ModN.isZero(bip32Material, (short) 0) || !ModN.lessThanN(bip32Material, (short) 0)) {
            // Wipe the partially-written master before bailing so a future commit (or a
            // diagnostic dump) cannot expose a structurally invalid key.
            Util.arrayFillNonAtomic(bip32Material, (short) 0, MASTER_LEN, (byte) 0);
            ISOException.throwIt(Constants.SW_CONDITIONS_NOT_SATISFIED);
        }
    }

    /**
     * Copies the BIP-32 master keying material — laid out as {@code k_master(32) || c_master(32)},
     * 64 bytes — into {@code dst[dstOff..dstOff+64]}. Callers MUST treat the destination slot as
     * secret and wipe it on the same scratch lifecycle that owns the surrounding HD walk state.
     *
     * <p>Per audit F-29 the previous {@code byte[] bip32Master()} accessor returned a live alias to
     * the persistent master field, which made it possible (in principle, not in any current call
     * site) for a misbehaving caller in the same package to mutate the master in place. This
     * pull-based API removes the alias outright: the master field is now reachable only through a
     * one-shot copy, and the field itself stays {@code private}.
     */
    public void copyBip32MasterTo(byte[] dst, short dstOff) {
        requireSeeded();
        Util.arrayCopyNonAtomic(bip32Material, (short) 0, dst, dstOff, MASTER_LEN);
    }

    /**
     * Copies the SLIP-10 Ed25519 master keying material with the same {@code k || c} layout into
     * {@code dst[dstOff..dstOff+64]}. Same secrecy contract as {@link #copyBip32MasterTo} (audit
     * F-29).
     */
    public void copySlip10MasterTo(byte[] dst, short dstOff) {
        requireSeeded();
        Util.arrayCopyNonAtomic(slip10Material, (short) 0, dst, dstOff, MASTER_LEN);
    }

    /** Reset-to-factory hook: wipe both master fields and the seeded flag. */
    public void wipe() {
        JCSystem.beginTransaction();
        wipeInTx();
        JCSystem.commitTransaction();
    }

    /**
     * Transaction-less wipe variant. Caller MUST hold a {@link JCSystem#beginTransaction()} block;
     * used by {@link MeowlApplet#wipe()} to bundle the master-seed wipe into the single
     * reset-to-factory transaction so the BIP-32 and SLIP-10 master fields, the seeded flag, the
     * PIN/PUK and the lifecycle state all flip atomically (audit F-15).
     */
    public void wipeInTx() {
        Util.arrayFillNonAtomic(bip32Material, (short) 0, MASTER_LEN, (byte) 0);
        Util.arrayFillNonAtomic(slip10Material, (short) 0, MASTER_LEN, (byte) 0);
        seededFlag[0] = 0;
    }

    private void hmacInto(
            byte[] label,
            short labelLen,
            byte[] in,
            short inOff,
            short inLen,
            byte[] out,
            short outOff) {
        hmac.sign(label, (short) 0, labelLen, in, inOff, inLen, out, outOff);
    }

    private void requireSeeded() {
        if (seededFlag[0] == 0) {
            ISOException.throwIt(Constants.SW_LIFECYCLE_INVALID);
        }
    }
}
