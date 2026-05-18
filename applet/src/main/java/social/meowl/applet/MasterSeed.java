/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.HMACKey;
import javacard.security.KeyBuilder;
import javacard.security.Signature;

/**
 * Persistent master-seed storage and HD derivation root for {@code MeowlApplet}.
 *
 * <h2>What lives on the card</h2>
 *
 * <p>The card never persists the raw BIP-39 seed material after a single import. It computes the
 * two HMAC-SHA-512 chains once and persists only the resulting master keying material:
 *
 * <pre>
 *   bip32Master  = HMAC-SHA-512("Bitcoin seed",  seed)   // 64 bytes
 *   slip10Master = HMAC-SHA-512("ed25519 seed",  seed)   // 64 bytes
 * </pre>
 *
 * <p>Both fields layout {@code k_master(32) || c_master(32)}. The raw seed is overwritten in the
 * APDU buffer by the handler before the response is emitted.
 *
 * <h2>Lifecycle</h2>
 *
 * <ul>
 *   <li>{@link #importSeed(byte[], short, short)} — host-supplied seed; advances to seeded state.
 *   <li>{@link #generateSeed(byte[], short)} — card-internal CSPRNG seed; writes the raw seed into
 *       the caller-supplied buffer (the {@code GENERATE_SEED} APDU then emits it as the response —
 *       the only path on which the raw seed ever leaves the card).
 *   <li>{@link #wipe()} — reset-to-factory hook; clears both master fields and the seeded flag.
 * </ul>
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
    private static final short HASH_LEN = (short) 64;

    /** HMAC-SHA-512 block size (bytes). Used to right-size the HMAC key builder. */
    private static final short HMAC_KEY_BITS = (short) (HASH_LEN * 8);

    /** Concatenated {@code k_master(32) || c_master(32)} for BIP-32 secp256k1. */
    private final byte[] bip32Master;

    /** Concatenated {@code k_master(32) || c_master(32)} for SLIP-10 Ed25519. */
    private final byte[] slip10Master;

    /** {@code [0] != 0} once a seed has been imported or generated. */
    private final byte[] seededFlag;

    private final Signature hmac;
    private final HMACKey labelKey;

    public MasterSeed() {
        this.bip32Master = new byte[MASTER_LEN];
        this.slip10Master = new byte[MASTER_LEN];
        this.seededFlag = new byte[1];

        // HMAC-SHA-512 is mandatory; if the silicon does not advertise it we surface that fact
        // as an applet-private SW (the install path will throw SW_UNSUPPORTED_FEATURE and the
        // host SDK can refuse to use this card).
        try {
            this.hmac = Signature.getInstance(Signature.ALG_HMAC_SHA_512, false);
            this.labelKey =
                    (HMACKey)
                            KeyBuilder.buildKey(
                                    KeyBuilder.TYPE_HMAC_TRANSIENT_DESELECT, HMAC_KEY_BITS, false);
        } catch (Exception e) {
            ISOException.throwIt(Constants.SW_UNSUPPORTED_FEATURE);
            throw new RuntimeException(); // unreachable; satisfies the constructor's flow analysis
        }
    }

    /** Whether a seed has been imported or generated. */
    public boolean isSeeded() {
        return seededFlag[0] != 0;
    }

    /**
     * Installs a host-supplied seed and computes both master-key chains atomically. Caller must
     *
     * @param seedBuf buffer holding the seed
     * @param seedOff offset of the first seed byte
     * @param seedLen seed length in bytes; must lie in [SEED_MIN_LEN, SEED_MAX_LEN]
     */
    public void importSeed(byte[] seedBuf, short seedOff, short seedLen) {
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
                bip32Master,
                (short) 0);
        hmacInto(
                HMAC_LABEL_SLIP10,
                (short) HMAC_LABEL_SLIP10.length,
                seedBuf,
                seedOff,
                seedLen,
                slip10Master,
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
        if (seededFlag[0] != 0) {
            ISOException.throwIt(Constants.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (outBuf == null
                || outOff < 0
                || (short) (outOff + Constants.SEED_GENERATED_LEN) > (short) outBuf.length) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        // Pull randomness into the output buffer. ALG_TRNG is the modern (since JC 3.0.5)
        // strong-entropy class; ALG_KEYGENERATION is the fallback explicitly designed for key
        // material on platforms whose TRNG is restricted.
        javacard.security.RandomData random;
        try {
            random =
                    javacard.security.RandomData.getInstance(
                            javacard.security.RandomData.ALG_KEYGENERATION);
        } catch (Exception e) {
            random =
                    javacard.security.RandomData.getInstance(javacard.security.RandomData.ALG_TRNG);
        }
        random.nextBytes(outBuf, outOff, Constants.SEED_GENERATED_LEN);

        hmacInto(
                HMAC_LABEL_BIP32,
                (short) HMAC_LABEL_BIP32.length,
                outBuf,
                outOff,
                Constants.SEED_GENERATED_LEN,
                bip32Master,
                (short) 0);
        hmacInto(
                HMAC_LABEL_SLIP10,
                (short) HMAC_LABEL_SLIP10.length,
                outBuf,
                outOff,
                Constants.SEED_GENERATED_LEN,
                slip10Master,
                (short) 0);
        seededFlag[0] = 1;
        return Constants.SEED_GENERATED_LEN;
    }

    /**
     * Returns the (read-only) view of the BIP-32 master keying material laid out as {@code
     * k_master(32) || c_master(32)}. The caller MUST NOT mutate the returned array.
     */
    public byte[] bip32Master() {
        requireSeeded();
        return bip32Master;
    }

    /** Returns the SLIP-10 Ed25519 master keying material with the same {@code k || c} layout. */
    public byte[] slip10Master() {
        requireSeeded();
        return slip10Master;
    }

    /** Reset-to-factory hook: wipe both master fields and the seeded flag. */
    public void wipe() {
        JCSystem.beginTransaction();
        Util.arrayFillNonAtomic(bip32Master, (short) 0, MASTER_LEN, (byte) 0);
        Util.arrayFillNonAtomic(slip10Master, (short) 0, MASTER_LEN, (byte) 0);
        seededFlag[0] = 0;
        JCSystem.commitTransaction();
    }

    private void hmacInto(
            byte[] label,
            short labelLen,
            byte[] in,
            short inOff,
            short inLen,
            byte[] out,
            short outOff) {
        labelKey.setKey(label, (short) 0, labelLen);
        hmac.init(labelKey, Signature.MODE_SIGN);
        hmac.sign(in, inOff, inLen, out, outOff);
    }

    private void requireSeeded() {
        if (seededFlag[0] == 0) {
            ISOException.throwIt(Constants.SW_LIFECYCLE_INVALID);
        }
    }
}
