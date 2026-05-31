/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.backup;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.KeyBuilder;
import javacard.security.RandomData;
import javacard.security.Signature;

/**
 * Single-slot vault for a BIP-39 seed (the raw entropy), aligned with the Ledger Recovery Key
 * storage hardening but built on J3R180-native primitives.
 *
 * <h2>Storage</h2>
 *
 * The 16/24/32-byte entropy is held inside a persistent {@link AESKey} object — not a plain {@code
 * byte[]} — so it inherits the secure element's hardware key-storage protection. Shorter entropy is
 * right-aligned in the 32-byte key with the leading bytes zeroed; {@link #seedLen} records the true
 * length.
 *
 * <h2>Integrity</h2>
 *
 * A 16-byte AES-CMAC-128 tag is computed over a fixed domain label concatenated with the length
 * byte, keyed by the seed itself. Recomputing and comparing it (constant-time) before every read
 * detects fault injection or EEPROM corruption that alters either the entropy or its declared
 * length — a non-match raises {@link Constants#SW_SEED_INTEGRITY_FAIL} and never returns suspect
 * bytes.
 *
 * <h2>Presence flag</h2>
 *
 * The {@code present} flag uses two far-apart magic constants rather than {@code 0}/{@code 1} so a
 * single-bit fault cannot flip "absent" into "present".
 *
 * <h2>Wipe</h2>
 *
 * {@link #wipeInTx} overwrites the key with fresh TRNG bytes before clearing it, so no plaintext
 * entropy remnant survives in the key store.
 */
public final class SeedVault {

    /** AES-256 backing store: the entropy is right-aligned into these 32 bytes. */
    private static final short KEY_BYTES = (short) 32;

    /** AES-CMAC-128 tag length. */
    private static final short CMAC_LEN = (short) 16;

    /** Magic value for "a seed is stored" — Hamming-distant from {@link #ABSENT}. */
    private static final short PRESENT = (short) 0x5A3C;

    /** Magic value for "no seed stored". */
    private static final short ABSENT = (short) 0xA5C3;

    /** Domain-separated integrity label: ASCII {@code "meowl-backup-seed-v1"}. */
    private static final byte[] CHECK_LABEL = {
        (byte) 'm',
        (byte) 'e',
        (byte) 'o',
        (byte) 'w',
        (byte) 'l',
        (byte) '-',
        (byte) 'b',
        (byte) 'a',
        (byte) 'c',
        (byte) 'k',
        (byte) 'u',
        (byte) 'p',
        (byte) '-',
        (byte) 's',
        (byte) 'e',
        (byte) 'e',
        (byte) 'd',
        (byte) '-',
        (byte) 'v',
        (byte) '1'
    };

    private final AESKey seedKey;
    private final byte[] seedCheck;
    private final byte[] seedLen;
    private final short[] present;
    private final Signature cmac;
    private final RandomData rng;

    /** Transient working buffer: entropy staging, key read-back, random wipe source. */
    private final byte[] scratch;

    /** Transient buffer for the recomputed integrity tag. */
    private final byte[] macScratch;

    public SeedVault() {
        this.seedKey =
                (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
        this.seedCheck = new byte[CMAC_LEN];
        this.seedLen = new byte[1];
        this.present = new short[1];
        this.present[0] = ABSENT;
        this.cmac = Signature.getInstance(Signature.ALG_AES_CMAC_128, false);
        this.rng = RandomData.getInstance(RandomData.ALG_TRNG);
        this.scratch = JCSystem.makeTransientByteArray(KEY_BYTES, JCSystem.CLEAR_ON_DESELECT);
        this.macScratch = JCSystem.makeTransientByteArray(CMAC_LEN, JCSystem.CLEAR_ON_DESELECT);
    }

    /** Whether a seed is currently stored. */
    public boolean isSeeded() {
        return present[0] == PRESENT;
    }

    /** The stored entropy length in bytes (16/24/32), or {@code 0} when empty. */
    public byte length() {
        return seedLen[0];
    }

    /**
     * Stores {@code len} bytes of BIP-39 entropy ({@code 16/24/32}) into the single slot and binds
     * its integrity tag. Rejects a second store with {@link Constants#SW_SEED_ALREADY_PRESENT}.
     * Caller MUST hold a {@link JCSystem#beginTransaction()} so the key, length, tag and presence
     * flag commit atomically.
     */
    public void storeInTx(byte[] buf, short off, short len) {
        if (JCSystem.getTransactionDepth() == 0) {
            ISOException.throwIt(Constants.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (present[0] == PRESENT) {
            ISOException.throwIt(Constants.SW_SEED_ALREADY_PRESENT);
        }
        if (!isValidEntropyLength(len)) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        // Right-align the entropy in a zero-padded 32-byte block, then load the AES key.
        Util.arrayFillNonAtomic(scratch, (short) 0, KEY_BYTES, (byte) 0);
        Util.arrayCopyNonAtomic(buf, off, scratch, (short) (KEY_BYTES - len), len);
        seedKey.setKey(scratch, (short) 0);
        Util.arrayFillNonAtomic(scratch, (short) 0, KEY_BYTES, (byte) 0);
        seedLen[0] = (byte) len;
        computeTag(seedCheck, (short) 0);
        present[0] = PRESENT;
    }

    /**
     * Verifies integrity, then writes the stored entropy to {@code out} and returns its length. Any
     * integrity mismatch raises {@link Constants#SW_SEED_INTEGRITY_FAIL} without emitting bytes.
     */
    public short restore(byte[] out, short outOff) {
        requireIntegrity();
        short len = (short) (seedLen[0] & 0xFF);
        Bounds.requireCapacity(out, outOff, len);
        seedKey.getKey(scratch, (short) 0);
        Util.arrayCopyNonAtomic(scratch, (short) (KEY_BYTES - len), out, outOff, len);
        Util.arrayFillNonAtomic(scratch, (short) 0, KEY_BYTES, (byte) 0);
        return len;
    }

    /** Recomputes and checks the integrity tag; raises {@link Constants#SW_SEED_INTEGRITY_FAIL}. */
    public void verify() {
        requireIntegrity();
    }

    /**
     * Random-overwrites then clears the seed and resets all gates. Caller MUST hold a {@link
     * JCSystem#beginTransaction()} so the wipe is atomic with the surrounding applet reset.
     */
    public void wipeInTx() {
        if (JCSystem.getTransactionDepth() == 0) {
            ISOException.throwIt(Constants.SW_CONDITIONS_NOT_SATISFIED);
        }
        rng.nextBytes(scratch, (short) 0, KEY_BYTES);
        seedKey.setKey(scratch, (short) 0);
        seedKey.clearKey();
        Util.arrayFillNonAtomic(scratch, (short) 0, KEY_BYTES, (byte) 0);
        Util.arrayFillNonAtomic(seedCheck, (short) 0, CMAC_LEN, (byte) 0);
        seedLen[0] = (byte) 0;
        present[0] = ABSENT;
    }

    private void requireIntegrity() {
        if (present[0] != PRESENT) {
            ISOException.throwIt(Constants.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (!isValidEntropyLength((short) (seedLen[0] & 0xFF))) {
            ISOException.throwIt(Constants.SW_SEED_INTEGRITY_FAIL);
        }
        computeTag(macScratch, (short) 0);
        boolean ok = CtUtil.ctEquals(macScratch, (short) 0, seedCheck, (short) 0, CMAC_LEN);
        Util.arrayFillNonAtomic(macScratch, (short) 0, CMAC_LEN, (byte) 0);
        if (!ok) {
            ISOException.throwIt(Constants.SW_SEED_INTEGRITY_FAIL);
        }
    }

    /** Computes {@code AES-CMAC-128(seed, CHECK_LABEL ‖ seedLen)} into {@code out}. */
    private void computeTag(byte[] out, short outOff) {
        cmac.init(seedKey, Signature.MODE_SIGN);
        cmac.update(CHECK_LABEL, (short) 0, (short) CHECK_LABEL.length);
        cmac.sign(seedLen, (short) 0, (short) 1, out, outOff);
    }

    private static boolean isValidEntropyLength(short len) {
        return len == (short) 16 || len == (short) 24 || len == Constants.ENTROPY_MAX_LEN;
    }
}
