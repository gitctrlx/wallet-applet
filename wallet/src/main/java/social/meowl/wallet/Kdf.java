/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.wallet;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.Signature;

/**
 * AES-CMAC–based key-derivation function for the meowl Secure Channel.
 *
 * <p>Two-stage extract-then-expand construction (HKDF-shaped) using J3R180-native primitives:
 *
 * <ul>
 *   <li><b>Extract</b> (SP 800-56C-style): {@code K_extract = SHA-256(salt)[0..16]} when the salt
 *       exceeds 16 bytes; the 16-byte truncation matches the AES-CMAC-128 key width and inherits
 *       SHA-256's whitening over the (mildly biased) ECDH-X coordinate. Then {@code PRK =
 *       AES-CMAC(K_extract, IKM)} — 16 bytes.
 *   <li><b>Expand</b> (HKDF-shaped, NIST SP 800-108 counter-mode equivalent with CMAC PRF): {@code
 *       T(i) = AES-CMAC(PRK, T(i-1) ‖ info ‖ i)} for {@code i = 1, 2, …, ⌈L/16⌉}; {@code OKM = T(1)
 *       ‖ T(2) ‖ … ‖ T(N)}.
 * </ul>
 *
 * <p>Why CMAC instead of HMAC: J3R180 silicon supports {@code Signature.ALG_AES_CMAC_128} natively
 * (~76 µs/call from the JCAlgTest profile in {@code 3rdparty/NXPJ3R180_NFC_1_ALGSUPPORT_*.csv}) but
 * exposes neither {@code Signature.ALG_HMAC_SHA_*} nor {@code TYPE_HMAC*}, so an HMAC-based KDF
 * would have to fall through to a software RFC 2104 implementation. Hardware CMAC is roughly 20×
 * faster than software HMAC and lets the entire SC handshake — derive K_enc/K_mac/IV_base —
 * complete inside one APDU round-trip without dragging in the software HMAC engine.
 *
 * <p>Buffer ownership: every operation writes into caller-supplied buffers; the {@link #prk} and
 * {@link #scratch} slots are {@link JCSystem#CLEAR_ON_DESELECT} so a session deselect wipes the
 * derived key material without an explicit {@link #reset} call.
 *
 * <p>Output blocks are always 16 bytes (the AES-CMAC-128 tag width); a single {@link #expand} call
 * may produce up to {@code 255 × 16 = 4080} bytes per RFC 5869 §2.3.
 */
public final class Kdf {

    /** AES-CMAC-128 output (and PRK) length, in bytes. */
    public static final short BLOCK_LEN = (short) 16;

    /** SP 800-108 §5.1 hard ceiling, mirroring RFC 5869's {@code 255 × HashLen}. */
    private static final short MAX_EXPAND_LEN = (short) (255 * BLOCK_LEN);

    private final Signature cmac;
    private final AESKey cmacKey;
    private final MessageDigest sha256;
    private final byte[] prk;
    private final byte[] scratch;

    /**
     * One-byte transient slot for the expand-phase counter byte. Dedicated so neither the running
     * {@code T(i-1)} state in {@link #scratch} nor the {@code info} buffer is mutated between
     * {@code Signature.update} and {@code Signature.sign}; the underlying {@code Signature.update}
     * may defer ingestion, which would observe a post-mutation byte.
     */
    private final byte[] counterBuf;

    /** Allocates the CMAC engine, the SHA-256 digest, and the per-session transient slots. */
    public Kdf() {
        this.cmac = Signature.getInstance(Signature.ALG_AES_CMAC_128, false);
        this.cmacKey =
                (AESKey)
                        KeyBuilder.buildKey(
                                KeyBuilder.TYPE_AES_TRANSIENT_DESELECT,
                                KeyBuilder.LENGTH_AES_128,
                                false);
        this.sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        this.prk = JCSystem.makeTransientByteArray(BLOCK_LEN, JCSystem.CLEAR_ON_DESELECT);
        this.scratch =
                JCSystem.makeTransientByteArray(
                        MessageDigest.LENGTH_SHA_256, JCSystem.CLEAR_ON_DESELECT);
        this.counterBuf = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
    }

    /**
     * Derives the 16-byte PRK from {@code salt ‖ ikm} and stores it internally for the subsequent
     * {@link #expand} call. Salt-length policy:
     *
     * <ul>
     *   <li>{@code saltLen == 0}: extract key is the 16-byte zero buffer (RFC 5869 §2.2 default)
     *   <li>{@code saltLen ≤ 16}: extract key is the salt zero-padded to 16 bytes
     *   <li>{@code saltLen > 16}: extract key is {@code SHA-256(salt)[0..16]} — the SP 800-56C
     *       single-step compression; 128 bits of pseudo-random extract material is plenty for a
     *       128-bit CMAC PRF
     * </ul>
     */
    public void extract(
            byte[] salt,
            short saltOffset,
            short saltLen,
            byte[] ikm,
            short ikmOffset,
            short ikmLen) {
        if (saltLen < 0 || ikmLen < 0) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        if (saltLen == 0) {
            Util.arrayFillNonAtomic(scratch, (short) 0, BLOCK_LEN, (byte) 0);
        } else if (saltLen <= BLOCK_LEN) {
            Util.arrayCopyNonAtomic(salt, saltOffset, scratch, (short) 0, saltLen);
            short tail = (short) (BLOCK_LEN - saltLen);
            if (tail > 0) {
                Util.arrayFillNonAtomic(scratch, saltLen, tail, (byte) 0);
            }
        } else {
            sha256.reset();
            sha256.doFinal(salt, saltOffset, saltLen, scratch, (short) 0);
            // First 16 bytes of the SHA-256 digest are our 128-bit extract key; the remaining
            // 16 bytes stay parked in scratch and are overwritten / wiped on the next operation.
        }
        cmacKey.setKey(scratch, (short) 0);
        cmac.init(cmacKey, Signature.MODE_SIGN);
        cmac.sign(ikm, ikmOffset, ikmLen, prk, (short) 0);
    }

    /**
     * Writes {@code length} bytes of OKM derived from the previously-extracted PRK. Layout per
     * iteration: {@code T(i) = AES-CMAC(PRK, T(i-1) ‖ info ‖ counter_byte_i)}.
     *
     * @param info may be {@code null} when {@code infoLen == 0} (empty info)
     * @param length requested OKM length; {@code 0 ≤ length ≤ 255 × 16}
     */
    public void expand(
            byte[] info,
            short infoOffset,
            short infoLen,
            byte[] out,
            short outOffset,
            short length) {
        if (length < 0 || length > MAX_EXPAND_LEN) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        if (info == null && infoLen != 0) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        Bounds.requireCapacity(out, outOffset, length);

        cmacKey.setKey(prk, (short) 0);
        short remaining = length;
        short writeOffset = outOffset;
        byte counter = (byte) 0x01;
        boolean firstBlock = true;

        while (remaining > 0) {
            cmac.init(cmacKey, Signature.MODE_SIGN);
            if (!firstBlock) {
                cmac.update(scratch, (short) 0, BLOCK_LEN);
            }
            if (infoLen > 0) {
                cmac.update(info, infoOffset, infoLen);
            }
            counterBuf[0] = counter;
            cmac.sign(counterBuf, (short) 0, (short) 1, scratch, (short) 0);
            short take = remaining < BLOCK_LEN ? remaining : BLOCK_LEN;
            Util.arrayCopyNonAtomic(scratch, (short) 0, out, writeOffset, take);
            writeOffset += take;
            remaining -= take;
            counter++;
            firstBlock = false;
        }
    }

    /** Wipes derived key material. Called by {@link SecureChannel#reset}. */
    public void reset() {
        cmacKey.clearKey();
        Util.arrayFillNonAtomic(prk, (short) 0, BLOCK_LEN, (byte) 0);
        Util.arrayFillNonAtomic(scratch, (short) 0, MessageDigest.LENGTH_SHA_256, (byte) 0);
        counterBuf[0] = 0;
    }
}
