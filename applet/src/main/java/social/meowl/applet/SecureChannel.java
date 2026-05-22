/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

/**
 * Implements the meowl Secure Channel as specified in {@code docs/specs/meap-2.md}.
 *
 * <h2>Handshake (INS 0x10)</h2>
 *
 * <pre>
 *   Host  → Card : client_eph_pub_uncompressed (65 bytes, secp256k1)
 *   Card        : 1. eph_card = genKeyPair(secp256k1)      (transient)
 *                 2. shared    = ECDH_xy(eph_card_priv, client_eph_pub)
 *                 3. PRK       = HKDF-Extract(salt=client_x ‖ card_x, ikm=shared_x)
 *                 4. okm       = HKDF-Expand(PRK, info="meowl-sc-v1", L=80)
 *                                K_enc(32) ‖ K_mac(32) ‖ IV_base(16)
 *                 5. sig       = ECDSA-SHA256(authentikey_priv,
 *                                             eph_card_pub ‖ client_eph_pub)
 *   Card  → Host : eph_card_pub_uncompressed (65) ‖ sigLen (2 BE) ‖ sig (DER, variable)
 * </pre>
 *
 * <h2>Inbound envelope (INS 0x11)</h2>
 *
 * <pre>
 *   APDU = [CLA INS P1 P2 LC]  IV(16)  ciphertext(N×16)  MAC(16)
 *     MAC = HMAC-SHA-256(K_mac, [CLA INS P1 P2 LC] ‖ IV ‖ ciphertext)[0..16]
 *   The IV must strictly exceed the previously accepted IV (replay defense).
 *   plaintext = AES-256-CBC-decrypt(K_enc, IV, ciphertext) with PKCS#5 padding.
 * </pre>
 *
 * <h2>Outbound envelope</h2>
 *
 * <pre>
 *   response = IV(16) ‖ ciphertext(N×16) ‖ MAC(16)
 *     MAC = HMAC-SHA-256(K_mac, 0xFF ‖ IV ‖ ciphertext)[0..16]
 *     IV  = IV_base XOR monotonic_counter (16 bytes)
 * </pre>
 *
 * <p>The handshake stages its inputs in a dedicated transient scratch buffer ({@link #hsScratch})
 * rather than in the APDU buffer, because the working set during ECDH + HKDF + ECDSA-sign exceeds
 * the 261-byte short APDU buffer typical of contemporary silicon.
 *
 * <p>All session keys, IVs, replay counters and the open-flag live in {@link
 * JCSystem#CLEAR_ON_DESELECT} transient memory — a deselect tears the session down automatically.
 * The explicit {@link #reset()} called from {@link MeowlApplet#select} acts as a belt-and-braces.
 */
public final class SecureChannel {

    /** Required size of the client ephemeral public key (uncompressed SEC1). */
    private static final short CLIENT_EPH_PUB_LEN = Constants.EC_POINT_UNCOMPRESSED_LEN;

    /** {@code K_enc ‖ K_mac ‖ IV_base} layout produced by HKDF-Expand. */
    private static final short OKM_LEN =
            (short) (Constants.SC_KEY_LEN + Constants.SC_KEY_LEN + Constants.SC_BLOCK_LEN);

    /** Offset of {@code IV_base} inside {@link #okm}. */
    private static final short OKM_IV_OFFSET =
            (short) (Constants.SC_KEY_LEN + Constants.SC_KEY_LEN);

    /** Handshake scratch layout (all sizes in bytes). */
    private static final short HS_CLIENT_PUB = (short) 0; // 65

    private static final short HS_CARD_PUB =
            (short) (HS_CLIENT_PUB + CLIENT_EPH_PUB_LEN); // 65 → ends 130
    private static final short HS_SHARED =
            (short) (HS_CARD_PUB + CLIENT_EPH_PUB_LEN); // 65 → ends 195
    private static final short HS_SALT = (short) (HS_SHARED + CLIENT_EPH_PUB_LEN); // 64 → ends 259
    private static final short HS_SCRATCH_LEN = (short) (HS_SALT + (Constants.EC_SCALAR_LEN * 2));

    /** Application-binding label for HKDF-Expand. */
    private static final byte[] HKDF_INFO = {
        (byte) 'm',
        (byte) 'e',
        (byte) 'o',
        (byte) 'w',
        (byte) 'l',
        (byte) '-',
        (byte) 's',
        (byte) 'c',
        (byte) '-',
        (byte) 'v',
        (byte) '1',
    };

    /** Single-byte response-direction header fed to the outbound MAC. */
    private static final byte[] RESP_HEADER = {(byte) 0xFF};

    private final Authentikey authentikey;
    private final Hkdf hkdf;

    private final KeyPair ephKeypair;
    private final KeyAgreement ecdh;
    private final AESKey encKey;
    private final HmacSha hmac;

    /**
     * Session MAC key {@code K_mac}. Lives in {@link JCSystem#CLEAR_ON_DESELECT} transient memory;
     * written by {@link #initHandshake} from the HKDF output and consumed by every {@link #unwrap}
     * / {@link #wrap} via {@link HmacSha#init}. Using a plain byte array (rather than {@code
     * HMACKey}) lets the same code path work on cards that omit {@code TYPE_HMAC*} from their key
     * builder catalogue (notably J3R180).
     */
    private final byte[] macKey;

    private final Cipher aesCbc;
    private final Signature ecdsa;

    /** {@code K_enc ‖ K_mac ‖ IV_base} scratch produced by HKDF-Expand. */
    private final byte[] okm;

    /** Last accepted inbound IV. Strictly-increasing IVs defeat replay. */
    private final byte[] lastInboundIv;

    /** Monotonic counter feeding the next outbound IV. */
    private final byte[] outboundCounter;

    /** Scratch buffer for HMAC-SHA-256 full-length output (32 bytes). */
    private final byte[] macScratch;

    /** Handshake working scratch (sized for HKDF salt + shared + both pubkeys). */
    private final byte[] hsScratch;

    /** Single-byte open flag (transient). */
    private final byte[] openFlag;

    /**
     * @param sharedHmac256 shared HMAC-SHA-256 engine reused by HKDF and the envelope MAC; safe to
     *     share because APDU dispatch is single-threaded.
     * @param sharedScratch singleton transient buffer (allocated by {@link MeowlApplet}) of at
     *     least {@link #HS_SCRATCH_LEN} bytes, repurposed as handshake scratch and — since the
     *     consumers never overlap on a single-threaded dispatcher — reused by {@link EcdsaK1},
     *     {@link Schnorr} and {@link Ed25519}.
     */
    public SecureChannel(Authentikey authentikey, HmacSha sharedHmac256, byte[] sharedScratch) {
        if ((short) sharedScratch.length < HS_SCRATCH_LEN) {
            ISOException.throwIt(Constants.SW_UNSUPPORTED_FEATURE);
        }
        this.authentikey = authentikey;
        this.hkdf = new Hkdf(sharedHmac256);
        this.hmac = sharedHmac256;

        this.ephKeypair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
        Secp256k1.setCurveParameters((ECPrivateKey) ephKeypair.getPrivate());
        Secp256k1.setCurveParameters((ECPublicKey) ephKeypair.getPublic());

        this.ecdh = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY, false);
        this.aesCbc = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        this.ecdsa = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);

        // Every session-scoped buffer lives in CLEAR_ON_DESELECT memory — the canonical lifecycle
        // for SCP-style session state, and a hard requirement on cards whose install-time
        // CLEAR_ON_RESET pool is too small to host this many parallel allocations (J3R180).
        this.encKey =
                (AESKey)
                        KeyBuilder.buildKey(
                                KeyBuilder.TYPE_AES_TRANSIENT_DESELECT,
                                KeyBuilder.LENGTH_AES_256,
                                false);
        this.macKey =
                JCSystem.makeTransientByteArray(Constants.SC_KEY_LEN, JCSystem.CLEAR_ON_DESELECT);

        this.okm = JCSystem.makeTransientByteArray(OKM_LEN, JCSystem.CLEAR_ON_DESELECT);
        this.lastInboundIv =
                JCSystem.makeTransientByteArray(Constants.SC_BLOCK_LEN, JCSystem.CLEAR_ON_DESELECT);
        this.outboundCounter =
                JCSystem.makeTransientByteArray(Constants.SC_BLOCK_LEN, JCSystem.CLEAR_ON_DESELECT);
        this.macScratch =
                JCSystem.makeTransientByteArray(Hkdf.HASH_LEN, JCSystem.CLEAR_ON_DESELECT);
        this.hsScratch = sharedScratch;
        this.openFlag = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
    }

    /** Whether a Secure Channel session is currently open. */
    public boolean isOpen() {
        return openFlag[0] != 0;
    }

    /** Tears down the session, clearing all derived keys and counters. */
    public void reset() {
        encKey.clearKey();
        Util.arrayFillNonAtomic(macKey, (short) 0, Constants.SC_KEY_LEN, (byte) 0);
        hmac.reset();
        hkdf.reset();
        Util.arrayFillNonAtomic(okm, (short) 0, OKM_LEN, (byte) 0);
        Util.arrayFillNonAtomic(lastInboundIv, (short) 0, Constants.SC_BLOCK_LEN, (byte) 0);
        Util.arrayFillNonAtomic(outboundCounter, (short) 0, Constants.SC_BLOCK_LEN, (byte) 0);
        Util.arrayFillNonAtomic(macScratch, (short) 0, Hkdf.HASH_LEN, (byte) 0);
        Util.arrayFillNonAtomic(hsScratch, (short) 0, HS_SCRATCH_LEN, (byte) 0);
        openFlag[0] = 0;
    }

    /**
     * Handles {@code INS_INIT_SECURE_CHANNEL}. Reads the client ephemeral pubkey from the APDU data
     * field, generates a fresh card ephemeral keypair, derives session keys, signs the
     * concatenation of both ephemeral pubkeys with the long-lived {@code authentikey}, and writes
     * the response back into the APDU buffer starting at offset 0.
     *
     * @return the number of bytes written into {@code apduBuffer} starting at offset 0
     */
    public short initHandshake(byte[] apduBuffer, short inDataOffset, short inDataLen) {
        if (inDataLen != CLIENT_EPH_PUB_LEN) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        // Per MEAP-2: a non-0x04 prefix is a crypto failure (6FB2), not a length error (6700).
        if (apduBuffer[inDataOffset] != (byte) 0x04) {
            ISOException.throwIt(Constants.SW_SECURE_CHANNEL_FAILED);
        }

        // Stage every handshake field in hsScratch; the APDU buffer is reserved for the response.
        Util.arrayCopyNonAtomic(
                apduBuffer, inDataOffset, hsScratch, HS_CLIENT_PUB, CLIENT_EPH_PUB_LEN);

        ephKeypair.genKeyPair();
        ECPublicKey cardEphPub = (ECPublicKey) ephKeypair.getPublic();
        short cardPubLen = cardEphPub.getW(hsScratch, HS_CARD_PUB);
        if (cardPubLen != CLIENT_EPH_PUB_LEN || hsScratch[HS_CARD_PUB] != (byte) 0x04) {
            ISOException.throwIt(Constants.SW_SECURE_CHANNEL_FAILED);
        }

        ecdh.init((ECPrivateKey) ephKeypair.getPrivate());
        short sharedLen;
        try {
            sharedLen =
                    ecdh.generateSecret(
                            hsScratch, HS_CLIENT_PUB, CLIENT_EPH_PUB_LEN, hsScratch, HS_SHARED);
        } catch (Exception e) {
            ISOException.throwIt(Constants.SW_SECURE_CHANNEL_FAILED);
            return 0;
        }
        if (sharedLen != Constants.EC_POINT_UNCOMPRESSED_LEN
                || hsScratch[HS_SHARED] != (byte) 0x04) {
            ISOException.throwIt(Constants.SW_SECURE_CHANNEL_FAILED);
        }

        // Compose HKDF salt = client_x ‖ card_x.
        Util.arrayCopyNonAtomic(
                hsScratch,
                (short) (HS_CLIENT_PUB + 1),
                hsScratch,
                HS_SALT,
                Constants.EC_SCALAR_LEN);
        Util.arrayCopyNonAtomic(
                hsScratch,
                (short) (HS_CARD_PUB + 1),
                hsScratch,
                (short) (HS_SALT + Constants.EC_SCALAR_LEN),
                Constants.EC_SCALAR_LEN);

        hkdf.extract(
                hsScratch,
                HS_SALT,
                (short) (Constants.EC_SCALAR_LEN * 2),
                hsScratch,
                (short) (HS_SHARED + 1),
                Constants.EC_SCALAR_LEN);
        hkdf.expand(HKDF_INFO, (short) 0, (short) HKDF_INFO.length, okm, (short) 0, OKM_LEN);
        encKey.setKey(okm, (short) 0);
        // K_mac lives in transient byte storage so the same code path works on cards without
        // TYPE_HMAC* in their key builder catalogue (J3R180).
        Util.arrayCopyNonAtomic(okm, Constants.SC_KEY_LEN, macKey, (short) 0, Constants.SC_KEY_LEN);

        Util.arrayFillNonAtomic(lastInboundIv, (short) 0, Constants.SC_BLOCK_LEN, (byte) 0);
        Util.arrayFillNonAtomic(outboundCounter, (short) 0, Constants.SC_BLOCK_LEN, (byte) 0);
        openFlag[0] = (byte) 1;

        // Sign (card_eph_pub ‖ client_eph_pub) with the authentikey. The two pubkeys live in
        // separate non-adjacent regions of hsScratch, so we feed them via Signature.update +
        // Signature.sign rather than copying them contiguously.
        ecdsa.init(authentikey.privateKey(), Signature.MODE_SIGN);
        ecdsa.update(hsScratch, HS_CARD_PUB, CLIENT_EPH_PUB_LEN);
        // sign() output goes into the APDU buffer at the final response offset (cardPub + 2-byte
        // length field), so we don't need an intermediate copy.
        short sigOffset = (short) (CLIENT_EPH_PUB_LEN + 2);
        short sigLen =
                ecdsa.sign(hsScratch, HS_CLIENT_PUB, CLIENT_EPH_PUB_LEN, apduBuffer, sigOffset);

        // Final outbound layout: card_pub(65) ‖ sigLen(2) ‖ sig(DER).
        Util.arrayCopyNonAtomic(hsScratch, HS_CARD_PUB, apduBuffer, (short) 0, CLIENT_EPH_PUB_LEN);
        Util.setShort(apduBuffer, CLIENT_EPH_PUB_LEN, sigLen);

        // Wipe the scratch material we no longer need.
        Util.arrayFillNonAtomic(hsScratch, (short) 0, HS_SCRATCH_LEN, (byte) 0);

        return (short) (sigOffset + sigLen);
    }

    /**
     * Decrypts and authenticates an envelope encoded as {@code IV ‖ ciphertext ‖ MAC} carried in
     * the outer APDU data field. On success, the plaintext is written into {@code apduBuffer}
     * starting at {@link ISO7816#OFFSET_CDATA} and the method returns its length.
     *
     * <p>Any cryptographic failure invalidates the session — the host must re-handshake.
     */
    public short unwrap(byte[] apduBuffer, short outerDataOffset, short outerDataLen) {
        if (!isOpen()) {
            ISOException.throwIt(Constants.SW_SECURE_CHANNEL_REQUIRED);
        }
        short minLen =
                (short) (Constants.SC_BLOCK_LEN + Constants.SC_BLOCK_LEN + Constants.SC_MAC_LEN);
        if (outerDataLen < minLen) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        short ctLen = (short) (outerDataLen - Constants.SC_BLOCK_LEN - Constants.SC_MAC_LEN);
        if ((short) (ctLen % Constants.SC_BLOCK_LEN) != 0) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }
        short ivOffset = outerDataOffset;
        short ctOffset = (short) (ivOffset + Constants.SC_BLOCK_LEN);
        short macOffset = (short) (ctOffset + ctLen);

        // Replay defense before MAC verification: a non-monotonic IV is a hard reject without
        // burning an HMAC computation, and IV bytes are public so a non-constant-time compare is
        // fine here.
        if (compare16(apduBuffer, ivOffset, lastInboundIv, (short) 0) <= 0) {
            reset();
            ISOException.throwIt(Constants.SW_SECURE_CHANNEL_FAILED);
        }

        // MAC = HMAC-SHA-256(K_mac, outer_header ‖ IV ‖ ciphertext)[0..16]. ConstantTime.equals
        // is mandatory: Util.arrayCompare is left-to-right ternary, leaking mismatch position.
        hmac.init(macKey, (short) 0, Constants.SC_KEY_LEN);
        hmac.update(apduBuffer, (short) 0, (short) 5);
        hmac.doFinal(
                apduBuffer,
                ivOffset,
                (short) (Constants.SC_BLOCK_LEN + ctLen),
                macScratch,
                (short) 0);
        if (!ConstantTime.equals(
                macScratch, (short) 0, apduBuffer, macOffset, Constants.SC_MAC_LEN)) {
            reset();
            ISOException.throwIt(Constants.SW_SECURE_CHANNEL_FAILED);
        }
        Util.arrayCopyNonAtomic(
                apduBuffer, ivOffset, lastInboundIv, (short) 0, Constants.SC_BLOCK_LEN);

        // AES-CBC NOPAD; PKCS#5 padding is stripped manually below.
        aesCbc.init(encKey, Cipher.MODE_DECRYPT, apduBuffer, ivOffset, Constants.SC_BLOCK_LEN);
        short paddedLen =
                aesCbc.doFinal(apduBuffer, ctOffset, ctLen, apduBuffer, ISO7816.OFFSET_CDATA);
        return stripPkcs5(apduBuffer, ISO7816.OFFSET_CDATA, paddedLen);
    }

    /**
     * Wraps {@code plaintextLen} bytes of response data placed at {@code apduBuffer[plainOffset ..
     * plainOffset+plaintextLen]} into an outbound envelope {@code IV ‖ ciphertext ‖ MAC} written to
     * offset 0. Returns the total envelope length.
     */
    public short wrap(byte[] apduBuffer, short plainOffset, short plaintextLen) {
        if (!isOpen()) {
            ISOException.throwIt(Constants.SW_SECURE_CHANNEL_REQUIRED);
        }
        short padded = pkcs5PaddedLength(plaintextLen);
        short total = (short) (Constants.SC_BLOCK_LEN + padded + Constants.SC_MAC_LEN);
        if (total > (short) apduBuffer.length) {
            ISOException.throwIt(Constants.SW_WRONG_LENGTH);
        }

        // Move plaintext to its final pre-encryption position (after the IV slot) and pad.
        Util.arrayCopyNonAtomic(
                apduBuffer, plainOffset, apduBuffer, Constants.SC_BLOCK_LEN, plaintextLen);
        applyPkcs5(apduBuffer, Constants.SC_BLOCK_LEN, plaintextLen, padded);

        // IV = IV_base XOR (counter++).
        incrementCounter();
        for (short i = 0; i < Constants.SC_BLOCK_LEN; i++) {
            apduBuffer[i] = (byte) (okm[(short) (OKM_IV_OFFSET + i)] ^ outboundCounter[i]);
        }

        aesCbc.init(encKey, Cipher.MODE_ENCRYPT, apduBuffer, (short) 0, Constants.SC_BLOCK_LEN);
        short ctLen =
                aesCbc.doFinal(
                        apduBuffer,
                        Constants.SC_BLOCK_LEN,
                        padded,
                        apduBuffer,
                        Constants.SC_BLOCK_LEN);

        short macOffset = (short) (Constants.SC_BLOCK_LEN + ctLen);
        hmac.init(macKey, (short) 0, Constants.SC_KEY_LEN);
        hmac.update(RESP_HEADER, (short) 0, (short) RESP_HEADER.length);
        hmac.doFinal(
                apduBuffer,
                (short) 0,
                (short) (Constants.SC_BLOCK_LEN + ctLen),
                macScratch,
                (short) 0);
        Util.arrayCopyNonAtomic(macScratch, (short) 0, apduBuffer, macOffset, Constants.SC_MAC_LEN);

        return (short) (Constants.SC_BLOCK_LEN + ctLen + Constants.SC_MAC_LEN);
    }

    private void incrementCounter() {
        for (short i = (short) (Constants.SC_BLOCK_LEN - 1); i >= 0; i--) {
            short next = (short) ((outboundCounter[i] & 0xFF) + 1);
            outboundCounter[i] = (byte) next;
            if (next <= 0xFF) {
                return;
            }
        }
    }

    /**
     * Lexicographic 16-byte big-endian comparison used solely for the inbound IV monotonicity
     * check. Returns {@code > 0} if {@code a > b}, {@code 0} on equality, {@code < 0} otherwise.
     *
     * <p>IV bytes are public — they ride in the clear at the head of every inbound envelope — so
     * timing-based side channels reveal nothing secret. Even so, audit F-28 brings this helper into
     * the same constant-time mask-based style the rest of the channel uses ({@link
     * ConstantTime#equals}, {@link Bignat#ctLessThan}) so the codebase speaks one defence-in-depth
     * dialect; the previous early-return ternary was a stylistic outlier.
     */
    static short compare16(byte[] a, short aOff, byte[] b, short bOff) {
        // gtMask / ltMask each track "have we already proven a > b / a < b at some earlier
        // (more significant) byte?". Once one of them is set, the per-byte comparison must not
        // overwrite the earlier verdict — masks are sticky.
        short gtMask = 0;
        short ltMask = 0;
        for (short i = 0; i < Constants.SC_BLOCK_LEN; i++) {
            short av = (short) (a[(short) (aOff + i)] & 0xFF);
            short bv = (short) (b[(short) (bOff + i)] & 0xFF);
            // (av - bv) ∈ [-255, 255]. Sign-shift to get a 0xFFFF mask iff av < bv.
            short diff = (short) (av - bv);
            short ltHere = (short) ((diff >> 31) & 0xFFFF);
            // bv < av iff (bv - av) is negative.
            short gtHere = (short) (((bv - av) >> 31) & 0xFFFF);
            // Promote ltHere/gtHere only if neither verdict was reached at a more significant
            // byte. ~(gtMask | ltMask) is 0xFFFF iff "still tied so far".
            short stillTied = (short) ~(gtMask | ltMask);
            ltMask |= (short) (ltHere & stillTied);
            gtMask |= (short) (gtHere & stillTied);
        }
        // Materialise the three-way result without a branch: +1 / -1 / 0.
        return (short) ((gtMask & 1) - (ltMask & 1));
    }

    /**
     * Validates and strips PKCS#5/#7 padding from an AES-CBC plaintext block in place. Returns the
     * unpadded length. On any malformed pad raises {@link Constants#SW_SECURE_CHANNEL_FAILED}.
     *
     * <p>Per audit F-27 every padding-error branch — bad block alignment, pad byte zero, pad byte
     * larger than the block size, or a body byte that does not equal the pad byte — folds into a
     * single accumulator {@code failMask} that is checked once at the end. This eliminates the
     * three early-return {@code ISOException.throwIt} calls and their associated timing fan-out
     * over the secret-derived plaintext bytes. The Encrypt-then-MAC layer above already gates any
     * externally-observable signal by rejecting tampered ciphertexts before this method runs, so
     * the change is defence-in-depth — but it also matches the discipline used by every other
     * secret-touching helper in the codebase ({@link ConstantTime#equals}, {@link Bignat}).
     */
    static short stripPkcs5(byte[] buf, short offset, short paddedLen) {
        // The block-alignment check stays branchful: it operates on plaintext length only, which
        // is structural metadata derived from the ciphertext length the AES engine accepted, not
        // from any secret byte. Returning early here also keeps the loop bound below well-defined.
        if (paddedLen <= 0 || (short) (paddedLen % Constants.SC_BLOCK_LEN) != 0) {
            ISOException.throwIt(Constants.SW_SECURE_CHANNEL_FAILED);
        }
        short padVal = (short) (buf[(short) (offset + paddedLen - 1)] & 0xFF);
        // failMask: 0 = OK, non-zero = at least one pad invariant failed. Bits are OR-accumulated
        // from per-check sub-masks so the time spent here is independent of which (or how many)
        // invariants were violated.
        short failMask = 0;
        // padVal == 0 → reject. ((padVal | -padVal) >>> 31) is the classic "is non-zero" mask:
        // 0 when padVal == 0, 1 otherwise. Subtracting from 1 inverts it into the failure bit.
        failMask |= (short) (1 - ((padVal | -padVal) >>> 31));
        // padVal > BLOCK_LEN → reject. (BLOCK_LEN - padVal) is negative iff padVal > BLOCK_LEN.
        failMask |= (short) (((Constants.SC_BLOCK_LEN - padVal) >> 31) & 1);
        // For every byte in the trailing block (the only positions that could legitimately hold
        // pad bytes), check that it equals padVal whenever its distance from the end is ≤ padVal.
        // Iterating over the full SC_BLOCK_LEN tail keeps the loop count constant; per-byte
        // contribution to failMask is gated by the "this position must match" mask.
        for (short i = 0; i < Constants.SC_BLOCK_LEN; i++) {
            short distFromEnd = (short) (i + 1); // 1..BLOCK_LEN
            // mustMatch = -1 iff distFromEnd ≤ padVal, else 0. (padVal - distFromEnd) is
            // non-negative iff the byte is inside the pad region.
            short mustMatch = (short) ~(((padVal - distFromEnd) >> 31) & 0xFFFF);
            short bv = (short) (buf[(short) (offset + paddedLen - distFromEnd)] & 0xFF);
            // mismatch: bv ⊕ padVal ∈ [0, 255]; gated by mustMatch, then collapsed to a single
            // bit via the same is-non-zero pattern used for padVal == 0 above.
            short mismatchHere = (short) ((bv ^ padVal) & mustMatch);
            failMask |= (short) ((mismatchHere | -mismatchHere) >>> 31);
        }
        if (failMask != 0) {
            ISOException.throwIt(Constants.SW_SECURE_CHANNEL_FAILED);
        }
        return (short) (paddedLen - padVal);
    }

    private static short pkcs5PaddedLength(short plaintextLen) {
        short rem = (short) (plaintextLen % Constants.SC_BLOCK_LEN);
        return (short) (plaintextLen + Constants.SC_BLOCK_LEN - rem);
    }

    private static void applyPkcs5(byte[] buf, short offset, short plaintextLen, short padded) {
        byte pad = (byte) (padded - plaintextLen);
        for (short i = plaintextLen; i < padded; i++) {
            buf[(short) (offset + i)] = pad;
        }
    }
}
