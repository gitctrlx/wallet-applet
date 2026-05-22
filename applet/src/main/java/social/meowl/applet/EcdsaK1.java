/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.ECPrivateKey;
import javacard.security.KeyBuilder;
import javacard.security.Signature;

/**
 * secp256k1 ECDSA signing primitive.
 *
 * <p>Given a BIP-32 path and a 32-byte digest, derives the leaf scalar via {@link
 * Bip32#deriveLeafScalar}, signs through the JC native {@code Signature.ALG_ECDSA_SHA_256} using
 * {@link Signature#signPreComputedHash} (hash-only per MEAP-6), parses the DER signature,
 * normalises {@code s} into the low half of {@code n} per BIP-62 / EIP-2, and writes a fixed-length
 * {@code r(32) ‖ s(32)} response.
 *
 * <p>The host is responsible for the recovery byte {@code v}: JC 3.0.5 exposes no modular square
 * root, and the host already holds the pubkey from a prior {@code EXPORT_XPUB}. The nonce is
 * platform-random (JC 3.0.5 has no RFC 6979 hook); random-nonce ECDSA is fully spec-compliant on
 * every chain meowl signs for.
 */
public final class EcdsaK1 {

    /** Length of the DER fragment {@code 0x02 ‖ len(1) ‖ value} header. */
    private static final short DER_INT_HEADER = (short) 2;

    /** DER tag for an INTEGER element. */
    private static final byte DER_TAG_INTEGER = (byte) 0x02;

    /** DER tag for the outer ECDSA-Sig-Value SEQUENCE. */
    private static final byte DER_TAG_SEQUENCE = (byte) 0x30;

    private final Bip32 bip32;
    private final Signature ecdsa;
    private final ECPrivateKey signKey;

    /**
     * Transient scratch laid out as {@code scalar(32) ‖ der_sig(72) ‖ r_buf(32) ‖ s_buf(32) = 168}.
     * The {@code scalar} slot is the only secret; everything else is post-signature public
     * material.
     */
    private final byte[] scratch;

    private static final short SCALAR_OFF = (short) 0;
    private static final short DER_OFF = (short) (SCALAR_OFF + ModN.LEN);
    private static final short R_OFF = (short) (DER_OFF + Constants.ECDSA_DER_MAX_LEN);
    private static final short S_OFF = (short) (R_OFF + ModN.LEN);
    private static final short SCRATCH_LEN = (short) (S_OFF + ModN.LEN);

    /**
     * @param sharedScratch singleton transient scratch (≥ {@link #SCRATCH_LEN} bytes) allocated by
     *     {@link MeowlApplet}; reused by every signing INS and the {@link SecureChannel} handshake
     *     since APDU dispatch is single-threaded.
     */
    public EcdsaK1(Bip32 bip32, byte[] sharedScratch) {
        if ((short) sharedScratch.length < SCRATCH_LEN) {
            ISOException.throwIt(Constants.SW_UNSUPPORTED_FEATURE);
        }
        this.bip32 = bip32;
        try {
            this.ecdsa = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
            // Prefer RAM-backed transient so the leaf scalar never lands in EEPROM; clearKey()
            // alone does not necessarily wipe EEPROM cells. Persistent only as a fallback.
            ECPrivateKey signKey;
            try {
                signKey =
                        (ECPrivateKey)
                                KeyBuilder.buildKey(
                                        KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT,
                                        KeyBuilder.LENGTH_EC_FP_256,
                                        false);
            } catch (javacard.security.CryptoException e) {
                signKey =
                        (ECPrivateKey)
                                KeyBuilder.buildKey(
                                        KeyBuilder.TYPE_EC_FP_PRIVATE,
                                        KeyBuilder.LENGTH_EC_FP_256,
                                        false);
            }
            this.signKey = signKey;
        } catch (Exception e) {
            ISOException.throwIt(Constants.SW_UNSUPPORTED_FEATURE);
            throw new RuntimeException(); // unreachable
        }
        this.scratch = sharedScratch;
    }

    /**
     * Signs the 32-byte {@code digest} under the secp256k1 key derived at {@code
     * pathBuf[pathOff..pathOff + 4*depth]}, writing {@code r(32) ‖ s(32)} with low-{@code s}
     * normalised.
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
            // Pull the leaf scalar into our own scratch. Bip32 wipes its internal copy on return,
            // and the outer finally clears the entire scratch buffer plus the EC private key.
            bip32.deriveLeafScalar(pathBuf, pathOff, depth, scratch, SCALAR_OFF);
            // Load the curve parameters and the secret scalar onto the EC private key, then sign.
            Secp256k1.setCurveParameters(signKey);
            signKey.setS(scratch, SCALAR_OFF, ModN.LEN);
            ecdsa.init(signKey, Signature.MODE_SIGN);

            short derLen =
                    ecdsa.signPreComputedHash(
                            digestBuf, digestOff, Constants.DIGEST_LEN, scratch, DER_OFF);

            // Parse the DER signature into fixed-width r and s slots; left-pad each to 32 bytes.
            parseDerSignature(scratch, DER_OFF, derLen);

            // Low-s normalisation: if s > ⌊n/2⌋ replace s with n − s.
            if (!ModN.lessThanHalfN(scratch, S_OFF)) {
                ModN.negateMod(scratch, S_OFF);
            }

            // Concatenate r ‖ s into the response buffer.
            Util.arrayCopyNonAtomic(scratch, R_OFF, outBuf, outOff, ModN.LEN);
            Util.arrayCopyNonAtomic(scratch, S_OFF, outBuf, (short) (outOff + ModN.LEN), ModN.LEN);

            return Constants.SIG_LEN_R_S;
        } finally {
            // SCALAR_OFF is the only secret; the DER and r/s slots are post-signature public
            // material but get wiped anyway so no residue survives the call boundary.
            Util.arrayFillNonAtomic(scratch, (short) 0, SCRATCH_LEN, (byte) 0);
            signKey.clearKey();
        }
    }

    /**
     * Parses the DER-encoded ECDSA signature in {@code der[derOff..+derLen]} and writes {@code r}
     * and {@code s} into {@link #R_OFF} / {@link #S_OFF} of {@link #scratch}, left-padded to 32
     * bytes each.
     *
     * <p>DER layout (RFC 3279 §2.2.3 / SEC 1 §C.5):
     *
     * <pre>
     *   ECDSA-Sig-Value ::= SEQUENCE {
     *       r INTEGER,
     *       s INTEGER
     *   }
     * </pre>
     *
     * <p>Strict parser: anything outside the well-formed encoding produced by JC's native ECDSA
     * raises {@link Constants#SW_UNSUPPORTED_FEATURE}, signalling a buggy silicon implementation.
     */
    private void parseDerSignature(byte[] der, short derOff, short derLen) {
        if (derLen < (short) (DER_INT_HEADER + 1 + DER_INT_HEADER + 1)
                || derLen > Constants.ECDSA_DER_MAX_LEN
                || der[derOff] != DER_TAG_SEQUENCE) {
            ISOException.throwIt(Constants.SW_UNSUPPORTED_FEATURE);
        }
        short cursor = (short) (derOff + 1);
        // JC native ECDSA produces ≤ 72 bytes of DER (always < 128), so the length field is
        // short-form. Reject long-form (high bit set) upfront to harden against off-by-one parse.
        short seqLen = (short) (der[cursor++] & 0xFF);
        if ((seqLen & 0x80) != 0) {
            ISOException.throwIt(Constants.SW_UNSUPPORTED_FEATURE);
        }
        if ((short) (cursor + seqLen) != (short) (derOff + derLen)) {
            ISOException.throwIt(Constants.SW_UNSUPPORTED_FEATURE);
        }
        cursor = copyDerInteger(der, cursor, scratch, R_OFF);
        cursor = copyDerInteger(der, cursor, scratch, S_OFF);
        if (cursor != (short) (derOff + derLen)) {
            ISOException.throwIt(Constants.SW_UNSUPPORTED_FEATURE);
        }
    }

    /**
     * Reads one DER {@code INTEGER} starting at {@code der[cursor]} and writes its magnitude,
     * left-padded to 32 bytes, into {@code out[outOff..+32]}. Strict minimal DER (X.690 §8.3.2): a
     * leading {@code 0x00} sign byte is allowed only when the next byte's MSB would otherwise make
     * the INTEGER look negative; {@code r = 0} or {@code s = 0} are rejected.
     *
     * @return the next cursor position after the element
     */
    private static short copyDerInteger(byte[] der, short cursor, byte[] out, short outOff) {
        if (der[cursor++] != DER_TAG_INTEGER) {
            ISOException.throwIt(Constants.SW_UNSUPPORTED_FEATURE);
        }
        // Same long-form rejection as parseDerSignature: an ECDSA INTEGER is at most 33 bytes.
        short rawLen = (short) (der[cursor++] & 0xFF);
        if ((rawLen & 0x80) != 0) {
            ISOException.throwIt(Constants.SW_UNSUPPORTED_FEATURE);
        }
        short valStart = cursor;
        short nextCursor = (short) (cursor + rawLen);
        short copyLen = rawLen;
        if (rawLen == 33 && der[valStart] == 0) {
            // Legal sign byte: magnitude is 32 bytes and its MSB must be set; otherwise the
            // 0x00 is non-minimal per X.690 §8.3.2.
            if ((der[(short) (valStart + 1)] & 0x80) == 0) {
                ISOException.throwIt(Constants.SW_UNSUPPORTED_FEATURE);
            }
            valStart++;
            copyLen--;
        } else if (rawLen > 1 && der[valStart] == 0) {
            // Any other leading 0x00 (rawLen < 33) is non-minimal DER.
            ISOException.throwIt(Constants.SW_UNSUPPORTED_FEATURE);
        }
        if (copyLen <= 0 || copyLen > ModN.LEN) {
            ISOException.throwIt(Constants.SW_UNSUPPORTED_FEATURE);
        }
        // Constant-time OR-fold to reject r = 0 / s = 0.
        short orAll = 0;
        for (short i = 0; i < copyLen; i++) {
            orAll |= (short) (der[(short) (valStart + i)] & 0xFF);
        }
        if (orAll == 0) {
            ISOException.throwIt(Constants.SW_UNSUPPORTED_FEATURE);
        }
        short padLen = (short) (ModN.LEN - copyLen);
        Util.arrayFillNonAtomic(out, outOff, padLen, (byte) 0);
        Util.arrayCopyNonAtomic(der, valStart, out, (short) (outOff + padLen), copyLen);
        return nextCursor;
    }
}
