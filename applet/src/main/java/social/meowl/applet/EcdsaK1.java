/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.ECPrivateKey;
import javacard.security.KeyBuilder;
import javacard.security.Signature;

/**
 * secp256k1 ECDSA signing primitive.
 *
 * <p>Given a BIP-32 path and a 32-byte digest, this class derives the leaf private scalar via
 * {@link Bip32#deriveLeafScalar}, signs the digest with the JC native {@code
 * Signature.ALG_ECDSA_SHA_256} algorithm (using {@link Signature#signPreComputedHash} so the applet
 * treats the host-supplied bytes as a pre-computed hash and does not re-hash them per <a
 * href="https://github.com/qntx/meowl-applet/blob/main/docs/adr/0007-card-only-signs-hashes.md">ADR-0007</a>),
 * parses the DER-encoded result, normalises {@code s} into the low half of {@code n} per <a
 * href="https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki">BIP-62</a> / <a
 * href="https://eips.ethereum.org/EIPS/eip-2">EIP-2</a>, and writes a fixed-length {@code r(32) ‖
 * s(32)} response.
 *
 * <p>The host is responsible for recovering the public-key recovery byte {@code v} from {@code (r,
 * s, digest, expected_pubkey)}; see {@code docs/adr/0010-signing-api-contract.md} for the rationale
 * (computing {@code v} on-card requires a modular square root that JavaCard 3.0.5 does not expose,
 * and an off-card recovery is both trivial and cheap given that the host already has the pubkey
 * from a prior {@code EXPORT_XPUB}).
 *
 * <p>Nonce: JavaCard 3.0.5 does not provide an interface for installing an RFC 6979 deterministic
 * nonce, so the JC ECDSA implementation generates a fresh random nonce per signature. ADR-0010
 * accepts this as the v1.0 reality: random-nonce ECDSA is fully spec-compliant on every chain meowl
 * signs for, and deterministic-nonce reproducibility is a host-side concern that the host SDK can
 * implement independently if it wants to.
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

    public EcdsaK1(Bip32 bip32) {
        this.bip32 = bip32;
        try {
            this.ecdsa = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
            // EEPROM-backed; we wipe via clearKey() at the tail of every signDigest call. JC
            // 3.0.5 does not universally expose TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT, so the
            // persistent flavour is the portable choice.
            this.signKey =
                    (ECPrivateKey)
                            KeyBuilder.buildKey(
                                    KeyBuilder.TYPE_EC_FP_PRIVATE,
                                    KeyBuilder.LENGTH_EC_FP_256,
                                    false);
        } catch (Exception e) {
            ISOException.throwIt(Constants.SW_UNSUPPORTED_FEATURE);
            throw new RuntimeException(); // unreachable
        }
        this.scratch = JCSystem.makeTransientByteArray(SCRATCH_LEN, JCSystem.CLEAR_ON_DESELECT);
    }

    /**
     * Signs the 32-byte {@code digest} under the secp256k1 private key derived at {@code pathBuf[
     * pathOff..pathOff + 4*depth]} and writes {@code r(32) ‖ s(32)} to {@code outBuf} at {@code
     * outOff}, with {@code s} guaranteed to lie in the low half of {@code n}.
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
        // Pull the leaf scalar into our own scratch. Bip32 wipes its internal copy on return,
        // and we wipe scratch[SCALAR_OFF] at the tail of this method.
        bip32.deriveLeafScalar(pathBuf, pathOff, depth, scratch, SCALAR_OFF);
        // Load the curve parameters and the secret scalar onto the EC private key, then sign.
        Secp256k1.setCurveParameters(signKey);
        signKey.setS(scratch, SCALAR_OFF, ModN.LEN);
        ecdsa.init(signKey, Signature.MODE_SIGN);

        short derLen;
        try {
            derLen =
                    ecdsa.signPreComputedHash(
                            digestBuf, digestOff, Constants.DIGEST_LEN, scratch, DER_OFF);
        } finally {
            // Whatever the signature outcome, the scalar is no longer needed.
            Util.arrayFillNonAtomic(scratch, SCALAR_OFF, ModN.LEN, (byte) 0);
            signKey.clearKey();
        }

        // Parse the DER signature into fixed-width r and s slots; left-pad each to 32 bytes.
        parseDerSignature(scratch, DER_OFF, derLen);

        // Low-s normalisation: if s > ⌊n/2⌋ replace s with n − s.
        if (!ModN.lessThanHalfN(scratch, S_OFF)) {
            ModN.negateMod(scratch, S_OFF);
        }

        // Concatenate r ‖ s into the response buffer.
        Util.arrayCopyNonAtomic(scratch, R_OFF, outBuf, outOff, ModN.LEN);
        Util.arrayCopyNonAtomic(scratch, S_OFF, outBuf, (short) (outOff + ModN.LEN), ModN.LEN);

        // The DER buffer and the parsed r/s slots are public, but clearing them is cheap and
        // means the transient buffer carries no residue past the call boundary.
        Util.arrayFillNonAtomic(
                scratch,
                DER_OFF,
                (short) (Constants.ECDSA_DER_MAX_LEN + ModN.LEN + ModN.LEN),
                (byte) 0);

        return Constants.SIG_LEN_R_S;
    }

    /**
     * Parses the DER-encoded ECDSA signature in {@code der[derOff..derOff + derLen]} and writes the
     * {@code r} and {@code s} INTEGER values to {@link #R_OFF} and {@link #S_OFF} of {@link
     * #scratch}, left-padded to 32 bytes each.
     *
     * <p>DER layout (per RFC 3279 §2.2.3 / SEC 1 §C.5):
     *
     * <pre>
     *   ECDSA-Sig-Value ::= SEQUENCE {
     *       r INTEGER,
     *       s INTEGER
     *   }
     * </pre>
     *
     * <p>{@code r} and {@code s} may carry a single leading {@code 0x00} byte when the top bit of
     * the magnitude would otherwise look negative under DER's signed-INTEGER convention; we strip
     * that byte during the left-pad step.
     *
     * <p>The parser is strict: anything outside the well-formed encoding produced by JC's {@code
     * Signature.ALG_ECDSA_SHA_256} raises {@link Constants#SW_UNSUPPORTED_FEATURE}, on the basis
     * that such an output indicates a buggy silicon implementation rather than caller-induced bad
     * input.
     */
    private void parseDerSignature(byte[] der, short derOff, short derLen) {
        if (derLen < (short) (DER_INT_HEADER + 1 + DER_INT_HEADER + 1)
                || derLen > Constants.ECDSA_DER_MAX_LEN
                || der[derOff] != DER_TAG_SEQUENCE) {
            ISOException.throwIt(Constants.SW_UNSUPPORTED_FEATURE);
        }
        short cursor = (short) (derOff + 1);
        short seqLen = (short) (der[cursor++] & 0xFF);
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
     * Reads one DER {@code INTEGER} element starting at {@code der[cursor]} and writes its
     * magnitude, left-padded to 32 bytes, to {@code out[outOff..outOff+32]}. The returned cursor is
     * positioned immediately after the element on the basis of the encoded (raw) length — stripping
     * the optional leading {@code 0x00} sign byte must not shrink the structural advance, only the
     * copied magnitude.
     *
     * @return the next cursor position after the element
     */
    private static short copyDerInteger(byte[] der, short cursor, byte[] out, short outOff) {
        if (der[cursor++] != DER_TAG_INTEGER) {
            ISOException.throwIt(Constants.SW_UNSUPPORTED_FEATURE);
        }
        short rawLen = (short) (der[cursor++] & 0xFF);
        short valStart = cursor;
        short nextCursor = (short) (cursor + rawLen);
        short copyLen = rawLen;
        // Drop the single optional leading 0x00 sign byte; reject anything wider than 33 bytes
        // (which would imply a value ≥ 2²⁵⁶, impossible for a well-formed ECDSA component).
        if (rawLen == 33 && der[valStart] == 0) {
            valStart++;
            copyLen--;
        }
        if (copyLen <= 0 || copyLen > ModN.LEN) {
            ISOException.throwIt(Constants.SW_UNSUPPORTED_FEATURE);
        }
        short padLen = (short) (ModN.LEN - copyLen);
        Util.arrayFillNonAtomic(out, outOff, padLen, (byte) 0);
        Util.arrayCopyNonAtomic(der, valStart, out, (short) (outOff + padLen), copyLen);
        return nextCursor;
    }
}
