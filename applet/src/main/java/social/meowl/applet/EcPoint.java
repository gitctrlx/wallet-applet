/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import javacard.framework.ISOException;
import javacard.security.ECPrivateKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;

/**
 * Hardware EC scalar multiplier built on {@link KeyAgreement#ALG_EC_SVDP_DH_PLAIN_XY}.
 *
 * <p>One instance binds to one short Weierstrass curve (secp256k1, Wei25519, …) via a {@link
 * CurveSetup} closure provided at install time. The instance owns a disposable {@link ECPrivateKey}
 * (transient where the silicon supports it) into which a fresh scalar is loaded for every
 * multiplication, and a {@link KeyAgreement} engine that drives the EC coprocessor. The class never
 * retains operand or output bytes — secrets live in caller-supplied buffers, wiped by the caller's
 * {@code finally} block.
 *
 * <h2>Operation</h2>
 *
 * <p>{@link #multiplyG} computes {@code scalar · G} for the curve's base point, returning the
 * 65-byte uncompressed result. {@link #multiplyPoint} computes {@code scalar · P} for a caller-
 * supplied {@code P}. Both routes share the same hardware code path; the only difference is whether
 * the input point comes from the curve's static {@code G} table or from a buffer.
 *
 * <p>The hardware EC engine is variable-time per silicon vendor practice; defence-in-depth against
 * power / EM side channels is supplied at the layer above:
 *
 * <ul>
 *   <li>fresh ephemeral nonces per signature (Ed25519, Schnorr),
 *   <li>Coron projective coordinate randomisation inside the KA implementation (vendor),
 *   <li>per-call wipe of the scalar slot ({@link #wipe}).
 * </ul>
 *
 * <p>Higher-order defences (scalar blinding {@code k → k + r·n}, double-computation fault
 * detection) are owned by the signing primitives, not this class.
 */
public final class EcPoint {

    /** Closure-style hook installed once at construction; sets curve parameters on the EC key. */
    public interface CurveSetup {
        /** Configures {@code key} with all curve parameters (p, a, b, G, r, k). */
        void apply(ECPrivateKey key);
    }

    private final KeyAgreement ka;
    private final ECPrivateKey scalarKey;
    private final CurveSetup curveSetup;
    private final byte[] curveParams;
    private final short generatorOff;
    private final short pointLen;

    /**
     * Builds an EcPoint engine for the curve described by {@code setup}.
     *
     * <p>The {@link CurveSetup} reference is kept and re-applied on every {@code multiply*}
     * invocation: a {@code TRANSIENT_DESELECT} EC private key loses its field / curve parameters
     * across a deselect, so the engine MUST reload them per call rather than only at install time.
     *
     * @param setup applies curve parameters (p, a, b, G, r, k) onto an ECPrivateKey.
     * @param curveParams packed parameter array; the base point uncompressed encoding lives at
     *     {@code curveParams[generatorOff..generatorOff + pointLen]}.
     * @param generatorOff offset of the base point inside {@code curveParams}.
     * @param pointLen length of the uncompressed point (65 for 256-bit curves).
     * @param keyBitLength bit length of the curve scalar (256 for secp256k1 and Wei25519).
     */
    public EcPoint(
            CurveSetup setup,
            byte[] curveParams,
            short generatorOff,
            short pointLen,
            short keyBitLength) {
        ECPrivateKey key;
        try {
            key =
                    (ECPrivateKey)
                            KeyBuilder.buildKey(
                                    KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT,
                                    keyBitLength,
                                    false);
        } catch (javacard.security.CryptoException e) {
            key =
                    (ECPrivateKey)
                            KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, keyBitLength, false);
        }
        this.scalarKey = key;
        this.curveSetup = setup;
        try {
            this.ka = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY, false);
        } catch (javacard.security.CryptoException e) {
            ISOException.throwIt(Constants.SW_UNSUPPORTED_FEATURE);
            throw new RuntimeException(); // unreachable
        }
        this.curveParams = curveParams;
        this.generatorOff = generatorOff;
        this.pointLen = pointLen;
    }

    /**
     * Computes {@code scalar · G} on this curve and writes the result as an uncompressed point
     * ({@code 0x04 ‖ X ‖ Y}) to {@code out[outOff..outOff + 65]}.
     *
     * @return {@link #pointLen} on success; throws {@link Constants#SW_UNSUPPORTED_FEATURE} if the
     *     hardware engine returns an unexpected length or prefix byte (defensive — JC native
     *     ECDH-XY always returns 65 with the {@code 0x04} prefix).
     */
    public short multiplyG(
            byte[] scalar, short scalarOff, short scalarLen, byte[] out, short outOff) {
        curveSetup.apply(scalarKey);
        scalarKey.setS(scalar, scalarOff, scalarLen);
        ka.init(scalarKey);
        short len = ka.generateSecret(curveParams, generatorOff, pointLen, out, outOff);
        if (len != pointLen || out[outOff] != (byte) 0x04) {
            ISOException.throwIt(Constants.SW_UNSUPPORTED_FEATURE);
        }
        return pointLen;
    }

    /**
     * Computes {@code scalar · point} on this curve and writes the result as an uncompressed point
     * to {@code out[outOff..outOff + 65]}. {@code point} MUST be the uncompressed encoding {@code
     * 0x04 ‖ X ‖ Y}.
     */
    public short multiplyPoint(
            byte[] scalar,
            short scalarOff,
            short scalarLen,
            byte[] point,
            short pointOff,
            byte[] out,
            short outOff) {
        curveSetup.apply(scalarKey);
        scalarKey.setS(scalar, scalarOff, scalarLen);
        ka.init(scalarKey);
        short len = ka.generateSecret(point, pointOff, pointLen, out, outOff);
        if (len != pointLen || out[outOff] != (byte) 0x04) {
            ISOException.throwIt(Constants.SW_UNSUPPORTED_FEATURE);
        }
        return pointLen;
    }

    /** Erases the scalar slot. Caller MUST invoke this in their {@code finally} block. */
    public void wipe() {
        scalarKey.clearKey();
    }
}
