/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

import javacard.security.ECKey;

/**
 * Curve parameters and helpers for {@code secp256k1}.
 *
 * <p>Constants are taken verbatim from <a href="https://www.secg.org/sec2-v2.pdf">SEC 2 v2.0</a>
 * §2.4.1. The byte layout matches the {@link ECKey#setFieldFP setFieldFP / setA / setB / setG /
 * setR / setK} API exposed by JavaCard 3.0.5, so the same backing array can be sliced and handed to
 * every setter.
 *
 * <p>The constants and the dispatch shape of {@link #setCurveParameters(ECKey)} are derived from
 * Toporin's Satochip applet (AGPL-3.0-or-later); they are otherwise standard SECG values.
 */
public final class Secp256k1 {

    /** Length of an EC scalar (private key / hash / x-coordinate). */
    public static final short SCALAR_LEN = (short) 32;

    /** Length of an uncompressed EC point ({@code 0x04 || x || y}). */
    public static final short POINT_UNCOMPRESSED_LEN = (short) 65;

    /** Cofactor {@code h = 1}. */
    public static final short COFACTOR = (short) 0x01;

    private static final short OFFSET_P = (short) 0;
    private static final short OFFSET_A = (short) 32;
    private static final short OFFSET_B = (short) 64;
    private static final short OFFSET_N = (short) 96;
    private static final short OFFSET_G = (short) 128;

    /** Packed curve parameters: {@code p ‖ a ‖ b ‖ n ‖ G(uncompressed)}. */
    private static final byte[] PARAMS = {
        // p — 32 bytes, offset 0
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFE,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFC,
        (byte) 0x2F,
        // a — 32 bytes, offset 32
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        // b — 32 bytes, offset 64
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x07,
        // n — 32 bytes, offset 96
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFE,
        (byte) 0xBA,
        (byte) 0xAE,
        (byte) 0xDC,
        (byte) 0xE6,
        (byte) 0xAF,
        (byte) 0x48,
        (byte) 0xA0,
        (byte) 0x3B,
        (byte) 0xBF,
        (byte) 0xD2,
        (byte) 0x5E,
        (byte) 0x8C,
        (byte) 0xD0,
        (byte) 0x36,
        (byte) 0x41,
        (byte) 0x41,
        // G — 65 bytes uncompressed, offset 128
        (byte) 0x04,
        (byte) 0x79,
        (byte) 0xBE,
        (byte) 0x66,
        (byte) 0x7E,
        (byte) 0xF9,
        (byte) 0xDC,
        (byte) 0xBB,
        (byte) 0xAC,
        (byte) 0x55,
        (byte) 0xA0,
        (byte) 0x62,
        (byte) 0x95,
        (byte) 0xCE,
        (byte) 0x87,
        (byte) 0x0B,
        (byte) 0x07,
        (byte) 0x02,
        (byte) 0x9B,
        (byte) 0xFC,
        (byte) 0xDB,
        (byte) 0x2D,
        (byte) 0xCE,
        (byte) 0x28,
        (byte) 0xD9,
        (byte) 0x59,
        (byte) 0xF2,
        (byte) 0x81,
        (byte) 0x5B,
        (byte) 0x16,
        (byte) 0xF8,
        (byte) 0x17,
        (byte) 0x98,
        (byte) 0x48,
        (byte) 0x3A,
        (byte) 0xDA,
        (byte) 0x77,
        (byte) 0x26,
        (byte) 0xA3,
        (byte) 0xC4,
        (byte) 0x65,
        (byte) 0x5D,
        (byte) 0xA4,
        (byte) 0xFB,
        (byte) 0xFC,
        (byte) 0x0E,
        (byte) 0x11,
        (byte) 0x08,
        (byte) 0xA8,
        (byte) 0xFD,
        (byte) 0x17,
        (byte) 0xB4,
        (byte) 0x48,
        (byte) 0xA6,
        (byte) 0x85,
        (byte) 0x54,
        (byte) 0x19,
        (byte) 0x9C,
        (byte) 0x47,
        (byte) 0xD0,
        (byte) 0x8F,
        (byte) 0xFB,
        (byte) 0x10,
        (byte) 0xD4,
        (byte) 0xB8,
    };

    private Secp256k1() {}

    /**
     * Configures {@code key} with the SECG secp256k1 parameters. Applicable to both {@code
     * ECPrivateKey} and {@code ECPublicKey} instances (both extend {@code ECKey}).
     */
    public static void setCurveParameters(ECKey key) {
        key.setFieldFP(PARAMS, OFFSET_P, SCALAR_LEN);
        key.setA(PARAMS, OFFSET_A, SCALAR_LEN);
        key.setB(PARAMS, OFFSET_B, SCALAR_LEN);
        key.setR(PARAMS, OFFSET_N, SCALAR_LEN);
        key.setG(PARAMS, OFFSET_G, POINT_UNCOMPRESSED_LEN);
        key.setK(COFACTOR);
    }
}
