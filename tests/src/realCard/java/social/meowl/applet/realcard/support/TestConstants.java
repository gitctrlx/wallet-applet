/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet.realcard.support;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.HexFormat;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import social.meowl.applet.Constants;

/**
 * Shared constants for end-to-end test suites driving the meowl applet through card-mediated APDUs.
 * Centralised here so each integration suite stops duplicating the same AID, INS bytes, KDF info,
 * and BIP-32 vector seeds.
 */
public final class TestConstants {

    /** Default applet AID (matches {@code Makefile} {@code APPLET_AID}). */
    public static final byte[] APPLET_AID_BYTES = {(byte) 0xF0, 0x6D, 0x65, 0x6F, 0x77, 0x6C, 0x01};

    public static final int CLA = Constants.CLA_MEOWL & 0xFF;
    public static final int INS_INIT_SC = Constants.INS_INIT_SECURE_CHANNEL & 0xFF;
    public static final int INS_OPEN_SC = Constants.INS_OPEN_SECURE_CHANNEL & 0xFF;

    public static final X9ECParameters SECP256K1 = CustomNamedCurves.getByName("secp256k1");

    /** KDF info label, MEAP-2 §key-derivation. Mirrors {@code SecureChannelClient.KDF_INFO}. */
    public static final byte[] KDF_INFO = "meowl-sc-v1".getBytes(StandardCharsets.UTF_8);

    /** Per-process secure RNG used to derive client ephemeral scalars during SC handshakes. */
    public static final SecureRandom RANDOM = new SecureRandom();

    public static final byte[] DEFAULT_PIN = "123456".getBytes(StandardCharsets.UTF_8);
    public static final byte[] DEFAULT_PUK = "ABCDEFGH".getBytes(StandardCharsets.UTF_8);

    /** BIP-32 test vector 1 seed (16 bytes, hex {@code 000102030405060708090a0b0c0d0e0f}). */
    public static final byte[] BIP32_VECTOR_1_SEED = parseHex("000102030405060708090a0b0c0d0e0f");

    /** Strips whitespace and decodes the remaining hex digits into bytes. */
    public static byte[] parseHex(String hex) {
        return HexFormat.of().parseHex(hex.replace(" ", ""));
    }

    private TestConstants() {}
}
