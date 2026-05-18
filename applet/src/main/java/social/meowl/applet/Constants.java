/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

/**
 * Wire-level and policy constants for the meowl-applet.
 *
 * <p>This class centralises every magic number that appears on the wire (CLA, INS, status words,
 * tags) or in policy thresholds (PIN length, retry counts, reset-counter target). Centralising them
 * here keeps the rest of the codebase free of literal hex constants and gives auditors a single
 * file to verify against the protocol specification under {@code docs/protocol.md}.
 *
 * <p>The class is intentionally not instantiable: it is a constant-only namespace. JavaCard 3.0.5
 * does not support {@code enum}, so byte / short literals are the idiomatic representation.
 */
public final class Constants {

    private Constants() {
        // non-instantiable namespace
    }

    /*  Protocol identification  */

    /** Wire-protocol major version reported by {@code GET_INFO}. */
    public static final byte PROTOCOL_VERSION_MAJOR = (byte) 0x01;

    /** Wire-protocol minor version reported by {@code GET_INFO}. */
    public static final byte PROTOCOL_VERSION_MINOR = (byte) 0x00;

    /** Applet implementation major version reported by {@code GET_INFO}. */
    public static final byte APPLET_VERSION_MAJOR = (byte) 0x00;

    /** Applet implementation minor version reported by {@code GET_INFO}. */
    public static final byte APPLET_VERSION_MINOR = (byte) 0x01;

    /*  CLA  */

    /**
     * Class byte for every command the meowl applet processes. ISO 7816-4 private-class range; see
     * <a href="../../../../../../docs/adr/0002-cla-and-greenfield-protocol.md">ADR-0002</a>.
     */
    public static final byte CLA_MEOWL = (byte) 0x80;

    /*  INS — see docs/protocol.md for the full table  */

    /** {@code GET_INFO} — returns a TLV-encoded capability + identity profile. */
    public static final byte INS_GET_INFO = (byte) 0x01;

    /** {@code GET_AUTHENTIKEY} — returns the card's compressed authentikey public key. */
    public static final byte INS_GET_AUTHENTIKEY = (byte) 0x02;

    /**
     * {@code RESET_TO_FACTORY} — wipes the seed and credentials after N consecutive invocations.
     */
    public static final byte INS_RESET_TO_FACTORY = (byte) 0x03;

    /*  Status words — ISO 7816-4 plus applet-private extensions in the 0x6Fxx range  */

    /** ISO 7816-4 {@code 6700} — wrong length. */
    public static final short SW_WRONG_LENGTH = (short) 0x6700;

    /** ISO 7816-4 {@code 6982} — security status not satisfied. */
    public static final short SW_SECURITY_STATUS_NOT_SATISFIED = (short) 0x6982;

    /** ISO 7816-4 {@code 6985} — condition of use not satisfied (e.g. wrong lifecycle state). */
    public static final short SW_CONDITIONS_NOT_SATISFIED = (short) 0x6985;

    /** ISO 7816-4 {@code 6A86} — incorrect P1 or P2. */
    public static final short SW_INCORRECT_P1P2 = (short) 0x6A86;

    /** ISO 7816-4 {@code 6D00} — INS not supported. */
    public static final short SW_INS_NOT_SUPPORTED = (short) 0x6D00;

    /** ISO 7816-4 {@code 6E00} — CLA not supported. */
    public static final short SW_CLA_NOT_SUPPORTED = (short) 0x6E00;

    /** ISO 7816-4 {@code 9000} — success. */
    public static final short SW_NO_ERROR = (short) 0x9000;

    /**
     * Reset-to-factory countdown base. The card returns {@code SW_RESET_COUNTDOWN_BASE + n}, where
     * {@code n} is the number of additional {@code RESET_TO_FACTORY} invocations still required to
     * trigger the wipe. The terminal value {@code n = 0} signals that the wipe has been performed.
     *
     * <p>Range used: {@code 0x6FA0}–{@code 0x6FAF}. See <a
     * href="../../../../../../docs/adr/0008-reset-to-factory-multi-step.md">ADR-0008</a>.
     */
    public static final short SW_RESET_COUNTDOWN_BASE = (short) 0x6FA0;

    /** Applet-private {@code 6FB0} — lifecycle state forbids this command. */
    public static final short SW_LIFECYCLE_INVALID = (short) 0x6FB0;

    /** Applet-private {@code 6FE0} — required JavaCard feature not available on this card. */
    public static final short SW_UNSUPPORTED_FEATURE = (short) 0x6FE0;

    /*  Capability bitmask (advertised in GET_INFO, TAG_CAPABILITIES)  */

    /** Bit 0 — card supports secp256k1 ECDSA signing. */
    public static final short CAP_K1_ECDSA = (short) 0x0001;

    /** Bit 1 — card supports BIP-340 Schnorr signing on secp256k1. */
    public static final short CAP_K1_SCHNORR = (short) 0x0002;

    /** Bit 2 — card supports Ed25519 EdDSA signing. */
    public static final short CAP_ED25519 = (short) 0x0004;

    /** Bit 3 — card exposes a Secure Channel using AES-GCM. */
    public static final short CAP_SC_GCM = (short) 0x0008;

    /** Bit 4 — card exposes a Secure Channel using AES-CBC + HMAC-SHA-256. */
    public static final short CAP_SC_CBC_HMAC = (short) 0x0010;

    /** Bit 5 — card exposes the PKI personalisation flow. */
    public static final short CAP_PKI = (short) 0x0020;

    /** Bit 6 — card supports {@code RESET_TO_FACTORY}. */
    public static final short CAP_RESET_TO_FACTORY = (short) 0x0040;

    /*  TLV tag values used inside GET_INFO  */

    /** Tag 0x01 — protocol version (2 bytes: major, minor). */
    public static final byte TAG_PROTOCOL_VERSION = (byte) 0x01;

    /** Tag 0x02 — applet implementation version (2 bytes: major, minor). */
    public static final byte TAG_APPLET_VERSION = (byte) 0x02;

    /** Tag 0x03 — lifecycle state (1 byte). */
    public static final byte TAG_LIFECYCLE_STATE = (byte) 0x03;

    /** Tag 0x04 — capability bitmask (2 bytes, big-endian). */
    public static final byte TAG_CAPABILITIES = (byte) 0x04;

    /** Tag 0x05 — compressed authentikey public key (33 bytes). */
    public static final byte TAG_AUTHENTIKEY_PUBKEY = (byte) 0x05;

    /*  Sizes  */

    /** Length of a secp256k1 scalar (private key, hash, x-coordinate). */
    public static final short SECP256K1_SCALAR_LEN = (short) 32;

    /** Length of an uncompressed secp256k1 public key (`0x04 || x || y`). */
    public static final short SECP256K1_UNCOMPRESSED_LEN = (short) 65;

    /** Length of a compressed secp256k1 public key (`0x02|0x03 || x`). */
    public static final short SECP256K1_COMPRESSED_LEN = (short) 33;

    /*  Reset-to-factory policy  */

    /**
     * Number of consecutive un-interleaved {@code RESET_TO_FACTORY} invocations required to trigger
     * the wipe. See <a
     * href="../../../../../../docs/adr/0008-reset-to-factory-multi-step.md">ADR-0008</a>.
     */
    public static final byte RESET_REQUIRED_INVOCATIONS = (byte) 4;
}
