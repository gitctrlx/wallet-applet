/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet;

/**
 * Wire-level and policy constants for the meowl-applet.
 *
 * <p>Every magic number that appears on the APDU wire or in a policy threshold is declared here so
 * the rest of the codebase stays free of literal hex constants. Auditors verify this single file
 * against {@code docs/protocol.md} and the ADRs under {@code docs/adr/}.
 *
 * <p>JavaCard 3.0.5 has no {@code enum}, so {@code byte} / {@code short} literals are the idiomatic
 * representation.
 */
public final class Constants {

    private Constants() {}

    /*  Versioning — packed as 16-bit big-endian (major << 8 | minor).  */

    /** Wire-protocol version reported by {@code GET_INFO}. */
    public static final short PROTOCOL_VERSION = (short) 0x0100;

    /** Applet implementation version reported by {@code GET_INFO}. */
    public static final short APPLET_VERSION = (short) 0x0001;

    /*  CLA  */

    /**
     * Class byte for every command the meowl applet processes. ISO 7816-4 private-class range; see
     * {@code docs/adr/0002-cla-and-greenfield-protocol.md}.
     */
    public static final byte CLA_MEOWL = (byte) 0x80;

    /*  INS table — see docs/protocol.md.
     *
     *  Banding convention (so auditors can read intent from the opcode alone):
     *    0x00–0x0F  lifecycle / identity / capability discovery
     *    0x10–0x1F  secure channel
     *    0x20–0x2F  PIN / PUK
     *    0x30–0x3F  PKI personalisation
     *    0x40–0x4F  seed management
     *    0x50–0x5F  signing primitives
     *    0x60–0x6F  derivation utilities
     *    0xFF       reset to factory (per ISO 7816-4 reserved range hint)
     *
     *  Reserved INS for later phases are declared as comments rather than as constants so that
     *  the implemented surface and the planned surface are visually distinct.
     */

    /** {@code GET_INFO} — returns a TLV-encoded capability + identity profile. (Phase 1) */
    public static final byte INS_GET_INFO = (byte) 0x01;

    /** {@code GET_AUTHENTIKEY} — returns the compressed authentikey public key. (Phase 1) */
    public static final byte INS_GET_AUTHENTIKEY = (byte) 0x02;

    /** {@code RESET_TO_FACTORY} — wipes secrets after N consecutive invocations. (Phase 1) */
    public static final byte INS_RESET_TO_FACTORY = (byte) 0x03;

    /** {@code INIT_SECURE_CHANNEL} — ECDH handshake; establishes session keys. (Phase 2) */
    public static final byte INS_INIT_SECURE_CHANNEL = (byte) 0x10;

    /** {@code OPEN_SECURE_CHANNEL} — envelopes an inner APDU under the session keys. (Phase 2) */
    public static final byte INS_OPEN_SECURE_CHANNEL = (byte) 0x11;

    /** {@code SETUP} — initial PIN/PUK provisioning. (Phase 3) */
    public static final byte INS_SETUP = (byte) 0x20;

    /** {@code VERIFY_PIN} — unlock session-scoped PIN authorisation. (Phase 3) */
    public static final byte INS_VERIFY_PIN = (byte) 0x21;

    /** {@code CHANGE_PIN} — rotate user PIN. (Phase 3) */
    public static final byte INS_CHANGE_PIN = (byte) 0x22;

    /** {@code CHANGE_PUK} — rotate unblock PUK. (Phase 3) */
    public static final byte INS_CHANGE_PUK = (byte) 0x23;

    /** {@code UNBLOCK_PIN} — PUK-based PIN unblock. (Phase 3) */
    public static final byte INS_UNBLOCK_PIN = (byte) 0x24;

    /** {@code EXPORT_PKI_PUBKEY} — export authentikey pubkey for CSR construction. (Phase 3) */
    public static final byte INS_EXPORT_PKI_PUBKEY = (byte) 0x30;

    /** {@code SIGN_PKI_CSR} — sign a host-provided CSR digest with the authentikey. (Phase 3) */
    public static final byte INS_SIGN_PKI_CSR = (byte) 0x31;

    /** {@code IMPORT_PKI_CERT} — chunked manufacturer certificate import. (Phase 3) */
    public static final byte INS_IMPORT_PKI_CERT = (byte) 0x32;

    /** {@code EXPORT_PKI_CERT} — paged certificate export. (Phase 3) */
    public static final byte INS_EXPORT_PKI_CERT = (byte) 0x33;

    /** {@code LOCK_PKI} — finalise PKI personalisation; transitions to PERSONALIZED. (Phase 3) */
    public static final byte INS_LOCK_PKI = (byte) 0x34;

    // Reserved for Phase 4: INS_IMPORT_SEED = 0x40, INS_GENERATE_SEED = 0x41,
    //                       INS_EXPORT_XPUB = 0x42.
    // Reserved for Phase 5: INS_SIGN_ECDSA_K1 = 0x50, INS_SIGN_SCHNORR_K1 = 0x51,
    //                       INS_SIGN_ED25519 = 0x52.

    /*  Status words — ISO 7816-4 standard codes plus applet-private extensions in the 6Fxx
     *  range. Keep the comments authoritative: every host SDK decodes against this table.
     */

    /** ISO 7816-4 {@code 6700} — wrong length. */
    public static final short SW_WRONG_LENGTH = (short) 0x6700;

    /** ISO 7816-4 {@code 6982} — security status not satisfied (PIN / Secure Channel). */
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
     * trigger the wipe. {@code n == 0} signals that the wipe has been performed.
     *
     * <p>Range used: {@code 0x6FA0}–{@code 0x6FAF}. See {@code
     * docs/adr/0008-reset-to-factory-multi-step.md}.
     */
    public static final short SW_RESET_COUNTDOWN_BASE = (short) 0x6FA0;

    /** Applet-private {@code 6FB0} — lifecycle state forbids this command. */
    public static final short SW_LIFECYCLE_INVALID = (short) 0x6FB0;

    /** Applet-private {@code 6FB1} — command requires an open Secure Channel. */
    public static final short SW_SECURE_CHANNEL_REQUIRED = (short) 0x6FB1;

    /** Applet-private {@code 6FB2} — Secure Channel cryptographic check failed. */
    public static final short SW_SECURE_CHANNEL_FAILED = (short) 0x6FB2;

    /**
     * ISO 7816-4 {@code 63Cn} base — PIN verification failed, {@code n} attempts remain. The caller
     * ORs in the (4-bit) remaining-tries count.
     */
    public static final short SW_PIN_RETRIES_BASE = (short) 0x63C0;

    /** Applet-private {@code 6983} — the PIN (or PUK) is blocked: authentication method blocked. */
    public static final short SW_PIN_BLOCKED = (short) 0x6983;

    /** Applet-private {@code 6FE0} — a required JavaCard feature is not available on this card. */
    public static final short SW_UNSUPPORTED_FEATURE = (short) 0x6FE0;

    /*  Capability bitmask advertised in GET_INFO under TAG_CAPABILITIES.
     *  16-bit so we can fit feature flags through several phases without re-encoding.
     */

    /** Bit 0 — card supports secp256k1 ECDSA signing. (Phase 5) */
    public static final short CAP_K1_ECDSA = (short) 0x0001;

    /** Bit 1 — card supports BIP-340 Schnorr signing on secp256k1. (Phase 5) */
    public static final short CAP_K1_SCHNORR = (short) 0x0002;

    /** Bit 2 — card supports Ed25519 EdDSA signing. (Phase 5) */
    public static final short CAP_ED25519 = (short) 0x0004;

    /** Bit 3 — card exposes a Secure Channel using AES-GCM. (Phase 2) */
    public static final short CAP_SC_GCM = (short) 0x0008;

    /** Bit 4 — card exposes a Secure Channel using AES-CBC + HMAC-SHA-256. (Phase 2) */
    public static final short CAP_SC_CBC_HMAC = (short) 0x0010;

    /** Bit 5 — card exposes the PKI personalisation flow. (Phase 3) */
    public static final short CAP_PKI = (short) 0x0020;

    /** Bit 6 — card supports {@code RESET_TO_FACTORY}. (Phase 1) */
    public static final short CAP_RESET_TO_FACTORY = (short) 0x0040;

    /*  TLV tags used inside GET_INFO. Single-byte tags in the application-private range so they
     *  never collide with ISO 7816-4 reserved primitive tags.
     */

    /** Tag 0x01 — protocol version (2 bytes, big-endian). */
    public static final byte TAG_PROTOCOL_VERSION = (byte) 0x01;

    /** Tag 0x02 — applet implementation version (2 bytes, big-endian). */
    public static final byte TAG_APPLET_VERSION = (byte) 0x02;

    /** Tag 0x03 — lifecycle state (1 byte). */
    public static final byte TAG_LIFECYCLE_STATE = (byte) 0x03;

    /** Tag 0x04 — capability bitmask (2 bytes, big-endian). */
    public static final byte TAG_CAPABILITIES = (byte) 0x04;

    /** Tag 0x05 — compressed authentikey public key (33 bytes). */
    public static final byte TAG_AUTHENTIKEY_PUBKEY = (byte) 0x05;

    /*  Sizes  */

    /** Length of an EC scalar (secp256k1 private key / hash / x-coordinate). */
    public static final short EC_SCALAR_LEN = (short) 32;

    /** Length of an uncompressed EC point ({@code 0x04 || x || y}). */
    public static final short EC_POINT_UNCOMPRESSED_LEN = (short) 65;

    /** Length of a compressed EC point ({@code 0x02|0x03 || x}). */
    public static final short EC_POINT_COMPRESSED_LEN = (short) 33;

    /*  Secure Channel sizes (Phase 2)  */

    /** AES key length (bytes) used by the Secure Channel — AES-256. */
    public static final short SC_KEY_LEN = (short) 32;

    /** AES-CBC block size and IV length (bytes). */
    public static final short SC_BLOCK_LEN = (short) 16;

    /** Truncated HMAC-SHA-256 tag length (bytes) used as the Secure Channel MAC. */
    public static final short SC_MAC_LEN = (short) 16;

    /*  PIN / PUK policy (Phase 3) — see docs/adr/0006-pin-policy.md  */

    /** Minimum PIN length in bytes. */
    public static final byte PIN_MIN_LEN = (byte) 4;

    /** Maximum PIN length in bytes. */
    public static final byte PIN_MAX_LEN = (byte) 16;

    /** Default PIN try-counter limit. */
    public static final byte PIN_RETRY_LIMIT = (byte) 3;

    /** Minimum PUK length in bytes. */
    public static final byte PUK_MIN_LEN = (byte) 8;

    /** Maximum PUK length in bytes. */
    public static final byte PUK_MAX_LEN = (byte) 32;

    /** Default PUK try-counter limit. */
    public static final byte PUK_RETRY_LIMIT = (byte) 5;

    /*  PKI personalisation (Phase 3)  */

    /** Maximum committed certificate size in EEPROM. Sized for a typical X.509v3 EE cert. */
    public static final short PKI_CERT_MAX_LEN = (short) 1024;

    /** Maximum payload length per IMPORT_PKI_CERT WRITE chunk. */
    public static final short PKI_CERT_CHUNK_MAX_LEN = (short) 200;

    /** {@code IMPORT_PKI_CERT} sub-command: stage the import with the declared total size. */
    public static final byte PKI_IMPORT_P1_INIT = (byte) 0x00;

    /** {@code IMPORT_PKI_CERT} sub-command: write a chunk at the given offset. */
    public static final byte PKI_IMPORT_P1_WRITE = (byte) 0x01;

    /** {@code IMPORT_PKI_CERT} sub-command: commit the staged size as the new cert length. */
    public static final byte PKI_IMPORT_P1_FINALIZE = (byte) 0x02;

    /*  Reset-to-factory policy  */

    /**
     * Number of consecutive un-interleaved {@code RESET_TO_FACTORY} invocations required to trigger
     * the wipe. See {@code docs/adr/0008-reset-to-factory-multi-step.md}.
     */
    public static final byte RESET_REQUIRED_INVOCATIONS = (byte) 4;
}
