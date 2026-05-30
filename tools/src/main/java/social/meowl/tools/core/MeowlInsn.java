/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.core;

import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Host-side mirror of the meowl applet INS bytes (the applet module targets Java 8 bytecode for the
 * JavaCard converter, which rejects {@code java.lang.Enum} and cannot expose enums to host code).
 * Each entry carries the wire byte, kebab-case CLI name, channel placement, and a one-line
 * description for {@code --help} / shell completion.
 *
 * <p><strong>Maintenance:</strong> any new applet INS byte must be mirrored here.
 */
public enum MeowlInsn {
    GET_INFO(
            (byte) 0x01,
            "get-info",
            Channel.OUTER,
            "Returns a TLV-encoded capability and identity profile."),
    GET_AUTHENTIKEY(
            (byte) 0x02,
            "get-authentikey",
            Channel.OUTER,
            "Returns the compressed authentikey public key."),
    RESET_TO_FACTORY(
            (byte) 0x03,
            "reset-to-factory",
            Channel.OUTER,
            "Wipes secrets after N consecutive un-interleaved invocations."),
    INIT_SECURE_CHANNEL(
            (byte) 0x10,
            "init-sc",
            Channel.OUTER,
            "ECDH handshake on secp256k1; establishes session keys."),
    OPEN_SECURE_CHANNEL(
            (byte) 0x11,
            "open-sc",
            Channel.OUTER,
            "Envelopes an inner APDU under the established session keys."),
    SETUP(
            (byte) 0x20,
            "setup",
            Channel.INNER,
            "Initial PIN/PUK provisioning; transitions UNINITIALIZED → SETUP_DONE."),
    VERIFY_PIN(
            (byte) 0x21, "verify-pin", Channel.INNER, "Unlocks session-scoped PIN authorisation."),
    CHANGE_PIN((byte) 0x22, "change-pin", Channel.INNER, "Rotates the user PIN."),
    CHANGE_PUK((byte) 0x23, "change-puk", Channel.INNER, "Rotates the unblock PUK."),
    UNBLOCK_PIN((byte) 0x24, "unblock-pin", Channel.INNER, "PUK-based PIN unblock."),
    EXPORT_PKI_PUBKEY(
            (byte) 0x30,
            "export-pki-pubkey",
            Channel.INNER,
            "Exports the authentikey public key for CSR construction."),
    SIGN_PKI_CSR(
            (byte) 0x31,
            "sign-pki-csr",
            Channel.INNER,
            "Signs a host-provided CSR digest with the authentikey."),
    IMPORT_PKI_CERT(
            (byte) 0x32,
            "import-pki-cert",
            Channel.INNER,
            "Chunked manufacturer certificate import."),
    EXPORT_PKI_CERT((byte) 0x33, "export-pki-cert", Channel.INNER, "Paged certificate export."),
    LOCK_PKI(
            (byte) 0x34,
            "lock-pki",
            Channel.INNER,
            "Finalises PKI personalisation; transitions to PERSONALIZED."),
    IMPORT_SEED(
            (byte) 0x40,
            "import-seed",
            Channel.INNER,
            "Installs a user-supplied master seed; transitions to SEEDED."),
    GENERATE_SEED(
            (byte) 0x41,
            "generate-seed",
            Channel.INNER,
            "Card-internal CSPRNG seed; raw seed returned once."),
    EXPORT_XPUB(
            (byte) 0x42,
            "export-xpub",
            Channel.INNER,
            "Derives a BIP-32 / SLIP-10 child and returns its public material."),
    SIGN_ECDSA_K1(
            (byte) 0x50,
            "sign-ecdsa-k1",
            Channel.INNER,
            "Signs a 32-byte digest with secp256k1 ECDSA (low-s normalised)."),
    SIGN_SCHNORR_K1(
            (byte) 0x51,
            "sign-schnorr-k1",
            Channel.INNER,
            "Signs a 32-byte digest with BIP-340 Schnorr on secp256k1."),
    SIGN_ED25519(
            (byte) 0x52,
            "sign-ed25519",
            Channel.INNER,
            "Signs an arbitrary-length message with Ed25519 (RFC 8032).");

    /** {@code CLA = 0x80} for every meowl-applet APDU per protocol.md §1. */
    public static final byte CLA_MEOWL = (byte) 0x80;

    /** Whether an INS travels on the bare CLA/INS surface or inside a Secure Channel envelope. */
    public enum Channel {
        OUTER,
        INNER;
    }

    private static final Map<String, MeowlInsn> BY_CLI_NAME =
            Arrays.stream(values())
                    .collect(Collectors.toUnmodifiableMap(MeowlInsn::cliName, Function.identity()));

    private static final Map<Byte, MeowlInsn> BY_VALUE =
            Arrays.stream(values())
                    .collect(Collectors.toUnmodifiableMap(MeowlInsn::value, Function.identity()));

    private final byte value;
    private final String cliName;
    private final Channel channel;
    private final String description;

    MeowlInsn(byte value, String cliName, Channel channel, String description) {
        this.value = value;
        this.cliName = cliName;
        this.channel = channel;
        this.description = description;
    }

    /** The byte transmitted on the APDU wire. */
    public byte value() {
        return value;
    }

    /** Lower-case kebab-case name used by the CLI / REPL command surface. */
    public String cliName() {
        return cliName;
    }

    /** Whether the INS is sent in clear or wrapped in a Secure Channel envelope. */
    public Channel channel() {
        return channel;
    }

    /** Whether the operation requires an open Secure Channel. */
    public boolean requiresSecureChannel() {
        return channel == Channel.INNER;
    }

    /** One-line human-readable description for {@code --help} and shell completion. */
    public String description() {
        return description;
    }

    /** Two-character uppercase hex form of the INS byte, e.g. {@code "01"}. */
    public String hex() {
        return Hex.encodeByte(value);
    }

    /** Looks up an INS by its kebab-case CLI name; case-sensitive. */
    public static Optional<MeowlInsn> ofCliName(String name) {
        Objects.requireNonNull(name, "name");
        return Optional.ofNullable(BY_CLI_NAME.get(name));
    }

    /** Looks up an INS by its wire byte value. */
    public static Optional<MeowlInsn> ofValue(byte value) {
        return Optional.ofNullable(BY_VALUE.get(value));
    }
}
