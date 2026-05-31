/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.core;

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.SequencedMap;

/**
 * Decoded form of the {@code GET_INFO} TLV response (protocol.md §5). A single source of truth that
 * both {@code meowl info} and the shell's {@code info} command render, so the two never drift.
 *
 * <p>{@link #parse(byte[])} is strict: the applet contract fixes all five tags and their lengths,
 * so a missing or mis-sized tag is a contract violation surfaced as {@link
 * IllegalArgumentException} rather than silently tolerated.
 */
public record MeowlInfo(
        Version protocolVersion,
        Version appletVersion,
        int lifecycleCode,
        int capabilityBits,
        byte[] authentikey) {

    public static final byte TAG_PROTOCOL_VERSION = 0x01;
    public static final byte TAG_APPLET_VERSION = 0x02;
    public static final byte TAG_LIFECYCLE = 0x03;
    public static final byte TAG_CAPABILITIES = 0x04;
    public static final byte TAG_AUTHENTIKEY = 0x05;

    public MeowlInfo {
        Objects.requireNonNull(protocolVersion, "protocolVersion");
        Objects.requireNonNull(appletVersion, "appletVersion");
        Objects.requireNonNull(authentikey, "authentikey");
        authentikey = authentikey.clone();
    }

    /** A two-byte {@code major.minor} version, as carried by tags {@code 0x01} / {@code 0x02}. */
    public record Version(int major, int minor) {
        @Override
        public String toString() {
            return major + "." + minor;
        }
    }

    /**
     * Resolves the lifecycle code to a known state, or empty for a code this build does not know.
     */
    public Optional<MeowlLifecycle> lifecycle() {
        return MeowlLifecycle.ofCode(lifecycleCode);
    }

    /** Lifecycle name, falling back to {@code UNKNOWN(0xNN)} for an unrecognised code. */
    public String lifecycleName() {
        return lifecycle().map(Enum::name).orElse("UNKNOWN(0x%02X)".formatted(lifecycleCode));
    }

    /** The capabilities advertised by {@link #capabilityBits()}, in ascending mask order. */
    public List<MeowlCapability> capabilities() {
        return MeowlCapability.decode(capabilityBits);
    }

    /** Defensive copy of the compressed authentikey public key. */
    @Override
    public byte[] authentikey() {
        return authentikey.clone();
    }

    /** Parses a {@code GET_INFO} TLV blob. */
    public static MeowlInfo parse(byte[] tlvBlob) {
        Objects.requireNonNull(tlvBlob, "tlvBlob");
        SequencedMap<Byte, byte[]> tlv = Tlv.parse(tlvBlob);
        return new MeowlInfo(
                version(tlv, TAG_PROTOCOL_VERSION, "protocol version"),
                version(tlv, TAG_APPLET_VERSION, "applet version"),
                singleByte(tlv, TAG_LIFECYCLE, "lifecycle"),
                u16(tlv, TAG_CAPABILITIES, "capabilities"),
                requiredTag(tlv, TAG_AUTHENTIKEY, "authentikey"));
    }

    private static Version version(SequencedMap<Byte, byte[]> tlv, byte tag, String label) {
        byte[] v = exactLength(tlv, tag, 2, label);
        return new Version(v[0] & 0xFF, v[1] & 0xFF);
    }

    private static int singleByte(SequencedMap<Byte, byte[]> tlv, byte tag, String label) {
        return exactLength(tlv, tag, 1, label)[0] & 0xFF;
    }

    private static int u16(SequencedMap<Byte, byte[]> tlv, byte tag, String label) {
        byte[] v = exactLength(tlv, tag, 2, label);
        return ((v[0] & 0xFF) << 8) | (v[1] & 0xFF);
    }

    private static byte[] requiredTag(SequencedMap<Byte, byte[]> tlv, byte tag, String label) {
        byte[] v = tlv.get(tag);
        if (v == null) {
            throw new IllegalArgumentException(
                    "GET_INFO is missing the %s tag (0x%02X)".formatted(label, tag & 0xFF));
        }
        return v;
    }

    private static byte[] exactLength(
            SequencedMap<Byte, byte[]> tlv, byte tag, int expected, String label) {
        byte[] v = requiredTag(tlv, tag, label);
        if (v.length != expected) {
            throw new IllegalArgumentException(
                    "GET_INFO %s tag (0x%02X) must be %d byte(s), got %d"
                            .formatted(label, tag & 0xFF, expected, v.length));
        }
        return v;
    }
}
