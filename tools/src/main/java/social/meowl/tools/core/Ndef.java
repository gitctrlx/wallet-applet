/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.core;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * Host-side codec for the single-record NFC Forum NDEF tag the meowl card serves.
 *
 * <p>It encodes and decodes the on-card NDEF elementary file, which is an {@code NLEN}-prefixed
 * NDEF message holding exactly one well-known URI record (RTD {@code "U"}). The URI abbreviation
 * table (RFC-style prefix codes, e.g. {@code 0x04 = "https://"}) is applied on encode (longest
 * match) and expanded on decode, matching what a phone's NFC stack does.
 *
 * <p>Only short records ({@code SR}, payload ≤ 255 bytes) are produced; the meowl content
 * convention ({@code https://meowl.social/p/<nprofile>}) is comfortably within that bound.
 */
public final class Ndef {

    /** NFC Forum URI Record Type Definition abbreviation table (prefix code → expansion). */
    private static final String[] URI_PREFIXES = {
        "", // 0x00
        "http://www.", // 0x01
        "https://www.", // 0x02
        "http://", // 0x03
        "https://", // 0x04
        "tel:", // 0x05
        "mailto:", // 0x06
        "ftp://anonymous:anonymous@", // 0x07
        "ftp://ftp.", // 0x08
        "ftps://", // 0x09
        "sftp://", // 0x0A
        "smb://", // 0x0B
        "nfs://", // 0x0C
        "ftp://", // 0x0D
        "dav://", // 0x0E
        "news:", // 0x0F
        "telnet://", // 0x10
        "imap:", // 0x11
        "rtsp://", // 0x12
        "urn:", // 0x13
        "pop:", // 0x14
        "sip:", // 0x15
        "sips:", // 0x16
        "tftp:", // 0x17
        "btspp://", // 0x18
        "btl2cap://", // 0x19
        "btgoep://", // 0x1A
        "tcpobex://", // 0x1B
        "irdaobex://", // 0x1C
        "file://", // 0x1D
        "urn:epc:id:", // 0x1E
        "urn:epc:tag:", // 0x1F
        "urn:epc:pat:", // 0x20
        "urn:epc:raw:", // 0x21
        "urn:epc:", // 0x22
        "urn:nfc:" // 0x23
    };

    /** NDEF record header: MB | ME | SR with TNF = NFC Forum well-known type. */
    private static final byte FLAGS_WELL_KNOWN_SR = (byte) 0xD1;

    /** RTD type {@code 'U'} (URI record). */
    private static final byte TYPE_URI = 0x55;

    private static final int MAX_SR_PAYLOAD = 255;

    private Ndef() {}

    /**
     * Encodes a URI into the on-card NDEF file image: a 2-byte {@code NLEN} length prefix followed
     * by one short URI record, with the longest matching abbreviation prefix applied.
     *
     * @throws IllegalArgumentException if the URI is empty or does not fit in a short record
     */
    public static byte[] encodeUriFile(String uri) {
        Objects.requireNonNull(uri, "uri");
        if (uri.isEmpty()) {
            throw new IllegalArgumentException("URI must not be empty");
        }

        int code = 0;
        String rest = uri;
        for (int i = 1; i < URI_PREFIXES.length; i++) {
            String prefix = URI_PREFIXES[i];
            if (uri.startsWith(prefix) && prefix.length() > URI_PREFIXES[code].length()) {
                code = i;
                rest = uri.substring(prefix.length());
            }
        }

        byte[] tail = rest.getBytes(StandardCharsets.UTF_8);
        int payloadLen = 1 + tail.length; // prefix code byte + remainder
        if (payloadLen > MAX_SR_PAYLOAD) {
            throw new IllegalArgumentException(
                    "URI too long for a short NDEF record: " + payloadLen + " > " + MAX_SR_PAYLOAD);
        }

        int recordLen = 4 + payloadLen; // flags + typeLen + payloadLen + type + payload
        byte[] file = new byte[2 + recordLen];
        int i = 0;
        file[i++] = (byte) (recordLen >> 8);
        file[i++] = (byte) recordLen; // NLEN
        file[i++] = FLAGS_WELL_KNOWN_SR;
        file[i++] = 0x01; // type length
        file[i++] = (byte) payloadLen;
        file[i++] = TYPE_URI;
        file[i++] = (byte) code;
        System.arraycopy(tail, 0, file, i, tail.length);
        return file;
    }

    /**
     * Decodes an on-card NDEF file image (as produced by {@link #encodeUriFile}) back into its URI,
     * expanding the abbreviation prefix.
     *
     * @throws IllegalArgumentException if the bytes are not a single short URI record
     */
    public static String decodeUriFile(byte[] file) {
        Objects.requireNonNull(file, "file");
        if (file.length < 2) {
            throw new IllegalArgumentException("NDEF file shorter than the NLEN prefix");
        }
        int nlen = ((file[0] & 0xFF) << 8) | (file[1] & 0xFF);
        if (nlen < 5 || 2 + nlen > file.length) {
            throw new IllegalArgumentException("NLEN " + nlen + " inconsistent with file length");
        }
        int flags = file[2] & 0xFF;
        if ((flags & 0x07) != 0x01) {
            throw new IllegalArgumentException("not a well-known TNF record");
        }
        if ((flags & 0x10) == 0) {
            throw new IllegalArgumentException("only short records are supported");
        }
        int typeLen = file[3] & 0xFF;
        int payloadLen = file[4] & 0xFF;
        if (typeLen != 1 || file[5] != TYPE_URI) {
            throw new IllegalArgumentException("not a URI ('U') record");
        }
        if (payloadLen < 1 || 6 + payloadLen > 2 + nlen) {
            throw new IllegalArgumentException("URI payload length out of range");
        }
        int code = file[6] & 0xFF;
        String prefix = code < URI_PREFIXES.length ? URI_PREFIXES[code] : "";
        String rest = new String(file, 7, payloadLen - 1, StandardCharsets.UTF_8);
        return prefix + rest;
    }
}
