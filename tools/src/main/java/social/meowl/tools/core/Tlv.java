/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.core;

import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.SequencedMap;

/**
 * Minimal Tag-Length-Value parser sized for the meowl applet's APDU surface.
 *
 * <p>The applet's TLV blobs (notably {@code GET_INFO}'s response) follow a deliberately constrained
 * shape: each entry is a single-byte tag, a single-byte unsigned length, and the value bytes. That
 * is sufficient for everything we encode today — no BER-TLV indefinite forms, no multi-byte tags,
 * no constructed types. Keeping the parser this strict means there is no decoder ambiguity for
 * auditors to reason about, and it can be implemented without {@link java.nio.ByteBuffer} or any
 * I/O dependency.
 *
 * <p>The parser preserves insertion order via {@link LinkedHashMap}, so duplicate-tag policy and
 * canonical TLV ordering can be enforced by simple equality on the result of {@link #parse(byte[])}
 * across two implementations.
 */
public final class Tlv {

    private Tlv() {}

    /** A parsed TLV entry. {@code value} is a copy — callers may mutate it freely. */
    public record Entry(byte tag, byte[] value) {

        public Entry {
            Objects.requireNonNull(value, "value");
        }

        public int unsignedTag() {
            return tag & 0xFF;
        }

        public int length() {
            return value.length;
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof Entry e && tag == e.tag && Arrays.equals(value, e.value);
        }

        @Override
        public int hashCode() {
            return 31 * Byte.hashCode(tag) + Arrays.hashCode(value);
        }

        @Override
        public String toString() {
            return "Tlv(%s, %s)".formatted(Hex.encodeByte(tag), Hex.encode(value));
        }
    }

    /**
     * Parses a sequence of {@code [tag(1) | len(1) | value(len)]} entries.
     *
     * @param blob the TLV blob; must not be {@code null}
     * @return an insertion-ordered map keyed by tag (boxed for Map compatibility); the value bytes
     *     are owned by the caller and are not aliased into {@code blob}
     * @throws IllegalArgumentException if the blob is malformed (truncated header, length runs past
     *     end of buffer, etc.)
     */
    public static SequencedMap<Byte, byte[]> parse(byte[] blob) {
        Objects.requireNonNull(blob, "blob");
        SequencedMap<Byte, byte[]> out = new LinkedHashMap<>();
        for (Entry entry : iterate(blob)) {
            out.put(entry.tag(), entry.value());
        }
        return out;
    }

    /**
     * Streaming variant of {@link #parse(byte[])}: returns an iterable that walks the blob without
     * materialising the result map. Useful for large blobs or for callers that want to reject
     * duplicate tags explicitly.
     */
    public static Iterable<Entry> iterate(byte[] blob) {
        Objects.requireNonNull(blob, "blob");
        return () -> new TlvIterator(blob);
    }

    /** Encodes a single TLV entry — small helper for tests and round-trip checks. */
    public static byte[] encode(byte tag, byte[] value) {
        Objects.requireNonNull(value, "value");
        if (value.length > 0xFF) {
            throw new IllegalArgumentException(
                    "Single-byte length cannot encode " + value.length + " bytes");
        }
        byte[] out = new byte[2 + value.length];
        out[0] = tag;
        out[1] = (byte) value.length;
        System.arraycopy(value, 0, out, 2, value.length);
        return out;
    }

    /**
     * Encodes a list of TLV entries by concatenating their wire forms in order. Convenience for
     * tests; the applet builds blobs incrementally so this is not a hot path.
     */
    public static byte[] encodeAll(Map<Byte, byte[]> entries) {
        Objects.requireNonNull(entries, "entries");
        int total = 0;
        for (Map.Entry<Byte, byte[]> e : entries.entrySet()) {
            total += 2 + e.getValue().length;
        }
        byte[] out = new byte[total];
        int pos = 0;
        for (Map.Entry<Byte, byte[]> e : entries.entrySet()) {
            byte[] tlv = encode(e.getKey(), e.getValue());
            System.arraycopy(tlv, 0, out, pos, tlv.length);
            pos += tlv.length;
        }
        return out;
    }

    private static final class TlvIterator implements Iterator<Entry> {
        private final byte[] blob;
        private int pos;

        TlvIterator(byte[] blob) {
            this.blob = blob;
            this.pos = 0;
        }

        @Override
        public boolean hasNext() {
            return pos < blob.length;
        }

        @Override
        public Entry next() {
            if (pos >= blob.length) throw new NoSuchElementException();
            if (pos + 2 > blob.length) {
                throw new IllegalArgumentException(
                        "Truncated TLV header at offset %d (need 2 bytes, have %d)"
                                .formatted(pos, blob.length - pos));
            }
            byte tag = blob[pos];
            int len = blob[pos + 1] & 0xFF;
            int valueStart = pos + 2;
            int valueEnd = valueStart + len;
            if (valueEnd > blob.length) {
                throw new IllegalArgumentException(
                        "TLV value at offset %d declared length %d but only %d bytes remain"
                                .formatted(pos, len, blob.length - valueStart));
            }
            byte[] value = Arrays.copyOfRange(blob, valueStart, valueEnd);
            pos = valueEnd;
            return new Entry(tag, value);
        }
    }
}
