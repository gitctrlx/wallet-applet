// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.host;

/**
 * Derivation paths of spec/protocol.md §9.2: the wire form is {@code depth(1) ‖ u32(index₁) ‖ … ‖
 * u32(index_depth)} with {@code depth ∈ [1, 10]}; a hardened index {@code i'} is {@code i + 2³¹}.
 * The string form is {@code m/44'/60'/0'/0/0}; the master path {@code "m"} has depth 0 and no wire
 * form.
 */
public final class Paths {
    static final long HARDENED = 0x80000000L;

    private Paths() {}

    /**
     * {@code m/44'/60'/0'/0/0} → {@code depth(1) ‖ u32(index)…}. The master path {@code "m"}
     * encodes as the single byte {@code 0x00}.
     *
     * @throws IllegalArgumentException on a malformed path or a depth outside {@code [1, 10]}
     */
    public static byte[] wire(String path) {
        long[] indices = indices(path);
        if (indices.length == 0) {
            return new byte[1];
        }
        byte[] out = new byte[1 + 4 * indices.length];
        out[0] = (byte) indices.length;
        for (int i = 0; i < indices.length; i++) {
            out[1 + 4 * i] = (byte) (indices[i] >>> 24);
            out[2 + 4 * i] = (byte) (indices[i] >>> 16);
            out[3 + 4 * i] = (byte) (indices[i] >>> 8);
            out[4 + 4 * i] = (byte) indices[i];
        }
        return out;
    }

    /** The indices of {@code path} as unsigned 32-bit values; empty for {@code "m"}. */
    static long[] indices(String path) {
        if (path == null || path.equals("m")) {
            return new long[0];
        }
        if (!path.startsWith("m/")) {
            throw new IllegalArgumentException("path must start with m/: " + path);
        }
        String[] parts = path.substring(2).split("/", -1);
        if (parts.length > 10) {
            throw new IllegalArgumentException("path depth must be in [1, 10]: " + path);
        }
        long[] out = new long[parts.length];
        for (int i = 0; i < parts.length; i++) {
            String p = parts[i];
            long index = 0;
            if (p.endsWith("'")) {
                index = HARDENED;
                p = p.substring(0, p.length() - 1);
            }
            if (p.isEmpty() || p.length() > 10 || !p.chars().allMatch(Character::isDigit)) {
                throw new IllegalArgumentException("bad path index: " + path);
            }
            long v = Long.parseLong(p);
            if (v >= HARDENED) {
                throw new IllegalArgumentException("path index too large: " + path);
            }
            out[i] = index + v;
        }
        return out;
    }

    /**
     * {@code depth(1) ‖ u32(index)…} → {@code "m/44'/60'/0'/0/0"}; the single byte {@code 0x00}
     * formats as {@code "m"}.
     *
     * @throws IllegalArgumentException when {@code wire} is empty or its length is not {@code 1 +
     *     4·depth}
     */
    public static String format(byte[] wire) {
        if (wire == null || wire.length == 0 || wire.length != 1 + 4 * (wire[0] & 0xFF)) {
            throw new IllegalArgumentException("bad path wire form");
        }
        int depth = wire[0] & 0xFF;
        if (depth == 0) {
            return "m";
        }
        StringBuilder out = new StringBuilder("m");
        for (int i = 0; i < depth; i++) {
            long index =
                    ((long) (wire[1 + 4 * i] & 0xFF) << 24)
                            | ((wire[2 + 4 * i] & 0xFF) << 16)
                            | ((wire[3 + 4 * i] & 0xFF) << 8)
                            | (wire[4 + 4 * i] & 0xFF);
            out.append('/');
            if (index >= HARDENED) {
                out.append(index - HARDENED).append('\'');
            } else {
                out.append(index);
            }
        }
        return out.toString();
    }
}
