/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.applet.realcard.support;

import social.meowl.applet.Constants;

/**
 * Pure APDU-body encoders/decoders for the real-card integration suites — no card I/O and no Secure
 * Channel state, only byte layout. Card-driving helpers live in {@link CardLifecycle}.
 */
public final class ApduCodec {

    private ApduCodec() {}

    /** Encodes the SETUP body: {@code [pinLen | pin... | pukLen | puk...]}. */
    public static byte[] encodeSetup(byte[] pin, byte[] puk) {
        byte[] out = new byte[1 + pin.length + 1 + puk.length];
        out[0] = (byte) pin.length;
        System.arraycopy(pin, 0, out, 1, pin.length);
        out[1 + pin.length] = (byte) puk.length;
        System.arraycopy(puk, 0, out, 1 + pin.length + 1, puk.length);
        return out;
    }

    /** Length-prefix a single byte array: {@code [len | data...]}. */
    public static byte[] prefixLen(byte[] data) {
        byte[] out = new byte[1 + data.length];
        out[0] = (byte) data.length;
        System.arraycopy(data, 0, out, 1, data.length);
        return out;
    }

    /** Big-endian {@code short} → 2 bytes. */
    public static byte[] shortBE(short v) {
        return new byte[] {(byte) (v >> 8), (byte) (v & 0xFF)};
    }

    /**
     * Encodes an HD signing request body: {@code [depth | path... | payload]}, where each path
     * index is a big-endian 32-bit word. Shared by the ECDSA / Schnorr / Ed25519 signing suites.
     */
    public static byte[] encodeSignRequest(int[] path, byte[] payload) {
        byte[] out = new byte[1 + 4 * path.length + payload.length];
        out[0] = (byte) path.length;
        for (int i = 0; i < path.length; i++) {
            int idx = path[i];
            out[1 + i * 4] = (byte) (idx >>> 24);
            out[1 + i * 4 + 1] = (byte) (idx >>> 16);
            out[1 + i * 4 + 2] = (byte) (idx >>> 8);
            out[1 + i * 4 + 3] = (byte) idx;
        }
        System.arraycopy(payload, 0, out, 1 + 4 * path.length, payload.length);
        return out;
    }

    /**
     * Encodes an {@code EXPORT_XPUB} request body: {@code [curve | depth | path...]}, where each
     * path index is a big-endian 32-bit word.
     */
    public static byte[] encodeXpubRequest(byte curve, int[] path) {
        byte[] out = new byte[2 + 4 * path.length];
        out[0] = curve;
        out[1] = (byte) path.length;
        for (int i = 0; i < path.length; i++) {
            int idx = path[i];
            out[2 + i * 4] = (byte) (idx >>> 24);
            out[2 + i * 4 + 1] = (byte) (idx >>> 16);
            out[2 + i * 4 + 2] = (byte) (idx >>> 8);
            out[2 + i * 4 + 3] = (byte) idx;
        }
        return out;
    }

    /**
     * Walks the {@code GET_INFO} TLV blob and returns the 2-byte capabilities bitmap.
     *
     * @throws IllegalStateException if the capabilities TLV is absent.
     */
    public static short readCapabilities(byte[] tlv) {
        int i = 0;
        while (i < tlv.length) {
            int tag = tlv[i++] & 0xFF;
            int len = tlv[i++] & 0xFF;
            if (tag == (Constants.TAG_CAPABILITIES & 0xFF)) {
                return (short) (((tlv[i] & 0xFF) << 8) | (tlv[i + 1] & 0xFF));
            }
            i += len;
        }
        throw new IllegalStateException("capabilities TLV not found");
    }
}
