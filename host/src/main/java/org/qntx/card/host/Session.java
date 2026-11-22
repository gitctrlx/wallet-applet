// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.host;

import java.util.Arrays;

/**
 * The host side of the §8 session: command records (§8.3) and response records (§8.4) with the
 * 16-bit counter shared by a command and its response. A record failure throws {@link
 * SessionBrokenException} and ends the session; {@link #close} overwrites the keys.
 */
public final class Session {
    private final byte[] a;
    private final byte[] cert;
    private final byte[] kce;
    private final byte[] kcm;
    private final byte[] kre;
    private final byte[] krm;
    private int ctr;
    private boolean closed;

    /** A session from fixed keys and counter — for vector tests and {@link Open#response}. */
    public Session(byte[] a, byte[] cert, byte[] kce, byte[] kcm, byte[] kre, byte[] krm, int ctr) {
        this.a = a.clone();
        this.cert = cert.clone();
        this.kce = kce.clone();
        this.kcm = kcm.clone();
        this.kre = kre.clone();
        this.krm = krm.clone();
        this.ctr = ctr;
    }

    /** {@code A}, the compressed identity key this session was authenticated as (§8.1). */
    public byte[] identity() {
        return a.clone();
    }

    /** The card's certificate (§5.2). */
    public byte[] cert() {
        return cert.clone();
    }

    /** The current record counter. */
    public int counter() {
        return ctr;
    }

    /** Whether the session ended (record failure, {@code ctr = 0xFFFF} or {@link #close}). */
    public boolean closed() {
        return closed;
    }

    /**
     * Builds the command record APDU for {@code INS ‖ P1 ‖ P2 ‖ data} (§8.3), {@code |data| ≤ 236}.
     */
    public byte[] wrap(int ins, int p1, int p2, byte[] data) throws SessionBrokenException {
        if (closed) {
            throw new SessionBrokenException("session is closed");
        }
        if (data.length > 236) {
            throw new IllegalArgumentException("record data must be at most 236 bytes");
        }
        byte[] plain = new byte[3 + data.length];
        plain[0] = (byte) ins;
        plain[1] = (byte) p1;
        plain[2] = (byte) p2;
        System.arraycopy(data, 0, plain, 3, data.length);
        byte[] iv = Crypto.aesBlock(kce, ivSeed(0x01));
        byte[] ct = Crypto.aesCbc(kce, iv, Crypto.m2pad(plain), true);
        byte[] tag = new byte[8];
        System.arraycopy(Crypto.cmac(kcm, Crypto.u16(ctr), ct), 0, tag, 0, 8);
        byte[] apdu = new byte[5 + ct.length + 8 + 1];
        apdu[0] = (byte) 0x80;
        apdu[1] = 0x12;
        apdu[4] = (byte) (ct.length + 8);
        System.arraycopy(ct, 0, apdu, 5, ct.length);
        System.arraycopy(tag, 0, apdu, 5 + ct.length, 8);
        return apdu;
    }

    /**
     * Validates and opens a response record (§8.4): outer {@code 9000}, tag in constant time before
     * decrypting, {@code unM2}, plaintext at least {@code data ‖ SW} — else the session is
     * abandoned.
     */
    public Response unwrap(byte[] rapdu) throws SessionBrokenException {
        if (closed) {
            throw new SessionBrokenException("session is closed");
        }
        if (rapdu.length < 2
                || ((rapdu[rapdu.length - 2] & 0xFF) << 8 | rapdu[rapdu.length - 1] & 0xFF)
                        != 0x9000) {
            closed = true;
            throw new SessionBrokenException("outer status is not 9000");
        }
        int bodyLen = rapdu.length - 2;
        if (bodyLen < 24 || (bodyLen - 8) % 16 != 0) {
            closed = true;
            throw new SessionBrokenException("bad record length");
        }
        byte[] ct = Arrays.copyOf(rapdu, bodyLen - 8);
        byte[] tag = Arrays.copyOfRange(rapdu, bodyLen - 8, bodyLen);
        byte[] expected = new byte[8];
        System.arraycopy(Crypto.cmac(krm, Crypto.u16(ctr), ct), 0, expected, 0, 8);
        if (!Crypto.equalConstantTime(expected, tag)) {
            closed = true;
            throw new SessionBrokenException("record tag mismatch");
        }
        byte[] iv = Crypto.aesBlock(kre, ivSeed(0x02));
        byte[] plain = Crypto.m2unpad(Crypto.aesCbc(kre, iv, ct, false));
        if (plain == null || plain.length < 2) {
            closed = true;
            throw new SessionBrokenException("bad record padding");
        }
        int sw = (plain[plain.length - 2] & 0xFF) << 8 | plain[plain.length - 1] & 0xFF;
        int sentCtr = ctr;
        ctr++;
        if (sentCtr == 0xFFFF) {
            closed = true;
        }
        return new Response(Arrays.copyOf(plain, plain.length - 2), sw);
    }

    /** Ends the session and overwrites the keys. */
    public void close() {
        Arrays.fill(kce, (byte) 0);
        Arrays.fill(kcm, (byte) 0);
        Arrays.fill(kre, (byte) 0);
        Arrays.fill(krm, (byte) 0);
        closed = true;
    }

    private byte[] ivSeed(int first) {
        byte[] seed = new byte[16];
        seed[0] = (byte) first;
        byte[] c = Crypto.u16(ctr);
        seed[14] = c[0];
        seed[15] = c[1];
        return seed;
    }
}
