// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.qntx.card.host.Bip32;
import org.qntx.card.host.Bip340;
import org.qntx.card.host.Crypto;
import org.qntx.card.host.Ecdsa;
import org.qntx.card.host.Ed25519;
import org.qntx.card.host.Response;
import org.qntx.card.host.Session;
import org.qntx.card.host.Slip10;
import org.qntx.card.host.Wei25519Map;
import org.qntx.card.sim.Card;
import org.qntx.card.sim.Fault;
import org.qntx.card.sim.Rng;
import org.qntx.card.tests.Vecs;

/**
 * The signing differential of architecture §14.5 G3: random keys, paths and inputs, every card
 * signature re-verified by the independent host helpers (BouncyCastle) — the card's PUBLIC_KEY is
 * not the oracle. Every verified signature is appended to {@code
 * tests/build/differential/signatures.json} in the {@code verify.ts} format, which the noble
 * differential step then checks a second time.
 *
 * <p>Counts: {@code qntx.differential} signatures per scheme (default 10 000), a fresh random
 * 64-byte seed every 1 000.
 */
final class SignDifferentialTest {

    private static final int COUNT = Integer.getInteger("qntx.differential", 10_000);
    private static final int SEED_EVERY = 1_000;
    private static final Path OUT =
            Path.of(
                    System.getProperty(
                            "qntx.differential.out", "build/differential/signatures.json"));

    private Card card;
    private Session session;
    private byte[] seed;
    private final StringBuilder ecdsa = new StringBuilder();
    private final StringBuilder bip340 = new StringBuilder();
    private final StringBuilder ed25519 = new StringBuilder();
    private int ecdsaCount;
    private int bip340Count;
    private int edCount;

    @AfterEach
    void disarm() {
        Fault.reset();
        Rng.reset();
    }

    /** A fresh card loaded with a random seed whose BIP-32 master is valid, session verified. */
    private void loadRandomSeed() throws Exception {
        card = Vecs.blankSelf();
        byte[] s = new byte[64];
        BigInteger k;
        do {
            Vecs.RND.nextBytes(s);
            k = new BigInteger(1, Bip32.master(s).privateKey());
        } while (k.signum() <= 0 || k.compareTo(Crypto.N) >= 0);
        seed = s;
        session = Vecs.open(card);
        byte[] create = new byte[96];
        System.arraycopy(Vecs.accessHash(), 0, create, 0, 32);
        System.arraycopy(seed, 0, create, 32, 64);
        assertEquals(0x9000, Vecs.roundtrip(card, session, 0x21, 1, 0, create).sw(), "CREATE");
        session = Vecs.open(card);
        assertEquals(0x9000, Vecs.roundtrip(card, session, 0x22, 0, 0, Vecs.accessHash()).sw());
    }

    /** A random wire path: depth 1–10, each index hardened with probability ½. */
    private static byte[] wirePath() {
        int depth = 1 + Vecs.RND.nextInt(10);
        byte[] wire = new byte[1 + 4 * depth];
        wire[0] = (byte) depth;
        for (int i = 0; i < depth; i++) {
            int index = Vecs.RND.nextInt() & 0x7FFFFFFF;
            if (Vecs.RND.nextBoolean()) {
                index |= 0x80000000;
            }
            wire[1 + 4 * i] = (byte) (index >>> 24);
            wire[2 + 4 * i] = (byte) (index >>> 16);
            wire[3 + 4 * i] = (byte) (index >>> 8);
            wire[4 + 4 * i] = (byte) index;
        }
        return wire;
    }

    /** A random all-hardened wire path (SLIP-10) of depth 1–10. */
    private static byte[] wirePathHardened() {
        byte[] wire = wirePath();
        for (int i = 0; i < (wire[0] & 0xFF); i++) {
            wire[1 + 4 * i] |= (byte) 0x80;
        }
        return wire;
    }

    /** {@code m/…} of a wire path, for the host derivation. */
    private static String pathString(byte[] wire) {
        StringBuilder p = new StringBuilder("m");
        int depth = wire[0] & 0xFF;
        for (int i = 0; i < depth; i++) {
            long index =
                    ((wire[1 + 4 * i] & 0xFFL) << 24)
                            | ((wire[2 + 4 * i] & 0xFFL) << 16)
                            | ((wire[3 + 4 * i] & 0xFFL) << 8)
                            | (wire[4 + 4 * i] & 0xFFL);
            p.append('/').append(index & 0x7FFFFFFFL);
            if ((index & 0x80000000L) != 0) {
                p.append('\'');
            }
        }
        return p.toString();
    }

    private Response inner(int ins, int p1, byte[] data) throws Exception {
        return Vecs.roundtrip(card, session, ins, p1, 0, data);
    }

    private static String hex(byte[] b) {
        return HexFormat.of().formatHex(b);
    }

    /** The §12.3 message expansion of {@code verify.ts}: SHA-512(seed ‖ u32be(i)) blocks. */
    private static byte[] expandMessage(byte[] seedBytes, int length) {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-512");
            byte[] out = new byte[length];
            byte[] in = new byte[36];
            System.arraycopy(seedBytes, 0, in, 0, 32);
            for (int i = 0, have = 0; have < length; i++, have += 64) {
                in[32] = (byte) (i >>> 24);
                in[33] = (byte) (i >>> 16);
                in[34] = (byte) (i >>> 8);
                in[35] = (byte) i;
                byte[] block = sha.digest(in);
                System.arraycopy(block, 0, out, have, Math.min(64, length - have));
            }
            return out;
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Feeds {@code stream} in update chunks of uniform 1–236 bytes and finishes with the rest. */
    private Response feedStream(byte[] stream) throws Exception {
        int off = 0;
        while (stream.length - off > 236) {
            int len = 1 + Vecs.RND.nextInt(236);
            Response r = inner(0x33, 1, Arrays.copyOfRange(stream, off, off + len));
            assertEquals(0x9000, r.sw(), "update at " + off);
            off += len;
        }
        return inner(0x33, 2, Arrays.copyOfRange(stream, off, stream.length));
    }

    private void ecdsaRun() throws Exception {
        byte[] wire = wirePath();
        Bip32.Node node = Bip32.derive(seed, pathString(wire));
        byte[] pub65 = Crypto.publicKey(new BigInteger(1, node.privateKey()));
        byte[] digest = new byte[32];
        Vecs.RND.nextBytes(digest);
        byte[] data = new byte[32 + wire.length];
        System.arraycopy(digest, 0, data, 0, 32);
        System.arraycopy(wire, 0, data, 32, wire.length);
        Response r = inner(0x31, 0, data);
        assertEquals(0x9000, r.sw());
        assertTrue(Ecdsa.verify(pub65, digest, r.data()), "ecdsa " + pathString(wire));
        if (ecdsaCount++ > 0) {
            ecdsa.append(',');
        }
        ecdsa.append("{\"publicKey\":\"")
                .append(hex(node.publicKey()))
                .append("\",\"digest\":\"")
                .append(hex(digest))
                .append("\",\"signature\":\"")
                .append(hex(r.data()))
                .append("\"}");
    }

    private void bip340Run() throws Exception {
        byte[] wire = wirePath();
        Bip32.Node node = Bip32.derive(seed, pathString(wire));
        byte[] internal = Crypto.publicKey(new BigInteger(1, node.privateKey()));
        byte[] message = new byte[32];
        Vecs.RND.nextBytes(message);
        byte[] tweak = new byte[32];
        if (Vecs.RND.nextInt(10) == 0) {
            // one in ten untweaked
        } else {
            do {
                Vecs.RND.nextBytes(tweak);
            } while (new BigInteger(1, tweak).compareTo(Crypto.N) >= 0);
        }
        byte[] outputKey = Bip340.outputKey(internal, tweak);
        byte[] data = new byte[64 + wire.length];
        System.arraycopy(message, 0, data, 0, 32);
        System.arraycopy(tweak, 0, data, 32, 32);
        System.arraycopy(wire, 0, data, 64, wire.length);
        Response r = inner(0x32, 0, data);
        assertEquals(0x9000, r.sw());
        assertTrue(Bip340.verify(outputKey, message, r.data()), "bip340 " + pathString(wire));
        if (bip340Count++ > 0) {
            bip340.append(',');
        }
        bip340.append("{\"outputKey\":\"")
                .append(hex(outputKey))
                .append("\",\"message\":\"")
                .append(hex(message))
                .append("\",\"signature\":\"")
                .append(hex(r.data()))
                .append("\"}");
    }

    private void ed25519Run() throws Exception {
        byte[] wire = wirePathHardened();
        Slip10.Node node = Slip10.derive(seed, pathString(wire));
        byte[] encodedA = Wei25519Map.encode(Slip10.wei(node.privateKey()));
        byte[] messageSeed = new byte[32];
        Vecs.RND.nextBytes(messageSeed);
        int messageLength = Vecs.RND.nextInt(8193);
        byte[] message = expandMessage(messageSeed, messageLength);
        Response begin = inner(0x33, 0, wire);
        assertEquals(0x9000, begin.sw());
        byte[] encodedR = Wei25519Map.encode(begin.data());
        Response fin = feedStream(Ed25519.stream(encodedR, encodedA, message));
        assertEquals(0x9000, fin.sw());
        byte[] signature = Ed25519.signature(encodedR, fin.data());
        assertTrue(Ed25519.verify(encodedA, message, signature), "ed25519 " + pathString(wire));
        if (edCount++ > 0) {
            ed25519.append(',');
        }
        ed25519.append("{\"publicKey\":\"")
                .append(hex(encodedA))
                .append("\",\"messageSeed\":\"")
                .append(hex(messageSeed))
                .append("\",\"messageLength\":")
                .append(messageLength)
                .append(",\"signature\":\"")
                .append(hex(signature))
                .append("\"}");
    }

    @Test
    void differential() throws Exception {
        for (int i = 0; i < COUNT; i++) {
            if (i % SEED_EVERY == 0) {
                loadRandomSeed();
            }
            ecdsaRun();
            bip340Run();
            ed25519Run();
        }
        writeFile();
    }

    private void writeFile() {
        try {
            Files.createDirectories(OUT.getParent());
            String json =
                    "{\"ecdsa\":["
                            + ecdsa
                            + "]"
                            + ",\"bip340\":["
                            + bip340
                            + "]"
                            + ",\"ed25519\":["
                            + ed25519
                            + "]}";
            Files.writeString(OUT, json, StandardCharsets.UTF_8);
            System.out.println(
                    "differential: wrote "
                            + OUT.toAbsolutePath()
                            + " (ecdsa "
                            + ecdsaCount
                            + ", bip340 "
                            + bip340Count
                            + ", ed25519 "
                            + edCount
                            + ")");
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
