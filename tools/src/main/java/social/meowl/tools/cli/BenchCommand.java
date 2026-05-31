/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.cli;

import apdu4j.core.APDUBIBO;
import apdu4j.core.BIBOException;
import java.io.PrintStream;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Option;
import picocli.CommandLine.ParentCommand;
import social.meowl.tools.card.MeowlCard;
import social.meowl.tools.core.MeowlInsn;
import social.meowl.tools.proto.SecureChannelClient;
import social.meowl.tools.transport.CardTransport;

/**
 * {@code meowl bench} — measures p50 / p95 / p99 wall-clock latency of the applet's main signing
 * and HD-walk paths on a real card. Assumes the card is in the {@code SEEDED} lifecycle state.
 *
 * <p>Runs a fresh Secure Channel handshake, performs a {@code VERIFY_PIN} with the supplied PIN,
 * then times each operation with {@link #warmup} warm-up iterations followed by {@link #samples}
 * timed iterations. Text mode prints a p50/p95/p99 table to stdout (per-op progress on stderr);
 * {@code --json} emits a structured object for regression harnesses.
 */
@Command(
        name = "bench",
        mixinStandardHelpOptions = true,
        description =
                "Measures p50/p95/p99 latency of sign + HD-walk paths on a real card. Card"
                        + " must be SEEDED + PIN-validated.")
public final class BenchCommand implements Callable<Integer> {

    @ParentCommand private MeowlCli parent;

    @Mixin public AidOption aid = new AidOption();

    @Option(
            names = {"-p", "--pin"},
            required = true,
            paramLabel = "PIN",
            description = "User PIN to authenticate before benchmarking (4-32 ASCII bytes).")
    public String pin;

    @Option(
            names = "--warmup",
            paramLabel = "N",
            description = "Warm-up iterations per operation (default: ${DEFAULT-VALUE}).",
            defaultValue = "5")
    public int warmup;

    @Option(
            names = "--samples",
            paramLabel = "N",
            description = "Timed iterations per operation (default: ${DEFAULT-VALUE}).",
            defaultValue = "30")
    public int samples;

    @Option(
            names = "--include",
            paramLabel = "OP[,OP...]",
            description =
                    "Comma-separated subset of {ecdsa,schnorr,ed25519,xpub-k1,xpub-ed25519,sc}."
                            + " Default: all.",
            split = ",")
    public String[] include;

    private static final SecureRandom RANDOM = new SecureRandom();

    /** secp256k1 BIP-44: m/44'/0'/0'/0/0 — Bitcoin first receive. */
    private static final int[] PATH_K1 = {
        0x8000002C, 0x80000000, 0x80000000, 0x00000000, 0x00000000
    };

    /** Ed25519 SLIP-44: m/44'/501'/0'/0' — Solana account 0. */
    private static final int[] PATH_ED25519 = {0x8000002C, 0x800001F5, 0x80000000, 0x80000000};

    @Override
    public Integer call() {
        Map<String, Stats> results =
                CardTransport.run(parent.globalOptions.toReaderPreferences(), this::runOnCard);
        if (parent.globalOptions.json) {
            JsonOutput.write(System.out, toJsonModel(results));
        } else {
            renderText(System.out, results);
        }
        return 0;
    }

    private Map<String, Stats> runOnCard(APDUBIBO bibo) throws BIBOException {
        long t0 = System.nanoTime();
        MeowlCard card = new MeowlCard(bibo, aid.bytes());
        byte[] authentikey = card.getAuthentikey();
        SecureChannelClient sc = SecureChannelClient.open(bibo, authentikey);
        verifyPin(sc, pin.getBytes());
        progress(
                "setup complete in %.1fs (SELECT + GET_AUTHENTIKEY + handshake + VERIFY_PIN);"
                        + " warmup=%d samples=%d per op",
                (System.nanoTime() - t0) / 1e9, warmup, samples);

        Map<String, Stats> out = new LinkedHashMap<>();
        if (shouldRun("ecdsa")) {
            byte[] payload = signPayloadK1();
            out.put(
                    "SIGN_ECDSA_K1",
                    benchOp(
                            "SIGN_ECDSA_K1",
                            () -> sendInner(sc, MeowlInsn.SIGN_ECDSA_K1.value(), payload)));
        }
        if (shouldRun("schnorr")) {
            byte[] payload = signPayloadK1();
            out.put(
                    "SIGN_SCHNORR_K1",
                    benchOp(
                            "SIGN_SCHNORR_K1",
                            () -> sendInner(sc, MeowlInsn.SIGN_SCHNORR_K1.value(), payload)));
        }
        if (shouldRun("ed25519")) {
            byte[] payload = signPayloadEd25519();
            out.put(
                    "SIGN_ED25519",
                    benchOp(
                            "SIGN_ED25519",
                            () -> sendInner(sc, MeowlInsn.SIGN_ED25519.value(), payload)));
        }
        if (shouldRun("xpub-k1")) {
            byte[] payload = exportXpubPayload((byte) 0x00, PATH_K1);
            out.put(
                    "EXPORT_XPUB_K1",
                    benchOp(
                            "EXPORT_XPUB_K1",
                            () -> sendInner(sc, MeowlInsn.EXPORT_XPUB.value(), payload)));
        }
        if (shouldRun("xpub-ed25519")) {
            byte[] payload = exportXpubPayload((byte) 0x01, PATH_ED25519);
            out.put(
                    "EXPORT_XPUB_ED25519",
                    benchOp(
                            "EXPORT_XPUB_ED25519",
                            () -> sendInner(sc, MeowlInsn.EXPORT_XPUB.value(), payload)));
        }
        if (shouldRun("sc")) {
            // For OPEN_SECURE_CHANNEL we re-handshake on every iteration. The closure captures
            // `bibo` and creates a fresh client / new ECDH ephemerals each call.
            out.put(
                    "OPEN_SECURE_CHANNEL",
                    benchOp("OPEN_SECURE_CHANNEL", () -> reHandshake(bibo, authentikey)));
        }
        progress("bench complete; total wall %.1fs", (System.nanoTime() - t0) / 1e9);
        return out;
    }

    private boolean shouldRun(String name) {
        if (include == null || include.length == 0) {
            return true;
        }
        for (String s : include) {
            if (s.equalsIgnoreCase(name)) {
                return true;
            }
        }
        return false;
    }

    private void verifyPin(SecureChannelClient sc, byte[] pinBytes) throws BIBOException {
        sc.sendInner(MeowlInsn.VERIFY_PIN.value(), 0, 0, pinBytes);
    }

    @FunctionalInterface
    private interface ThrowingRunnable {
        void run() throws Exception;
    }

    private Stats benchOp(String label, ThrowingRunnable op) {
        try {
            long opStart = System.nanoTime();
            progress("%-22s starting (warmup=%d)...", label, warmup);
            long warmStart = System.nanoTime();
            for (int i = 0; i < warmup; i++) {
                op.run();
            }
            long warmNanos = System.nanoTime() - warmStart;
            double warmupMeanMs = warmup == 0 ? 0.0 : (warmNanos / (double) warmup) / 1e6;
            progress(
                    "%-22s warmup done in %.1fs (mean %.0fms); now timing %d samples...",
                    label, warmNanos / 1e9, warmupMeanMs, samples);
            long[] nanos = new long[samples];
            for (int i = 0; i < samples; i++) {
                long start = System.nanoTime();
                op.run();
                nanos[i] = System.nanoTime() - start;
                if (samples >= 10 && (i + 1) % Math.max(1, samples / 10) == 0) {
                    progress("%-22s   %d/%d   last=%.0fms", label, i + 1, samples, nanos[i] / 1e6);
                }
            }
            Stats stats = Stats.from(nanos);
            progress(
                    "%-22s done in %.1fs   p50=%.0fms   p99=%.0fms",
                    label, (System.nanoTime() - opStart) / 1e9, stats.p50Ms, stats.p99Ms);
            return stats;
        } catch (Exception e) {
            throw new RuntimeException("benchmark op failed: " + label, e);
        }
    }

    /** Per-op progress line on stderr. Suppressed in {@code --json} mode to keep stdout pure. */
    private void progress(String fmt, Object... args) {
        if (parent.globalOptions.json) {
            return;
        }
        System.err.println("[bench] " + String.format(fmt, args));
        System.err.flush();
    }

    private static byte[] sendInner(SecureChannelClient sc, byte ins, byte[] data)
            throws BIBOException {
        return sc.sendInner(ins, 0, 0, data);
    }

    private static void reHandshake(APDUBIBO bibo, byte[] authentikey) throws BIBOException {
        SecureChannelClient.open(bibo, authentikey);
    }

    private static byte[] signPayloadK1() {
        // depth(1) ‖ path(20) ‖ digest(32)  for m/44'/0'/0'/0/0
        byte[] out = new byte[1 + 4 * PATH_K1.length + 32];
        out[0] = (byte) PATH_K1.length;
        for (int i = 0; i < PATH_K1.length; i++) {
            encodeUint32BE(out, 1 + 4 * i, PATH_K1[i] & 0xFFFFFFFFL);
        }
        byte[] digest = new byte[32];
        RANDOM.nextBytes(digest);
        System.arraycopy(digest, 0, out, 1 + 4 * PATH_K1.length, 32);
        return out;
    }

    private static byte[] signPayloadEd25519() {
        // depth(1) ‖ path(16) ‖ message(32)  for m/44'/501'/0'/0'
        byte[] out = new byte[1 + 4 * PATH_ED25519.length + 32];
        out[0] = (byte) PATH_ED25519.length;
        for (int i = 0; i < PATH_ED25519.length; i++) {
            encodeUint32BE(out, 1 + 4 * i, PATH_ED25519[i] & 0xFFFFFFFFL);
        }
        byte[] msg = new byte[32];
        RANDOM.nextBytes(msg);
        System.arraycopy(msg, 0, out, 1 + 4 * PATH_ED25519.length, 32);
        return out;
    }

    private static byte[] exportXpubPayload(byte curveId, int[] path) {
        byte[] out = new byte[2 + 4 * path.length];
        out[0] = curveId;
        out[1] = (byte) path.length;
        for (int i = 0; i < path.length; i++) {
            encodeUint32BE(out, 2 + 4 * i, path[i] & 0xFFFFFFFFL);
        }
        return out;
    }

    private static void encodeUint32BE(byte[] dst, int off, long val) {
        dst[off] = (byte) ((val >>> 24) & 0xFF);
        dst[off + 1] = (byte) ((val >>> 16) & 0xFF);
        dst[off + 2] = (byte) ((val >>> 8) & 0xFF);
        dst[off + 3] = (byte) (val & 0xFF);
    }

    private static void renderText(PrintStream out, Map<String, Stats> results) {
        out.printf(
                "%-22s %5s %8s %8s %8s %8s %8s %8s %8s%n",
                "operation",
                "n",
                "p50_ms",
                "p95_ms",
                "p99_ms",
                "mean_ms",
                "stddev",
                "min_ms",
                "max_ms");
        out.println(
                "---------------------- ----- -------- -------- -------- -------- "
                        + "-------- -------- --------");
        for (var e : results.entrySet()) {
            Stats s = e.getValue();
            out.printf(
                    "%-22s %5d %8.1f %8.1f %8.1f %8.1f %8.1f %8.1f %8.1f%n",
                    e.getKey(),
                    s.n,
                    s.p50Ms,
                    s.p95Ms,
                    s.p99Ms,
                    s.meanMs,
                    s.stddevMs,
                    s.minMs,
                    s.maxMs);
        }
    }

    private static Map<String, Object> toJsonModel(Map<String, Stats> results) {
        Map<String, Object> root = new LinkedHashMap<>();
        for (var e : results.entrySet()) {
            Stats s = e.getValue();
            Map<String, Object> obj = new LinkedHashMap<>();
            obj.put("n", s.n);
            obj.put("p50_ms", s.p50Ms);
            obj.put("p95_ms", s.p95Ms);
            obj.put("p99_ms", s.p99Ms);
            obj.put("mean_ms", s.meanMs);
            obj.put("stddev_ms", s.stddevMs);
            obj.put("min_ms", s.minMs);
            obj.put("max_ms", s.maxMs);
            root.put(e.getKey(), obj);
        }
        return root;
    }

    /** Latency distribution for a single operation. */
    public record Stats(
            int n,
            double p50Ms,
            double p95Ms,
            double p99Ms,
            double meanMs,
            double stddevMs,
            double minMs,
            double maxMs) {

        static Stats from(long[] nanos) {
            long[] sorted = nanos.clone();
            Arrays.sort(sorted);
            long sum = 0;
            for (long v : sorted) sum += v;
            double mean = sum / (double) sorted.length;
            double sqSum = 0;
            for (long v : sorted) {
                double d = v - mean;
                sqSum += d * d;
            }
            double stddev = Math.sqrt(sqSum / sorted.length);
            return new Stats(
                    sorted.length,
                    sorted[(int) (sorted.length * 0.50)] / 1_000_000.0,
                    sorted[(int) (sorted.length * 0.95)] / 1_000_000.0,
                    sorted[Math.min(sorted.length - 1, (int) (sorted.length * 0.99))] / 1_000_000.0,
                    mean / 1_000_000.0,
                    stddev / 1_000_000.0,
                    sorted[0] / 1_000_000.0,
                    sorted[sorted.length - 1] / 1_000_000.0);
        }
    }
}
