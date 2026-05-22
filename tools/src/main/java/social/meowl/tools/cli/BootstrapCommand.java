/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.cli;

import apdu4j.core.APDUBIBO;
import apdu4j.core.BIBOException;
import apdu4j.core.CommandAPDU;
import apdu4j.core.ResponseAPDU;
import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Option;
import picocli.CommandLine.ParentCommand;
import social.meowl.tools.core.Hex;
import social.meowl.tools.core.MeowlInsn;
import social.meowl.tools.core.MeowlSw;
import social.meowl.tools.proto.SecureChannelClient;
import social.meowl.tools.transport.CardTransport;

/**
 * {@code meowl bootstrap} — drives a fresh card from {@code POST_INSTALL} all the way to {@code
 * SEEDED + PIN-validated} in one shot.
 *
 * <p>Performs the canonical lifecycle walk that {@code BenchmarkSuite} runs against {@code
 * jcardsim}, but over a real Secure Channel:
 *
 * <ol>
 *   <li>SELECT the applet, GET_AUTHENTIKEY, open Secure Channel.
 *   <li>{@code IMPORT_PKI_CERT} (init / write / finalize) with a synthetic {@code 80}-byte cert
 *       so {@code LOCK_PKI} is willing to commit.
 *   <li>{@code LOCK_PKI} → {@code PERSONALIZED}.
 *   <li>{@code SETUP} with {@code --pin}/{@code --puk} → {@code SETUP_DONE}.
 *   <li>{@code VERIFY_PIN} (the SETUP transition leaves the card in a not-PIN-verified state on
 *       the first hop after SETUP_DONE in some applet builds; verifying explicitly is harmless
 *       on every revision and lets {@code IMPORT_SEED} succeed unconditionally).
 *   <li>{@code IMPORT_SEED} (default: deterministic {@code 0x01 0x02 ... 0x20}) → {@code SEEDED}.
 *       Override with {@code --seed=HEX} to import a specific seed (16-64 bytes).
 * </ol>
 *
 * <p><b>This command is destructive.</b> A successful {@code SETUP} burns the card's transition
 * counter; running {@code bootstrap} on a card that is already past {@code POST_INSTALL} will
 * fail at the offending step (the applet rejects re-{@code SETUP} once {@code SETUP_DONE} has
 * been reached). For a clean re-bootstrap, run {@code meowl reset} first or re-install the CAP.
 *
 * <p>The synthetic cert is a deterministic byte ramp ({@code 0x00 0x01 ... 0x4F}); production
 * deployments MUST replace it with a real manufacturer-signed cert before {@code LOCK_PKI}.
 * {@code bootstrap} is a developer / CI / hardware-bench tool, not a production provisioning
 * path — call it that way in any deploy script that uses it.
 */
@Command(
        name = "bootstrap",
        mixinStandardHelpOptions = true,
        description =
                "Brings a freshly-installed card to SEEDED in one shot: cert import + LOCK_PKI +"
                        + " SETUP + VERIFY_PIN + IMPORT_SEED. Developer / hardware-bench helper;"
                        + " do NOT use for production provisioning.")
public final class BootstrapCommand implements Callable<Integer> {

    @ParentCommand private MeowlCli parent;

    @Mixin public AidOption aid = new AidOption();

    @Option(
            names = {"-p", "--pin"},
            required = true,
            paramLabel = "PIN",
            description = "User PIN to install (4-32 ASCII bytes).")
    public String pin;

    @Option(
            names = "--puk",
            required = true,
            paramLabel = "PUK",
            description = "Unblock PUK to install (4-32 ASCII bytes).")
    public String puk;

    @Option(
            names = "--seed",
            paramLabel = "HEX",
            description =
                    "Seed bytes to import as hex (16-64 bytes). Default: deterministic"
                            + " 32-byte ramp 0x01..0x20 — useful for reproducibility against"
                            + " jcardsim-based KATs.")
    public String seedHex;

    @Option(
            names = "--cert-size",
            paramLabel = "N",
            description =
                    "Synthetic cert size in bytes for the IMPORT_PKI_CERT phase (default: "
                            + "${DEFAULT-VALUE}). Must be ≥ 1 and ≤ 1024.",
            defaultValue = "80")
    public int certSize;

    /** Default deterministic seed mirrored from {@code BenchmarkSuite.DEFAULT_SEED}. */
    private static final byte[] DEFAULT_SEED = new byte[32];

    static {
        for (int i = 0; i < DEFAULT_SEED.length; i++) {
            DEFAULT_SEED[i] = (byte) (i + 1);
        }
    }

    /** Maximum chunk size accepted by IMPORT_PKI_CERT WRITE — mirrors {@code Constants}. */
    private static final int PKI_CERT_CHUNK_MAX_LEN = 200;

    private static final byte PKI_IMPORT_P1_INIT = 0x00;
    private static final byte PKI_IMPORT_P1_WRITE = 0x01;
    private static final byte PKI_IMPORT_P1_FINALIZE = 0x02;

    @Override
    public Integer call() {
        CardTransport.run(parent.globalOptions.toReaderPreferences(), this::runOnCard);
        return 0;
    }

    private Void runOnCard(APDUBIBO bibo) throws BIBOException {
        MeowlSession.select(bibo, aid.bytes());

        ResponseAPDU akResp =
                bibo.transmit(
                        new CommandAPDU(
                                SecureChannelClient.CLA_MEOWL,
                                MeowlInsn.GET_AUTHENTIKEY.value() & 0xFF,
                                0,
                                0));
        if (!MeowlSw.isSuccess(akResp.getSW())) {
            throw new ProtocolException(
                    akResp.getSW(), "GET_AUTHENTIKEY failed during bootstrap");
        }

        SecureChannelClient sc = new SecureChannelClient(bibo, akResp.getData());
        sc.handshake();
        log("Secure Channel established.");

        // 1. IMPORT_PKI_CERT (init / write / finalize).
        importCert(sc);
        log("IMPORT_PKI_CERT: %d bytes installed.", certSize);

        // 2. LOCK_PKI → PERSONALIZED.
        sendInner(sc, MeowlInsn.LOCK_PKI.value(), (byte) 0, (byte) 0, new byte[0]);
        log("LOCK_PKI: applet now in PERSONALIZED.");

        // 3. SETUP → SETUP_DONE.
        byte[] pinBytes = pin.getBytes();
        byte[] pukBytes = puk.getBytes();
        sendInner(
                sc,
                MeowlInsn.SETUP.value(),
                (byte) 0,
                (byte) 0,
                encodeSetup(pinBytes, pukBytes));
        log("SETUP: PIN/PUK installed (PIN=%d B, PUK=%d B).", pinBytes.length, pukBytes.length);

        // 4. VERIFY_PIN — establishes the session-scoped PIN authorisation IMPORT_SEED needs.
        sendInner(sc, MeowlInsn.VERIFY_PIN.value(), (byte) 0, (byte) 0, pinBytes);
        log("VERIFY_PIN: authorised.");

        // 5. IMPORT_SEED → SEEDED.
        byte[] seed = resolveSeed();
        byte[] seedPayload = new byte[1 + seed.length];
        seedPayload[0] = (byte) seed.length;
        System.arraycopy(seed, 0, seedPayload, 1, seed.length);
        sendInner(sc, MeowlInsn.IMPORT_SEED.value(), (byte) 0, (byte) 0, seedPayload);
        log("IMPORT_SEED: %d-byte seed installed; lifecycle now SEEDED.", seed.length);

        log("bootstrap complete — card is ready for `meowl bench --pin %s`.", pin);
        return null;
    }

    private void importCert(SecureChannelClient sc) throws BIBOException {
        if (certSize < 1 || certSize > 1024) {
            throw new IllegalArgumentException(
                    "--cert-size must be between 1 and 1024, got " + certSize);
        }
        // INIT: declare total size (2 bytes BE).
        byte[] sizeBe = {(byte) (certSize >>> 8), (byte) (certSize & 0xFF)};
        sendInner(sc, MeowlInsn.IMPORT_PKI_CERT.value(), PKI_IMPORT_P1_INIT, (byte) 0, sizeBe);

        // WRITE: stream the deterministic ramp 0x00, 0x01, ..., (certSize - 1) & 0xFF in chunks.
        int written = 0;
        while (written < certSize) {
            int chunkLen = Math.min(PKI_CERT_CHUNK_MAX_LEN, certSize - written);
            byte[] payload = new byte[2 + chunkLen];
            payload[0] = (byte) (written >>> 8);
            payload[1] = (byte) (written & 0xFF);
            for (int i = 0; i < chunkLen; i++) {
                payload[2 + i] = (byte) ((written + i) & 0xFF);
            }
            sendInner(
                    sc,
                    MeowlInsn.IMPORT_PKI_CERT.value(),
                    PKI_IMPORT_P1_WRITE,
                    (byte) 0,
                    payload);
            written += chunkLen;
        }

        // FINALIZE: commit the staged size.
        sendInner(
                sc,
                MeowlInsn.IMPORT_PKI_CERT.value(),
                PKI_IMPORT_P1_FINALIZE,
                (byte) 0,
                new byte[0]);
    }

    private byte[] resolveSeed() {
        if (seedHex == null || seedHex.isBlank()) {
            return DEFAULT_SEED.clone();
        }
        byte[] bytes;
        try {
            bytes = Hex.decode(seedHex);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("--seed is not valid hex: " + e.getMessage());
        }
        if (bytes.length < 16 || bytes.length > 64) {
            throw new IllegalArgumentException(
                    "--seed must be 16-64 bytes; got " + bytes.length);
        }
        return bytes;
    }

    private static void sendInner(
            SecureChannelClient sc, byte ins, byte p1, byte p2, byte[] data) throws BIBOException {
        byte[] inner = new byte[5 + data.length];
        inner[0] = (byte) 0x80;
        inner[1] = ins;
        inner[2] = p1;
        inner[3] = p2;
        inner[4] = (byte) data.length;
        System.arraycopy(data, 0, inner, 5, data.length);
        sc.sendInner(inner);
    }

    private static byte[] encodeSetup(byte[] pinBytes, byte[] pukBytes) {
        byte[] out = new byte[1 + pinBytes.length + 1 + pukBytes.length];
        out[0] = (byte) pinBytes.length;
        System.arraycopy(pinBytes, 0, out, 1, pinBytes.length);
        out[1 + pinBytes.length] = (byte) pukBytes.length;
        System.arraycopy(pukBytes, 0, out, 1 + pinBytes.length + 1, pukBytes.length);
        return out;
    }

    private void log(String fmt, Object... args) {
        if (parent.globalOptions.json) {
            return;
        }
        System.err.println("[bootstrap] " + String.format(fmt, args));
    }
}
