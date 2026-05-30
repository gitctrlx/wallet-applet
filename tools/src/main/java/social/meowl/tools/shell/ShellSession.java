/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.shell;

import apdu4j.core.APDUBIBO;
import apdu4j.core.BIBOException;
import apdu4j.core.CommandAPDU;
import apdu4j.core.ResponseAPDU;
import java.io.PrintWriter;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.SequencedMap;
import social.meowl.tools.core.Hex;
import social.meowl.tools.core.MeowlAid;
import social.meowl.tools.core.MeowlInsn;
import social.meowl.tools.core.MeowlSw;
import social.meowl.tools.core.Tlv;
import social.meowl.tools.proto.SecureChannelClient;

/**
 * Stateful REPL backend for {@code meowl shell}: holds the long-lived {@link APDUBIBO} and any open
 * {@link SecureChannelClient} across user inputs, dispatching each line through a tiny built-in
 * parser (deliberately not picocli, which would re-instantiate every subcommand per call).
 * Single-threaded: one instance per shell loop, no synchronisation.
 */
public final class ShellSession {

    private static final int RESET_REQUIRED_INVOCATIONS = 4;

    private final APDUBIBO bibo;
    private final PrintWriter out;
    private final PrintWriter err;
    private byte[] currentAid = MeowlAid.defaultBytes();
    private SecureChannelClient sc;
    private boolean appletSelected;

    public ShellSession(APDUBIBO bibo, PrintWriter out, PrintWriter err) {
        this.bibo = bibo;
        this.out = out;
        this.err = err;
    }

    /** Builds the shell prompt for the next input line, reflecting the current session state. */
    public String prompt() {
        if (sc != null) return "meowl[sc]> ";
        if (appletSelected) return "meowl> ";
        return "meowl[disconnected]> ";
    }

    /** Selects the meowl applet at the configured AID. */
    public void selectApplet() throws BIBOException {
        ResponseAPDU resp = bibo.transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, currentAid));
        if (!MeowlSw.isSuccess(resp.getSW())) {
            appletSelected = false;
            throw new ShellException("SELECT failed: " + MeowlSw.describe(resp.getSW()));
        }
        appletSelected = true;
        sc = null;
    }

    /** Dispatches one command line; see {@link #help} for the full grammar. */
    public void execute(String line) throws BIBOException {
        String trimmed = line.trim();
        if (trimmed.isEmpty()) return;

        String[] tokens = trimmed.split("\\s+");
        String cmd = tokens[0].toLowerCase();
        switch (cmd) {
            case "help" -> help();
            case "select" -> {
                if (tokens.length > 1) {
                    currentAid = MeowlAid.parse(tokens[1]);
                }
                selectApplet();
                out.println("OK");
            }
            case "info" -> runInfo();
            case "authentikey" -> runAuthentikey();
            case "apdu" -> runApdu(tokens);
            case "sc" -> runSc(tokens);
            case "reset" -> runReset();
            case "exit", "quit" -> {
                /* swallowed; main loop watches for these tokens too. */
            }
            default -> err.println("unknown command: " + cmd + " (type 'help' for the list)");
        }
    }

    /** Closes any open SC session. The underlying BIBO is owned by the caller. */
    public void shutdown() {
        sc = null;
    }

    private void runInfo() throws BIBOException {
        ensureSelected();
        ResponseAPDU resp =
                bibo.transmit(
                        new CommandAPDU(
                                SecureChannelClient.CLA_MEOWL,
                                MeowlInsn.GET_INFO.value() & 0xFF,
                                0,
                                0));
        if (!MeowlSw.isSuccess(resp.getSW())) {
            throw new ShellException("GET_INFO failed: " + MeowlSw.describe(resp.getSW()));
        }
        SequencedMap<Byte, byte[]> tlv = Tlv.parse(resp.getData());
        Map<Byte, byte[]> linkedTlv = new LinkedHashMap<>(tlv);
        for (Map.Entry<Byte, byte[]> entry : linkedTlv.entrySet()) {
            out.printf(
                    "  tag 0x%02X (%d bytes) : 0x%s%n",
                    entry.getKey() & 0xFF, entry.getValue().length, Hex.encode(entry.getValue()));
        }
    }

    private void runAuthentikey() throws BIBOException {
        ensureSelected();
        ResponseAPDU resp =
                bibo.transmit(
                        new CommandAPDU(
                                SecureChannelClient.CLA_MEOWL,
                                MeowlInsn.GET_AUTHENTIKEY.value() & 0xFF,
                                0,
                                0));
        if (!MeowlSw.isSuccess(resp.getSW())) {
            throw new ShellException("GET_AUTHENTIKEY failed: " + MeowlSw.describe(resp.getSW()));
        }
        out.println("0x" + Hex.encode(resp.getData()));
    }

    private void runApdu(String[] tokens) throws BIBOException {
        if (tokens.length < 2) {
            err.println("usage: apdu <hex-bytes>");
            return;
        }
        ensureSelected();
        byte[] command = Hex.decode(tokens[1]);
        ResponseAPDU resp = bibo.transmit(new CommandAPDU(command));
        out.printf(
                "<-- %s SW=%04X (%s)%n",
                Hex.encode(resp.getData()), resp.getSW(), MeowlSw.describe(resp.getSW()));
    }

    private void runSc(String[] tokens) throws BIBOException {
        if (tokens.length < 2) {
            err.println("usage: sc <handshake|send|close>");
            return;
        }
        switch (tokens[1].toLowerCase()) {
            case "handshake" -> openSc();
            case "send" -> {
                if (tokens.length < 3) {
                    err.println("usage: sc send <inner-hex>");
                    return;
                }
                if (sc == null) {
                    err.println("no Secure Channel session — run 'sc handshake' first");
                    return;
                }
                byte[] inner = Hex.decode(tokens[2]);
                byte[] decrypted = sc.sendInner(inner);
                out.println("<-- 0x" + Hex.encode(decrypted));
            }
            case "close" -> {
                sc = null;
                out.println(
                        "OK (sc session closed; new commands will run on the bare APDU surface)");
            }
            default -> err.println("unknown sc subcommand: " + tokens[1]);
        }
    }

    private void runReset() throws BIBOException {
        ensureSelected();
        int last = 0;
        for (int i = 0; i < RESET_REQUIRED_INVOCATIONS; i++) {
            ResponseAPDU resp =
                    bibo.transmit(
                            new CommandAPDU(
                                    SecureChannelClient.CLA_MEOWL,
                                    MeowlInsn.RESET_TO_FACTORY.value() & 0xFF,
                                    0,
                                    0));
            last = resp.getSW();
            if ((last & 0xFFF0) != MeowlSw.RESET_COUNTDOWN_BASE) {
                throw new ShellException(
                        "RESET_TO_FACTORY step " + (i + 1) + " returned " + MeowlSw.describe(last));
            }
            out.println("  " + MeowlSw.describe(last));
        }
        if ((last & 0x000F) != 0) {
            throw new ShellException("RESET_TO_FACTORY did not complete the wipe");
        }
        out.println("OK (factory reset complete)");
        sc = null;
    }

    private void openSc() throws BIBOException {
        ensureSelected();
        ResponseAPDU akResp =
                bibo.transmit(
                        new CommandAPDU(
                                SecureChannelClient.CLA_MEOWL,
                                MeowlInsn.GET_AUTHENTIKEY.value() & 0xFF,
                                0,
                                0));
        if (!MeowlSw.isSuccess(akResp.getSW())) {
            throw new ShellException(
                    "GET_AUTHENTIKEY failed during sc handshake: "
                            + MeowlSw.describe(akResp.getSW()));
        }
        SecureChannelClient client = new SecureChannelClient(bibo, akResp.getData());
        client.handshake();
        sc = client;
        out.println("OK (Secure Channel established)");
    }

    private void ensureSelected() throws BIBOException {
        if (!appletSelected) {
            selectApplet();
        }
    }

    private void help() {
        out.println("Available commands:");
        out.println("  select [hex-aid]     SELECT the meowl applet (default AID by default)");
        out.println("  info                 GET_INFO + pretty-print the TLV blob");
        out.println("  authentikey          GET_AUTHENTIKEY (33-byte compressed pubkey)");
        out.println("  apdu <hex>           transmit a raw APDU and print the response");
        out.println("  sc handshake         open a MEAP-2 Secure Channel against this card");
        out.println("  sc send <inner-hex>  send an inner APDU through the open Secure Channel");
        out.println("  sc close             tear down the open Secure Channel session");
        out.println("  reset                drive RESET_TO_FACTORY countdown to 6FA0");
        out.println("  help                 print this listing");
        out.println("  exit, quit           leave the shell");
    }

    /** Raised when a shell command fails with a recoverable error; reported to the user. */
    public static final class ShellException extends RuntimeException {
        public ShellException(String message) {
            super(message);
        }
    }
}
