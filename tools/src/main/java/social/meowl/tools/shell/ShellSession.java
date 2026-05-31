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
import social.meowl.tools.card.MeowlCard;
import social.meowl.tools.core.Hex;
import social.meowl.tools.core.MeowlAid;
import social.meowl.tools.core.MeowlInfo;
import social.meowl.tools.core.MeowlSw;
import social.meowl.tools.proto.SecureChannelClient;

/**
 * Stateful REPL backend for {@code meowl shell}: holds a long-lived {@link MeowlCard} (and any open
 * {@link SecureChannelClient}) across user inputs, dispatching each line through a tiny built-in
 * parser (deliberately not picocli, which would re-instantiate every subcommand per call).
 *
 * <p>Every card operation is delegated to {@link MeowlCard}, so the shell and the one-shot
 * subcommands share identical wire choreography — {@code info} here renders the same decoded
 * profile as {@code meowl info}. Single-threaded: one instance per shell loop, no synchronisation.
 */
public final class ShellSession {

    private final MeowlCard card;
    private final PrintWriter out;
    private final PrintWriter err;
    private SecureChannelClient sc;

    public ShellSession(APDUBIBO bibo, PrintWriter out, PrintWriter err) {
        this.card = new MeowlCard(bibo);
        this.out = out;
        this.err = err;
    }

    /** Builds the shell prompt for the next input line, reflecting the current session state. */
    public String prompt() {
        if (sc != null) {
            return "meowl[sc]> ";
        }
        if (card.isSelected()) {
            return "meowl> ";
        }
        return "meowl[disconnected]> ";
    }

    /** Dispatches one command line; see {@link #help} for the full grammar. */
    public void execute(String line) throws BIBOException {
        String trimmed = line.trim();
        if (trimmed.isEmpty()) {
            return;
        }

        String[] tokens = trimmed.split("\\s+");
        String cmd = tokens[0].toLowerCase();
        switch (cmd) {
            case "help" -> help();
            case "select" -> {
                if (tokens.length > 1) {
                    card.aid(MeowlAid.parse(tokens[1]));
                }
                card.select();
                sc = null;
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
        MeowlInfo info = card.getInfo();
        out.printf("  protocol version : %s%n", info.protocolVersion());
        out.printf("  applet version   : %s%n", info.appletVersion());
        out.printf("  lifecycle        : %s%n", info.lifecycleName());
        out.printf(
                "  capabilities     : 0x%04X (%s)%n",
                info.capabilityBits(),
                String.join(", ", info.capabilities().stream().map(Enum::name).toList()));
        out.printf("  authentikey      : 0x%s%n", Hex.encode(info.authentikey()));
    }

    private void runAuthentikey() throws BIBOException {
        out.println("0x" + Hex.encode(card.getAuthentikey()));
    }

    private void runApdu(String[] tokens) throws BIBOException {
        if (tokens.length < 2) {
            err.println("usage: apdu <hex-bytes>");
            return;
        }
        card.ensureSelected();
        ResponseAPDU resp = card.transmit(new CommandAPDU(Hex.decode(tokens[1])));
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
            case "handshake" -> {
                sc = card.openSecureChannel();
                out.println("OK (Secure Channel established)");
            }
            case "send" -> {
                if (tokens.length < 3) {
                    err.println("usage: sc send <inner-hex>");
                    return;
                }
                if (sc == null) {
                    err.println("no Secure Channel session — run 'sc handshake' first");
                    return;
                }
                byte[] decrypted = sc.sendInner(Hex.decode(tokens[2]));
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
        int[] steps = card.resetToFactory();
        for (int sw : steps) {
            out.println("  " + MeowlSw.describe(sw));
        }
        out.println("OK (factory reset complete)");
        sc = null;
    }

    private void help() {
        out.println("Available commands:");
        out.println("  select [hex-aid]     SELECT the meowl applet (default AID by default)");
        out.println("  info                 GET_INFO + pretty-print the decoded profile");
        out.println("  authentikey          GET_AUTHENTIKEY (33-byte compressed pubkey)");
        out.println("  apdu <hex>           transmit a raw APDU and print the response");
        out.println("  sc handshake         open a Secure Channel against this card");
        out.println("  sc send <inner-hex>  send an inner APDU through the open Secure Channel");
        out.println("  sc close             tear down the open Secure Channel session");
        out.println("  reset                drive RESET_TO_FACTORY countdown to 6FA0");
        out.println("  help                 print this listing");
        out.println("  exit, quit           leave the shell");
    }
}
