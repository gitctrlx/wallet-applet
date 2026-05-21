/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.cli;

import apdu4j.core.APDUBIBO;
import apdu4j.core.BIBOException;
import apdu4j.core.CommandAPDU;
import apdu4j.core.ResponseAPDU;
import java.io.PrintStream;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.SequencedMap;
import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.ParentCommand;
import social.meowl.tools.core.Hex;
import social.meowl.tools.core.MeowlInsn;
import social.meowl.tools.core.MeowlSw;
import social.meowl.tools.core.Tlv;
import social.meowl.tools.transport.CardTransport;

/**
 * {@code meowl info} — issues {@code GET_INFO} and pretty-prints the returned TLV blob.
 *
 * <p>Tags decoded:
 *
 * <ul>
 *   <li>{@code 0x01} protocol version (2 bytes, big-endian)
 *   <li>{@code 0x02} applet implementation version (2 bytes, big-endian)
 *   <li>{@code 0x03} lifecycle state (1 byte: 0=UNINITIALIZED, 1=PERSONALIZED, 2=SETUP_DONE,
 *       3=SEEDED)
 *   <li>{@code 0x04} capability bitmask (2 bytes, big-endian)
 *   <li>{@code 0x05} compressed authentikey public key (33 bytes)
 * </ul>
 *
 * <p>With {@code --json} the response is emitted as a structured object suitable for piping into
 * downstream tooling (Rust SDK integration tests, monitoring scripts, …).
 */
@Command(
        name = "info",
        mixinStandardHelpOptions = true,
        description = "Returns the applet's TLV-encoded capability and identity profile.")
public final class InfoCommand implements Callable<Integer> {

    private static final byte CLA_MEOWL = (byte) 0x80;

    private static final byte TAG_PROTOCOL_VERSION = 0x01;
    private static final byte TAG_APPLET_VERSION = 0x02;
    private static final byte TAG_LIFECYCLE_STATE = 0x03;
    private static final byte TAG_CAPABILITIES = 0x04;
    private static final byte TAG_AUTHENTIKEY_PUBKEY = 0x05;

    @ParentCommand private MeowlCli parent;

    @Mixin public AidOption aid = new AidOption();

    @Override
    public Integer call() {
        SequencedMap<Byte, byte[]> tlv =
                CardTransport.run(parent.globalOptions.toReaderPreferences(), this::queryInfo);

        if (parent.globalOptions.json) {
            JsonOutput.write(System.out, toJsonModel(tlv));
        } else {
            renderText(System.out, tlv);
        }
        return 0;
    }

    private SequencedMap<Byte, byte[]> queryInfo(APDUBIBO bibo) throws BIBOException {
        MeowlSession.select(bibo, aid.bytes());
        ResponseAPDU resp =
                bibo.transmit(
                        new CommandAPDU(CLA_MEOWL & 0xFF, MeowlInsn.GET_INFO.value() & 0xFF, 0, 0));
        if (!MeowlSw.isSuccess(resp.getSW())) {
            throw new ProtocolException(resp.getSW(), "GET_INFO failed");
        }
        return Tlv.parse(resp.getData());
    }

    private static void renderText(PrintStream out, SequencedMap<Byte, byte[]> tlv) {
        byte[] proto = tlv.get(TAG_PROTOCOL_VERSION);
        byte[] applet = tlv.get(TAG_APPLET_VERSION);
        byte[] lifecycle = tlv.get(TAG_LIFECYCLE_STATE);
        byte[] caps = tlv.get(TAG_CAPABILITIES);
        byte[] authentikey = tlv.get(TAG_AUTHENTIKEY_PUBKEY);

        if (proto != null) out.printf("  protocol version : %s%n", versionStr(proto));
        if (applet != null) out.printf("  applet version   : %s%n", versionStr(applet));
        if (lifecycle != null && lifecycle.length == 1) {
            out.printf("  lifecycle        : %s%n", lifecycleName(lifecycle[0]));
        }
        if (caps != null && caps.length == 2) {
            int bits = ((caps[0] & 0xFF) << 8) | (caps[1] & 0xFF);
            out.printf("  capabilities     : 0x%04X (%s)%n", bits, capsStr(bits));
        }
        if (authentikey != null) {
            out.printf("  authentikey      : 0x%s%n", Hex.encode(authentikey));
        }
    }

    private static Map<String, Object> toJsonModel(SequencedMap<Byte, byte[]> tlv) {
        Map<String, Object> json = new LinkedHashMap<>();
        byte[] proto = tlv.get(TAG_PROTOCOL_VERSION);
        if (proto != null) json.put("protocol_version", versionStr(proto));
        byte[] applet = tlv.get(TAG_APPLET_VERSION);
        if (applet != null) json.put("applet_version", versionStr(applet));
        byte[] lifecycle = tlv.get(TAG_LIFECYCLE_STATE);
        if (lifecycle != null && lifecycle.length == 1) {
            Map<String, Object> lc = new LinkedHashMap<>();
            lc.put("code", lifecycle[0] & 0xFF);
            lc.put("name", lifecycleName(lifecycle[0]));
            json.put("lifecycle", lc);
        }
        byte[] caps = tlv.get(TAG_CAPABILITIES);
        if (caps != null && caps.length == 2) {
            int bits = ((caps[0] & 0xFF) << 8) | (caps[1] & 0xFF);
            Map<String, Object> capObj = new LinkedHashMap<>();
            capObj.put("bits", "0x%04X".formatted(bits));
            capObj.put("flags", java.util.Arrays.asList(capabilityNames(bits)));
            json.put("capabilities", capObj);
        }
        byte[] authentikey = tlv.get(TAG_AUTHENTIKEY_PUBKEY);
        if (authentikey != null) {
            json.put("authentikey", "0x" + Hex.encode(authentikey));
        }
        return json;
    }

    private static String versionStr(byte[] bytes) {
        if (bytes.length != 2) return "0x" + Hex.encode(bytes);
        return "%d.%d".formatted(bytes[0] & 0xFF, bytes[1] & 0xFF);
    }

    private static String lifecycleName(byte b) {
        return switch (b) {
            case 0 -> "UNINITIALIZED";
            case 1 -> "PERSONALIZED";
            case 2 -> "SETUP_DONE";
            case 3 -> "SEEDED";
            default -> "UNKNOWN(0x%02X)".formatted(b & 0xFF);
        };
    }

    private static String capsStr(int bits) {
        return String.join(", ", capabilityNames(bits));
    }

    private static String[] capabilityNames(int bits) {
        var names = new java.util.ArrayList<String>();
        if ((bits & 0x0001) != 0) names.add("ECDSA_K1");
        if ((bits & 0x0002) != 0) names.add("SCHNORR_K1");
        if ((bits & 0x0004) != 0) names.add("ED25519");
        if ((bits & 0x0008) != 0) names.add("SC_GCM");
        if ((bits & 0x0010) != 0) names.add("SC_CBC_HMAC");
        if ((bits & 0x0020) != 0) names.add("PKI");
        if ((bits & 0x0040) != 0) names.add("RESET_TO_FACTORY");
        if ((bits & 0x0080) != 0) names.add("BIP32");
        if ((bits & 0x0100) != 0) names.add("SLIP10");
        return names.toArray(String[]::new);
    }
}
