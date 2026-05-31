/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.cli;

import java.io.PrintStream;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.ParentCommand;
import social.meowl.tools.card.MeowlCard;
import social.meowl.tools.core.Hex;
import social.meowl.tools.core.MeowlInfo;
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

    @ParentCommand private MeowlCli parent;

    @Mixin public AidOption aid = new AidOption();

    @Override
    public Integer call() {
        MeowlInfo info =
                CardTransport.run(
                        parent.globalOptions.toReaderPreferences(),
                        bibo -> new MeowlCard(bibo, aid.bytes()).getInfo());

        if (parent.globalOptions.json) {
            JsonOutput.write(System.out, toJsonModel(info));
        } else {
            renderText(System.out, info);
        }
        return 0;
    }

    private static void renderText(PrintStream out, MeowlInfo info) {
        out.printf("  protocol version : %s%n", info.protocolVersion());
        out.printf("  applet version   : %s%n", info.appletVersion());
        out.printf("  lifecycle        : %s%n", info.lifecycleName());
        out.printf(
                "  capabilities     : 0x%04X (%s)%n",
                info.capabilityBits(), String.join(", ", capabilityNames(info)));
        out.printf("  authentikey      : 0x%s%n", Hex.encode(info.authentikey()));
    }

    private static Map<String, Object> toJsonModel(MeowlInfo info) {
        Map<String, Object> json = new LinkedHashMap<>();
        json.put("protocol_version", info.protocolVersion().toString());
        json.put("applet_version", info.appletVersion().toString());

        Map<String, Object> lifecycle = new LinkedHashMap<>();
        lifecycle.put("code", info.lifecycleCode());
        lifecycle.put("name", info.lifecycleName());
        json.put("lifecycle", lifecycle);

        Map<String, Object> capabilities = new LinkedHashMap<>();
        capabilities.put("bits", "0x%04X".formatted(info.capabilityBits()));
        capabilities.put("flags", capabilityNames(info));
        json.put("capabilities", capabilities);

        json.put("authentikey", "0x" + Hex.encode(info.authentikey()));
        return json;
    }

    private static List<String> capabilityNames(MeowlInfo info) {
        return info.capabilities().stream().map(Enum::name).toList();
    }
}
