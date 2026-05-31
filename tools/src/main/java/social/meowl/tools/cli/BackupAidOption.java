/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.cli;

import picocli.CommandLine.Option;
import social.meowl.tools.core.MeowlAid;

/**
 * Picocli mixin contributing a {@code --aid} option to the {@code backup} subcommands, defaulting
 * to the backup applet instance AID {@link MeowlAid#BACKUP_INSTANCE_HEX}.
 */
public final class BackupAidOption {

    @Option(
            names = "--aid",
            paramLabel = "HEX",
            description = "Backup applet AID to SELECT, hex (default: ${DEFAULT-VALUE}).",
            defaultValue = MeowlAid.BACKUP_INSTANCE_HEX)
    public String aid = MeowlAid.BACKUP_INSTANCE_HEX;

    /** Returns the parsed AID bytes; throws {@link IllegalArgumentException} for invalid input. */
    public byte[] bytes() {
        return MeowlAid.parse(aid);
    }
}
