/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.cli;

import java.util.concurrent.Callable;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Spec;

/**
 * {@code meowl backup ...} — namespace for operating the meowl backup card (BIP-39 seed-backup).
 *
 * <p>This is a non-leaf command: invoking {@code meowl backup} alone prints the usage banner of the
 * {@code backup} subtree. Every secret-touching subcommand runs over the meowl Secure Channel and,
 * past provisioning, a verified PIN.
 */
@Command(
        name = "backup",
        mixinStandardHelpOptions = true,
        description =
                "Backup-card subcommands (status / provision / restore / change-pin / set-name /"
                        + " factory-reset).",
        synopsisSubcommandLabel = "COMMAND",
        subcommands = {
            CommandLine.HelpCommand.class,
            BackupStatusCommand.class,
            BackupProvisionCommand.class,
            BackupRestoreCommand.class,
            BackupChangePinCommand.class,
            BackupSetNameCommand.class,
            BackupFactoryResetCommand.class,
        })
public final class BackupCommand implements Callable<Integer> {

    /** {@code BACKUP_SEED} inner INS — store BIP-39 entropy. */
    public static final byte INS_BACKUP_SEED = (byte) 0x43;

    /** {@code RESTORE_SEED} inner INS — return stored entropy under the Secure Channel. */
    public static final byte INS_RESTORE_SEED = (byte) 0x44;

    /** {@code VERIFY_SEED} inner INS — integrity self-check. */
    public static final byte INS_VERIFY_SEED = (byte) 0x45;

    /** {@code SET_NAME} inner INS — set the card label. */
    public static final byte INS_SET_NAME = (byte) 0x46;

    @Spec public CommandLine.Model.CommandSpec spec;

    @Override
    public Integer call() {
        spec.commandLine().usage(System.out);
        return CommandLine.ExitCode.USAGE;
    }
}
