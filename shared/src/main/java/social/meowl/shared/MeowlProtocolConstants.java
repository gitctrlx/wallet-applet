/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.shared;

/**
 * Protocol constants shared by the applet, host CLI and integration tests.
 *
 * <p>This class is a placeholder during Phase 0 of the Q2-2026 refactor. Phase 2 migrates the
 * mirrored constants currently duplicated between {@code applet/.../Constants.java} and the
 * relevant host classes (e.g. {@code BootstrapCommand}, {@code BenchCommand}, {@code
 * SecureChannelClient}) into this single location.
 *
 * <p>Closes audit findings AUDIT-013, AUDIT-014, NEWAUDIT-011, NEWAUDIT-012 once the migration
 * lands.
 */
public final class MeowlProtocolConstants {

    /** ISO/IEC 7816-4 proprietary CLA byte used by every meowl-applet command. */
    public static final byte CLA_MEOWL = (byte) 0x80;

    private MeowlProtocolConstants() {
        // No instances.
    }
}
