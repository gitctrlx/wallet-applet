/*
 * SPDX-FileCopyrightText: 2026 meowl.social contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */
package social.meowl.tools.proto;

/**
 * Raised when any wire- or cryptographic-check fails inside the Secure Channel client stack ({@link
 * SecureChannelClient}, {@link HostCrypto}, …). The {@link #sw()} field carries the relevant 16-bit
 * status word when the failure originated in a card response, or {@code 0} when the failure
 * happened in pure host code (signature mismatch, padding error, malformed body, …).
 *
 * <p>Promoted to a top-level class in audit S4-01 so {@link HostCrypto} can raise it directly on
 * PKCS#5 padding errors without creating a cyclic compile-time dependency on {@link
 * SecureChannelClient}.
 */
public final class SecureChannelException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final int sw;

    public SecureChannelException(int sw, String message) {
        super(message);
        this.sw = sw;
    }

    public int sw() {
        return sw;
    }
}
