// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import javacard.framework.JCSystem;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

/**
 * The shared engines and scratch arrays, allocated once in the applet constructor (architecture.md
 * §5.2). Commands are sequential, so one command owns all scratch; {@link #wipeScratch} runs in a
 * {@code finally} around every handler.
 *
 * <p>{@code P} (130 B) holds up to two uncompressed secp256k1 points. {@code W} (256 B) is the
 * arithmetic, KDF and DER scratch; shared regions inside it are {@link #W_DER} (72 B, DER encodings
 * of {@link Identity}) and {@link #W_KDF} (40 B, used by {@link Kdf}).
 */
final class Mem {
    /** {@link #W} offset of the 72-byte DER codec area used by {@link Identity}. */
    static final short W_DER = 184;

    /**
     * {@link #W} offset of the 40-byte {@link Kdf} area (32-byte digest block at {@code W_KDF}, u32
     * counter and CMAC separators at {@code W_KDF + 36}).
     */
    static final short W_KDF = 216;

    final Cipher aesCbc;
    final Signature cmac;
    final MessageDigest sha256;
    final RandomData random;
    final byte[] P;
    final byte[] W;

    Mem() {
        aesCbc = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        cmac = Signature.getInstance(Signature.ALG_AES_CMAC_128, false);
        sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        random = RandomData.getInstance(RandomData.ALG_KEYGENERATION);
        P = JCSystem.makeTransientByteArray((short) 130, JCSystem.CLEAR_ON_DESELECT);
        W = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_DESELECT);
    }

    void wipeScratch() {
        Bytes.wipe(P, (short) 0, (short) P.length);
        Bytes.wipe(W, (short) 0, (short) W.length);
    }
}
