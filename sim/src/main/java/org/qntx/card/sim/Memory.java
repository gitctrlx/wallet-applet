// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.sim;

import javacard.framework.JCSystem;
import javacard.security.Key;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

/**
 * Transient-memory hooks the {@link Agent} weaves into applet bytecode (architecture spec section
 * 8, patch 6): only calls from instrumented applet packages pass through here, so these entry
 * points can charge card A's measured transient pool. The charge table lives on {@link
 * CardRuntime}.
 */
public final class Memory {

    private Memory() {}

    public static byte[] makeTransientByteArray(short length, byte event) {
        return JCSystem.makeTransientByteArray(length, event);
    }

    public static short[] makeTransientShortArray(short length, byte event) {
        return JCSystem.makeTransientShortArray(length, event);
    }

    public static boolean[] makeTransientBooleanArray(short length, byte event) {
        return JCSystem.makeTransientBooleanArray(length, event);
    }

    public static Object[] makeTransientObjectArray(short length, byte event) {
        return JCSystem.makeTransientObjectArray(length, event);
    }

    public static Key buildKey(byte keyType, short keyLength, boolean keyEncryption) {
        return KeyBuilder.buildKey(keyType, keyLength, keyEncryption);
    }

    public static Key buildKey(
            byte keyType, byte keyAlgorithmType, short keyLength, boolean keyEncryption) {
        return KeyBuilder.buildKey(keyType, keyAlgorithmType, keyLength, keyEncryption);
    }

    public static Key buildKeyWithSharedDomain(
            byte keyType, byte keyAlgorithmType, Key domainKey, boolean keyEncryption) {
        return KeyBuilder.buildKeyWithSharedDomain(
                keyType, keyAlgorithmType, domainKey, keyEncryption);
    }

    public static Cipher cipher(byte algorithm, boolean externalAccess) {
        return Cipher.getInstance(algorithm, externalAccess);
    }

    public static Cipher cipher(byte algorithm, byte paddingAlgorithm, boolean externalAccess) {
        return Cipher.getInstance(algorithm, paddingAlgorithm, externalAccess);
    }

    public static Signature signature(byte algorithm, boolean externalAccess) {
        return Signature.getInstance(algorithm, externalAccess);
    }

    public static Signature signature(
            byte signatureAlgorithm,
            byte cipherAlgorithm,
            byte messageDigestAlgorithm,
            boolean externalAccess) {
        return Signature.getInstance(
                signatureAlgorithm, cipherAlgorithm, messageDigestAlgorithm, externalAccess);
    }

    public static MessageDigest messageDigest(byte algorithm, boolean externalAccess) {
        return MessageDigest.getInstance(algorithm, externalAccess);
    }

    public static KeyAgreement keyAgreement(byte algorithm, boolean externalAccess) {
        return KeyAgreement.getInstance(algorithm, externalAccess);
    }

    public static RandomData randomData(byte algorithm) {
        return RandomData.getInstance(algorithm);
    }
}
