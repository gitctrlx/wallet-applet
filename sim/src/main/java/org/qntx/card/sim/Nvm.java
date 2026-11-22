// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.sim;

import javacard.framework.Util;
import javacard.security.Key;
import javacard.security.KeyBuilder;

/**
 * Persistent-write hooks the {@link Agent} weaves into applet bytecode (architecture spec section
 * 8, patch 5). Every hook charges the commit buffer, counts the write for {@link Card#writes()} and
 * the armed tear point, and journals the pre-image while a transaction is open; the actual store
 * happens only if the hook returns normally. Only arrays the applet allocated itself — creation
 * instructions observed by the agent — count as persistent targets, so writes while no {@link
 * CardRuntime} is bound, and writes to APDU buffers, transient memory or foreign arrays, pass
 * through uncounted.
 */
public final class Nvm {

    private Nvm() {}

    /**
     * Runs after every array-creation instruction in instrumented bytecode and registers the new
     * array as applet-owned persistent memory. Arrays the applet did not allocate itself — APDU
     * buffers, transient-memory allocations, harness or coverage-agent probe arrays — stay
     * invisible to {@link CardRuntime#isPersistentArray}.
     */
    public static void trackArray(Object array) {
        CardRuntime rt = CardRuntime.current();
        if (rt != null) {
            rt.registerArray(array);
        }
    }

    /**
     * Replacement for {@code bastore}. The incoming value is widened to {@code int} so the same
     * hook serves {@code byte[]} and {@code boolean[]} targets.
     */
    public static void bastore(Object array, int index, int value) {
        CardRuntime rt = CardRuntime.current();
        if (array instanceof byte[] bytes) {
            if (rt != null && rt.isPersistentArray(bytes)) {
                rt.arrayWrite(bytes, index, 1);
            }
            bytes[index] = (byte) value;
        } else {
            boolean[] booleans = (boolean[]) array;
            if (rt != null && rt.isPersistentArray(booleans)) {
                rt.arrayWrite(booleans, index, 1);
            }
            booleans[index] = (value & 1) != 0;
        }
    }

    /** Replacement for {@code sastore}; value widened to {@code int}. */
    public static void sastore(short[] array, int index, int value) {
        CardRuntime rt = CardRuntime.current();
        if (rt != null && rt.isPersistentArray(array)) {
            rt.arrayWrite(array, index, 1);
        }
        array[index] = (short) value;
    }

    /** {@link Util#setShort} on a persistent buffer is one atomic write. */
    public static short setShort(byte[] bArray, short bOff, short sValue) {
        CardRuntime rt = CardRuntime.current();
        if (rt != null && rt.isPersistentArray(bArray)) {
            rt.arrayWrite(bArray, bOff, 2);
        }
        return Util.setShort(bArray, bOff, sValue);
    }

    /** Atomic copy: one commit-buffer span, one write, one tear point. */
    public static short arrayCopy(
            byte[] src, short srcOff, byte[] dest, short destOff, short length) {
        CardRuntime rt = CardRuntime.current();
        if (rt != null && rt.isPersistentArray(dest)) {
            rt.arrayWrite(dest, destOff, length);
        }
        return Util.arrayCopy(src, srcOff, dest, destOff, length);
    }

    /**
     * Non-atomic copy: two write points so an armed tear can stop the copy half-written, matching
     * the torn-copy evidence in the audit.
     */
    public static short arrayCopyNonAtomic(
            byte[] src, short srcOff, byte[] dest, short destOff, short length) {
        CardRuntime rt = CardRuntime.current();
        if (rt != null && rt.isPersistentArray(dest)) {
            rt.arrayWritePoint();
            short half = (short) (length / 2);
            Util.arrayCopyNonAtomic(src, srcOff, dest, destOff, half);
            rt.arrayWritePoint();
            return Util.arrayCopyNonAtomic(
                    src,
                    (short) (srcOff + half),
                    dest,
                    (short) (destOff + half),
                    (short) (length - half));
        }
        return Util.arrayCopyNonAtomic(src, srcOff, dest, destOff, length);
    }

    /** Non-atomic fill: two write points like {@link #arrayCopyNonAtomic}. */
    public static short arrayFillNonAtomic(byte[] bArray, short bOff, short bLen, byte bValue) {
        CardRuntime rt = CardRuntime.current();
        if (rt != null && rt.isPersistentArray(bArray)) {
            rt.arrayWritePoint();
            short half = (short) (bLen / 2);
            Util.arrayFillNonAtomic(bArray, bOff, half, bValue);
            rt.arrayWritePoint();
            Util.arrayFillNonAtomic(bArray, (short) (bOff + half), (short) (bLen - half), bValue);
            return (short) (bOff + bLen);
        }
        return Util.arrayFillNonAtomic(bArray, bOff, bLen, bValue);
    }

    /**
     * Fires before every {@code putfield}/{@code putstatic} in instrumented bytecode. The applet
     * protocol keeps persistent state in arrays; a field assignment during a command is a defect
     * and the simulator surfaces it as {@link AssertionError}.
     */
    public static void field() {
        CardRuntime rt = CardRuntime.current();
        if (rt != null && rt.inCommand()) {
            throw new AssertionError("persistent field write after install");
        }
    }

    /**
     * Prepended to every instrumented catch/finally handler so a {@link PowerLoss} steers around
     * handler bodies; the error itself then unwinds the frame untouched.
     */
    public static void rethrowPowerLoss(Throwable t) {
        if (t instanceof PowerLoss) {
            throw (PowerLoss) t;
        }
    }

    /**
     * Persistent key-object write injected before key setter bodies and {@code KeyBuilder.buildKey}
     * calls in instrumented code (patches 2 and 5): {@code charge} is the commit-buffer cost, 0 for
     * free.
     */
    public static void keyWrite(Object key, int charge) {
        if (!(key instanceof Key)) {
            return;
        }
        if (isTransientKeyType(((Key) key).getType())) {
            return;
        }
        CardRuntime rt = CardRuntime.current();
        if (rt != null) {
            rt.keyWrite(key, charge);
        }
    }

    /** {@code KeyPair.genKeyPair} writes both keys: one 1024 B charge. */
    public static void keyPairWrite(Object publicKey, Object privateKey) {
        CardRuntime rt = CardRuntime.current();
        if (rt == null) {
            return;
        }
        boolean persistent =
                (publicKey instanceof Key && !isTransientKeyType(((Key) publicKey).getType()))
                        || (privateKey instanceof Key
                                && !isTransientKeyType(((Key) privateKey).getType()));
        if (persistent) {
            rt.keyPairWrite(publicKey, privateKey);
        }
    }

    static boolean isTransientKeyType(byte type) {
        switch (type) {
            case KeyBuilder.TYPE_DES_TRANSIENT_RESET:
            case KeyBuilder.TYPE_DES_TRANSIENT_DESELECT:
            case KeyBuilder.TYPE_AES_TRANSIENT_RESET:
            case KeyBuilder.TYPE_AES_TRANSIENT_DESELECT:
            case KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_RESET:
            case KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT:
            case KeyBuilder.TYPE_EC_F2M_PRIVATE_TRANSIENT_RESET:
            case KeyBuilder.TYPE_EC_F2M_PRIVATE_TRANSIENT_DESELECT:
            case KeyBuilder.TYPE_RSA_PRIVATE_TRANSIENT_RESET:
            case KeyBuilder.TYPE_RSA_PRIVATE_TRANSIENT_DESELECT:
            case KeyBuilder.TYPE_RSA_CRT_PRIVATE_TRANSIENT_RESET:
            case KeyBuilder.TYPE_RSA_CRT_PRIVATE_TRANSIENT_DESELECT:
            case KeyBuilder.TYPE_KOREAN_SEED_TRANSIENT_RESET:
            case KeyBuilder.TYPE_KOREAN_SEED_TRANSIENT_DESELECT:
            case KeyBuilder.TYPE_HMAC_TRANSIENT_RESET:
            case KeyBuilder.TYPE_HMAC_TRANSIENT_DESELECT:
            case KeyBuilder.TYPE_DSA_PRIVATE_TRANSIENT_RESET:
            case KeyBuilder.TYPE_DSA_PRIVATE_TRANSIENT_DESELECT:
            case KeyBuilder.TYPE_DH_PUBLIC_TRANSIENT_RESET:
            case KeyBuilder.TYPE_DH_PUBLIC_TRANSIENT_DESELECT:
            case KeyBuilder.TYPE_DH_PRIVATE_TRANSIENT_RESET:
            case KeyBuilder.TYPE_DH_PRIVATE_TRANSIENT_DESELECT:
                return true;
            default:
                return false;
        }
    }
}
