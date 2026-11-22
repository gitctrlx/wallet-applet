// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card;

import java.lang.reflect.Field;
import javacard.framework.Applet;
import javacard.security.AESKey;

/**
 * Reflection into the installed applet for the simulator tests that inspect transient state and
 * exercise package-private internals (Kdf, ModArith, Secp256k1, Bytes) directly.
 */
public final class Internals {
    private Internals() {}

    public static Mem mem(Applet applet) {
        return (Mem) get(applet, "mem");
    }

    public static Session session(Applet applet) {
        return (Session) get(applet, "session");
    }

    public static Identity identity(Applet applet) {
        return (Identity) get(applet, "identity");
    }

    public static Secp256k1 secp(Applet applet) {
        return (Secp256k1) get(identity(applet), "secp");
    }

    public static ModArith modArith(Applet applet) {
        return (ModArith) get(secp(applet), "modArith");
    }

    public static State state(Applet applet) {
        return (State) get(applet, "state");
    }

    public static Wallet wallet(Applet applet) {
        return (Wallet) get(applet, "wallet");
    }

    public static Derivation derivation(Applet applet) {
        return (Derivation) get(applet, "derivation");
    }

    public static Wei25519 wei(Applet applet) {
        return (Wei25519) get(derivation(applet), "wei");
    }

    /** The persistent {@code wrapKey} of {@link Wallet} (read or overwrite it in tests). */
    public static AESKey wrapKey(Applet applet) {
        return (AESKey) get(wallet(applet), "wrapKey");
    }

    /** A {@code Mem} field by name ({@code kEnc}, {@code kMac}, engines, scratch). */
    public static Object memField(Applet applet, String name) {
        return get(mem(applet), name);
    }

    /** Invokes a private method of an applet object (e.g. {@code Wallet.wrapNew}). */
    public static Object invoke(Object target, String method, Class<?>[] sig, Object... args) {
        try {
            java.lang.reflect.Method m = target.getClass().getDeclaredMethod(method, sig);
            m.setAccessible(true);
            return m.invoke(target, args);
        } catch (java.lang.reflect.InvocationTargetException e) {
            if (e.getCause() instanceof RuntimeException r) {
                throw r;
            }
            if (e.getCause() instanceof Error err) {
                throw err;
            }
            throw new RuntimeException(e.getCause());
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException(e);
        }
    }

    /** The persistent {@code state[272]} array itself (read or corrupt it in tests). */
    public static byte[] stateArray(Applet applet) {
        return (byte[]) get(state(applet), "state");
    }

    /** The transient {@code words[8]} of {@link Session} (open, verified, ctr, pending). */
    public static byte[] words(Applet applet) {
        return (byte[]) get(session(applet), "words");
    }

    /** The transient {@code Mem.W[256]} scratch, for wipe assertions. */
    public static byte[] wBytes(Applet applet) {
        return (byte[]) get(mem(applet), "W");
    }

    /** The transient {@code Mem.P[130]} point scratch, for wipe assertions. */
    public static byte[] pBytes(Applet applet) {
        return (byte[]) get(mem(applet), "P");
    }

    /** The transient {@code Mem.seed[64]} session seed, for wipe assertions. */
    public static byte[] seedBytes(Applet applet) {
        return (byte[]) get(mem(applet), "seed");
    }

    /** The transient {@code Mem.secpCache[138]} node cache, for wipe assertions. */
    public static byte[] secpCacheBytes(Applet applet) {
        return (byte[]) get(mem(applet), "secpCache");
    }

    /** The transient {@code Mem.edCache[105]} node cache, for wipe assertions. */
    public static byte[] edCacheBytes(Applet applet) {
        return (byte[]) get(mem(applet), "edCache");
    }

    /** The transient {@code Mem.N[101]} derivation node, for wipe assertions and pokes. */
    public static byte[] nBytes(Applet applet) {
        return (byte[]) get(mem(applet), "N");
    }

    /** The transient {@code Mem.H[192]} derivation/persistence area, for wipe assertions. */
    public static byte[] hBytes(Applet applet) {
        return (byte[]) get(mem(applet), "H");
    }

    /** The shared SHA-256 engine; a test can leave it dirty before a command. */
    public static javacard.security.MessageDigest sha256(Applet applet) {
        return (javacard.security.MessageDigest) get(mem(applet), "sha256");
    }

    /** The shared SHA-512 engine; a test can leave it dirty before a command. */
    public static javacard.security.MessageDigest sha512(Applet applet) {
        return (javacard.security.MessageDigest) get(mem(applet), "sha512");
    }

    /** A {@code private static final short} offset constant of {@link Session}. */
    public static int sessionOffset(String field) {
        try {
            Field f = Session.class.getDeclaredField(field);
            f.setAccessible(true);
            return f.getShort(null) & 0xFFFF;
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("field " + field, e);
        }
    }

    public static AESKey sessionKey(Applet applet, String name) {
        return (AESKey) get(session(applet), name);
    }

    /** The transient scalar slot of {@link Secp256k1#mul}. */
    public static javacard.security.ECPrivateKey ephKey(Applet applet) {
        return (javacard.security.ECPrivateKey) get(secp(applet), "ephKey");
    }

    /** The identity public key of {@link Identity}, for direct verify calls. */
    public static javacard.security.ECPublicKey idPublic(Applet applet) {
        return (javacard.security.ECPublicKey) get(identity(applet), "idPublic");
    }

    private static Object get(Object o, String field) {
        try {
            Field f = o.getClass().getDeclaredField(field);
            f.setAccessible(true);
            return f.get(o);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("field " + field + " of " + o.getClass(), e);
        }
    }
}
