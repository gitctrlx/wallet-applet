// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.sim;

import com.licel.jcardsim.base.SimulatorRuntime;
import com.licel.jcardsim.crypto.ByteContainer;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.List;
import javacard.framework.JCSystem;
import javacard.framework.SystemException;
import javacard.framework.TransactionException;
import javacard.security.Key;

/**
 * Card A runtime model (architecture spec section 8): command-local persistent-write counting, an
 * armed tear point, the transaction journal with measured commit-buffer accounting, and the
 * measured transient pool. The {@link Agent} routes applet bytecode writes through {@link
 * Nvm}/{@link Memory}, which land here.
 *
 * <p>The journal records byte-level pre-images of persistent arrays and reflective pre-images of
 * {@link ByteContainer}-backed key fields, so abort and power loss restore the same state a real
 * commit buffer would have held. The buffer is charged in 1024 B spans per touched array and in
 * measured flat amounts for key writes (512 B setters, 1024 B {@code setW}/{@code genKeyPair}),
 * capped at 5120 B.
 */
public final class CardRuntime extends SimulatorRuntime {

    enum Phase {
        INSTALL,
        COMMAND
    }

    public static final int MAX_COMMIT = 5120;
    public static final int COMMIT_SPAN = 1024;
    public static final int COMMIT_PAGE = 512;
    public static final int SET_KEY_CHARGE = 512;
    public static final int SET_W_CHARGE = 1024;
    public static final int KEY_GEN_CHARGE = 1024;
    public static final int TRANSIENT_POOL = 3990;
    public static final int TRANSIENT_BUDGET = 3990;

    private static final ThreadLocal<CardRuntime> CURRENT = new ThreadLocal<>();

    static CardRuntime current() {
        return CURRENT.get();
    }

    private Phase phase;
    private int writes;
    private int armedWrite;
    private int commitUsed;
    private int lastCommitBytes;
    private final List<Integer> commits = new ArrayList<>();
    private final List<Runnable> journal = new ArrayList<>();
    private final IdentityHashMap<Object, int[]> spans = new IdentityHashMap<>();
    private final IdentityHashMap<Object, Object> keySnapshots = new IdentityHashMap<>();
    private final Object[] apduBuffers;
    private int transientUsed;
    private final List<String> transientAllocations = new ArrayList<>();

    public CardRuntime() {
        apduBuffers = new Object[] {shortAPDU.getBuffer(), extendedAPDU.getBuffer()};
    }

    void bind(Phase newPhase) {
        CURRENT.set(this);
        phase = newPhase;
    }

    void unbind() {
        CURRENT.remove();
        phase = null;
    }

    void startCommand() {
        writes = 0;
        commits.clear();
        // lastCommitBytes intentionally survives: it reports the last
        // transaction's commit-buffer consumption until the next one ends
        bind(Phase.COMMAND);
    }

    boolean inCommand() {
        return phase == Phase.COMMAND;
    }

    /**
     * Persistent arrays are every array the applet can reach that is neither registered transient
     * memory nor an APDU buffer.
     */
    boolean isPersistentArray(Object array) {
        if (array == null) {
            return false;
        }
        for (Object buffer : apduBuffers) {
            if (array == buffer) {
                return false;
            }
        }
        return transientMemory.isTransient(array) == JCSystem.NOT_A_TRANSIENT_OBJECT;
    }

    /**
     * One atomic persistent write of {@code length} bytes at {@code offset}: commit-buffer check,
     * write counter/tear point, then span accounting and pre-image journaling while a transaction
     * is open. The store itself happens in {@link Nvm} after this call returns, so a {@link
     * PowerLoss} here leaves it unwritten.
     */
    void arrayWrite(Object array, int offset, int length) {
        int delta = 0;
        if (transactionDepth != 0) {
            delta = spanDelta(array, offset, offset + length);
            checkCommitCapacity(delta);
        }
        countWrite();
        if (transactionDepth != 0) {
            applySpan(array, offset, offset + length);
            journalArray(array, offset, length);
            commitUsed += delta;
        }
    }

    /**
     * A non-atomic write point: counted and tearable, never journaled or charged, so a torn copy
     * can stop half-written (patch 5).
     */
    void arrayWritePoint() {
        countWrite();
    }

    /**
     * A persistent key-object write: flat commit-buffer charge, one counted write, and a one-time
     * reflective snapshot of the key's {@link ByteContainer} fields while a transaction is open.
     */
    void keyWrite(Object key, int charge) {
        if (transactionDepth != 0) {
            checkCommitCapacity(charge);
        }
        countWrite();
        if (transactionDepth != 0) {
            commitUsed += charge;
            snapshotKeyOnce(key);
        }
    }

    /** {@code KeyPair.genKeyPair}: one shared 1024 B charge, both keys snapshotted. */
    void keyPairWrite(Object publicKey, Object privateKey) {
        if (transactionDepth != 0) {
            checkCommitCapacity(KEY_GEN_CHARGE);
        }
        countWrite();
        if (transactionDepth != 0) {
            commitUsed += KEY_GEN_CHARGE;
            if (publicKey instanceof Key && !Nvm.isTransientKeyType(((Key) publicKey).getType())) {
                snapshotKeyOnce(publicKey);
            }
            if (privateKey instanceof Key
                    && !Nvm.isTransientKeyType(((Key) privateKey).getType())) {
                snapshotKeyOnce(privateKey);
            }
        }
    }

    /**
     * The command's persistent-write counter and the armed tear point. Only command-phase writes
     * count; firing throws {@link PowerLoss} before the write it was armed on takes effect, so
     * write N of a torn command leaves exactly writes 1..N-1 applied.
     */
    private void countWrite() {
        if (phase != Phase.COMMAND) {
            return;
        }
        writes++;
        if (armedWrite > 0 && writes >= armedWrite) {
            armedWrite = 0;
            throw new PowerLoss();
        }
    }

    /**
     * Grow the touched span of {@code array} to cover [{@code lo}, {@code hiExclusive}) and return
     * the extra commit bytes the merged span costs: every started 512 B page bills two pages, so
     * span charge = ceil(spanBytes / 512) * 1024 (audit F-6).
     */
    private int spanDelta(Object array, int lo, int hiExclusive) {
        int[] span = spans.get(array);
        int newLo = span == null ? lo : Math.min(span[0], lo);
        int newHi = span == null ? hiExclusive : Math.max(span[1], hiExclusive);
        int oldCharge = span == null ? 0 : spanCharge(span[1] - span[0]);
        return spanCharge(newHi - newLo) - oldCharge;
    }

    private void applySpan(Object array, int lo, int hiExclusive) {
        int[] span = spans.get(array);
        if (span == null) {
            spans.put(array, new int[] {lo, hiExclusive});
        } else {
            span[0] = Math.min(span[0], lo);
            span[1] = Math.max(span[1], hiExclusive);
        }
    }

    private static int spanCharge(int spanBytes) {
        return ((spanBytes + COMMIT_PAGE - 1) / COMMIT_PAGE) * COMMIT_SPAN;
    }

    private void checkCommitCapacity(int delta) {
        if (commitUsed + delta > MAX_COMMIT) {
            TransactionException.throwIt(TransactionException.BUFFER_FULL);
        }
    }

    private void journalArray(Object array, int offset, int length) {
        if (array instanceof byte[] bytes) {
            byte[] preimage = new byte[length];
            System.arraycopy(bytes, offset, preimage, 0, length);
            journal.add(() -> System.arraycopy(preimage, 0, bytes, offset, length));
        } else if (array instanceof short[] shorts) {
            short[] preimage = new short[length];
            System.arraycopy(shorts, offset, preimage, 0, length);
            journal.add(() -> System.arraycopy(preimage, 0, shorts, offset, length));
        } else if (array instanceof boolean[] booleans) {
            boolean[] preimage = new boolean[length];
            System.arraycopy(booleans, offset, preimage, 0, length);
            journal.add(() -> System.arraycopy(preimage, 0, booleans, offset, length));
        }
    }

    /**
     * Snapshot the key's writable {@link ByteContainer} fields and scalar state once per
     * transaction; the undo entry restores all of them, which is what a real commit buffer covering
     * key EEPROM does.
     */
    private void snapshotKeyOnce(Object key) {
        if (keySnapshots.containsKey(key)) {
            return;
        }
        List<Object[]> saved = new ArrayList<>();
        for (Class<?> c = key.getClass(); c != null; c = c.getSuperclass()) {
            for (Field field : c.getDeclaredFields()) {
                if (Modifier.isStatic(field.getModifiers()) || field.isSynthetic()) {
                    continue;
                }
                try {
                    field.setAccessible(true);
                    if (ByteContainer.class.isAssignableFrom(field.getType())) {
                        ByteContainer container = (ByteContainer) field.get(key);
                        if (container != null) {
                            saved.add(new Object[] {field, container.save(), Boolean.TRUE});
                        }
                    } else {
                        saved.add(new Object[] {field, field.get(key), Boolean.FALSE});
                    }
                } catch (ReflectiveOperationException | RuntimeException e) {
                    // field not readable or save() not possible; skip
                }
            }
        }
        keySnapshots.put(key, saved);
        journal.add(() -> restoreKey(key, saved));
    }

    private static void restoreKey(Object key, List<Object[]> saved) {
        for (Object[] record : saved) {
            Field field = (Field) record[0];
            try {
                if (record[2] == Boolean.TRUE) {
                    ((ByteContainer) field.get(key)).restore(record[1]);
                } else {
                    field.set(key, record[1]);
                }
            } catch (ReflectiveOperationException | RuntimeException e) {
                throw new IllegalStateException("journal restore failed for " + field, e);
            }
        }
    }

    @Override
    public void beginTransaction() {
        super.beginTransaction();
        journal.clear();
        spans.clear();
        keySnapshots.clear();
        commitUsed = 0;
    }

    @Override
    public void commitTransaction() {
        super.commitTransaction();
        recordCommit();
        journal.clear();
        spans.clear();
        keySnapshots.clear();
    }

    @Override
    public void abortTransaction() {
        super.abortTransaction();
        rollback();
        recordCommit();
    }

    private void rollback() {
        for (int i = journal.size() - 1; i >= 0; i--) {
            journal.get(i).run();
        }
        journal.clear();
        spans.clear();
        keySnapshots.clear();
    }

    private void recordCommit() {
        lastCommitBytes = commitUsed;
        commits.add(commitUsed);
        commitUsed = 0;
    }

    /**
     * Power loss while a transaction is open rolls the buffer back before the card resets, so the
     * next power-up sees pre-transaction state (patch 5).
     */
    void powerLoss() {
        if (transactionDepth != 0) {
            rollback();
            recordCommit();
            transactionDepth = 0;
        }
        armedWrite = 0;
        reset();
    }

    @Override
    public void reset() {
        super.reset();
        journal.clear();
        spans.clear();
        keySnapshots.clear();
        commitUsed = 0;
        armedWrite = 0;
    }

    void armTear(int n) {
        armedWrite = n;
    }

    int writes() {
        return writes;
    }

    int lastCommitBytes() {
        return lastCommitBytes;
    }

    List<Integer> commits() {
        return List.copyOf(commits);
    }

    /** Measured 5120 B commit buffer (audit-impl card memory dump). */
    @Override
    public short getMaxCommitCapacity() {
        return MAX_COMMIT;
    }

    @Override
    public short getUnusedCommitCapacity() {
        return (short) (MAX_COMMIT - commitUsed);
    }

    @Override
    public short getAvailableTransientResetMemory() {
        return (short) (TRANSIENT_POOL - transientUsed);
    }

    @Override
    public short getAvailableTransientDeselectMemory() {
        return (short) (TRANSIENT_POOL - transientUsed);
    }

    /**
     * Charge {@code bytes} against the shared 3990 B transient pool and record the allocation for
     * {@link #memoryReport()}.
     */
    void chargeTransient(int bytes, String description) {
        if (transientUsed + bytes > TRANSIENT_POOL) {
            SystemException.throwIt(SystemException.NO_TRANSIENT_SPACE);
        }
        transientUsed += bytes;
        transientAllocations.add(description + " " + bytes);
    }

    /**
     * Reject engine instances card A does not support or measure; creating one must fail loudly
     * rather than simulate unmeasured memory (patch 6).
     */
    void rejectUnmeasured(String what) {
        throw new IllegalStateException("unmeasured engine on card A: " + what);
    }

    int transientUsed() {
        return transientUsed;
    }

    String memoryReport() {
        StringBuilder report = new StringBuilder();
        for (String allocation : transientAllocations) {
            report.append(allocation).append('\n');
        }
        report.append("total ")
                .append(transientUsed)
                .append(" / ")
                .append(TRANSIENT_POOL)
                .append(" (budget ")
                .append(TRANSIENT_BUDGET)
                .append(')');
        return report.toString();
    }
}
