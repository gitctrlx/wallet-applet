// SPDX-FileCopyrightText: 2026 QuantX
// SPDX-License-Identifier: AGPL-3.0-or-later
package org.qntx.card.sim;

import java.lang.classfile.ClassFile;
import java.lang.classfile.ClassHierarchyResolver;
import java.lang.classfile.ClassTransform;
import java.lang.classfile.CodeBuilder;
import java.lang.classfile.CodeElement;
import java.lang.classfile.CodeTransform;
import java.lang.classfile.Label;
import java.lang.classfile.Opcode;
import java.lang.classfile.instruction.ArrayStoreInstruction;
import java.lang.classfile.instruction.ExceptionCatch;
import java.lang.classfile.instruction.FieldInstruction;
import java.lang.classfile.instruction.InvokeInstruction;
import java.lang.constant.ClassDesc;
import java.lang.constant.MethodTypeDesc;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Java agent that weaves persistent-memory hooks into applet bytecode (architecture spec section 8,
 * patch 5). It runs on {@code -javaagent} with a comma-separated list of instrumented package
 * names, e.g. {@code -javaagent:sim-agent.jar=org/qntx/card/sim/probe}.
 *
 * <p>Per instrumented class it replaces {@code bastore}/{@code sastore}, rewrites {@code
 * Util.arrayCopy*}/{@code setShort}, {@code JCSystem.makeTransient*}, factory {@code getInstance}
 * calls and {@code KeyBuilder.buildKey*} through {@link Nvm}/{@link Memory}, and prepends a {@link
 * Nvm#rethrowPowerLoss} stub to every exception handler so a {@link PowerLoss} skips handler bodies
 * entirely.
 */
public final class Agent {

    private static final ClassDesc NVM = ClassDesc.of("org.qntx.card.sim.Nvm");
    private static final ClassDesc MEMORY = ClassDesc.of("org.qntx.card.sim.Memory");

    private static volatile boolean installed;

    private Agent() {}

    public static void premain(String args, Instrumentation inst) {
        // no -javaagent argument: instrument the applet package
        if (args == null || args.isEmpty()) {
            args = "org/qntx/card";
        }
        Set<String> packages = new HashSet<>(Arrays.asList(args.split(",")));
        inst.addTransformer(new AppletTransformer(packages));
        installed = true;
    }

    /** True once {@link #premain} ran; {@link Card} refuses to work without it. */
    public static boolean installed() {
        return installed;
    }

    private static final class AppletTransformer implements ClassFileTransformer {

        private final Set<String> packages;

        AppletTransformer(Set<String> packages) {
            this.packages = packages;
        }

        @Override
        public byte[] transform(
                ClassLoader loader,
                String className,
                Class<?> classBeingRedefined,
                ProtectionDomain protectionDomain,
                byte[] classfileBuffer) {
            if (className == null) {
                return null;
            }
            int slash = className.lastIndexOf('/');
            if (slash < 0 || !packages.contains(className.substring(0, slash))) {
                return null;
            }
            try {
                // defaultResolver() reads the system class path, which does
                // not contain the javacard supertypes; resolve hierarchy
                // questions through the defining loader instead so stack
                // maps can be recomputed.
                ClassHierarchyResolver resolver =
                        ClassHierarchyResolver.ofResourceParsing(loader)
                                .orElse(ClassHierarchyResolver.defaultResolver());
                ClassFile cf =
                        ClassFile.of(
                                ClassFile.StackMapsOption.GENERATE_STACK_MAPS,
                                ClassFile.ClassHierarchyResolverOption.of(resolver));
                return cf.transformClass(
                        cf.parse(classfileBuffer),
                        ClassTransform.transformingMethodBodies(
                                CodeTransform.ofStateful(HookTransform::new)));
            } catch (RuntimeException e) {
                throw new IllegalStateException("sim agent failed to transform " + className, e);
            }
        }
    }

    private static final class HookTransform implements CodeTransform {

        private List<AbstractMap.SimpleEntry<Label, Label>> stubs;

        @Override
        public void atStart(CodeBuilder builder) {
            stubs = new ArrayList<>();
        }

        @Override
        public void accept(CodeBuilder builder, CodeElement element) {
            switch (element) {
                case ArrayStoreInstruction store -> rewriteArrayStore(builder, store);
                case FieldInstruction field -> rewriteFieldStore(builder, field);
                case InvokeInstruction invoke -> rewriteInvoke(builder, invoke);
                case ExceptionCatch handler -> redirectHandler(builder, handler);
                default -> builder.with(element);
            }
        }

        @Override
        public void atEnd(CodeBuilder builder) {
            for (AbstractMap.SimpleEntry<Label, Label> stub : stubs) {
                builder.labelBinding(stub.getKey());
                builder.dup();
                builder.invokestatic(
                        NVM,
                        "rethrowPowerLoss",
                        MethodTypeDesc.ofDescriptor("(Ljava/lang/Throwable;)V"));
                builder.goto_(stub.getValue());
            }
            stubs = null;
        }

        private void rewriteArrayStore(CodeBuilder builder, ArrayStoreInstruction store) {
            if (store.opcode() == Opcode.BASTORE) {
                builder.invokestatic(
                        NVM, "bastore", MethodTypeDesc.ofDescriptor("(Ljava/lang/Object;II)V"));
            } else if (store.opcode() == Opcode.SASTORE) {
                builder.invokestatic(NVM, "sastore", MethodTypeDesc.ofDescriptor("([SII)V"));
            } else {
                builder.with(store);
            }
        }

        private void rewriteFieldStore(CodeBuilder builder, FieldInstruction field) {
            if (field.opcode() == Opcode.PUTFIELD || field.opcode() == Opcode.PUTSTATIC) {
                builder.invokestatic(NVM, "field", MethodTypeDesc.ofDescriptor("()V"));
            }
            builder.with(field);
        }

        private void redirectHandler(CodeBuilder builder, ExceptionCatch handler) {
            Label stub = builder.newLabel();
            stubs.add(new AbstractMap.SimpleEntry<>(stub, handler.handler()));
            builder.exceptionCatch(handler.tryStart(), handler.tryEnd(), stub, handler.catchType());
        }

        private void rewriteInvoke(CodeBuilder builder, InvokeInstruction invoke) {
            if (invoke.opcode() != Opcode.INVOKESTATIC) {
                builder.with(invoke);
                return;
            }
            String owner = invoke.method().owner().name().stringValue();
            String name = invoke.method().name().stringValue();
            String desc = invoke.method().type().stringValue();
            ClassDesc target =
                    switch (owner) {
                        case "javacard/framework/Util" ->
                                switch (name) {
                                    case "arrayCopy",
                                            "arrayCopyNonAtomic",
                                            "arrayFillNonAtomic",
                                            "setShort" ->
                                            NVM;
                                    default -> null;
                                };
                        case "javacard/framework/JCSystem" ->
                                switch (name) {
                                    case "makeTransientByteArray",
                                            "makeTransientShortArray",
                                            "makeTransientBooleanArray",
                                            "makeTransientObjectArray" ->
                                            MEMORY;
                                    default -> null;
                                };
                        case "javacard/security/KeyBuilder" ->
                                switch (name) {
                                    case "buildKey", "buildKeyWithSharedDomain" -> MEMORY;
                                    default -> null;
                                };
                        case "javacardx/crypto/Cipher" ->
                                "getInstance".equals(name) ? MEMORY : null;
                        case "javacard/security/Signature" ->
                                "getInstance".equals(name) ? MEMORY : null;
                        case "javacard/security/MessageDigest" ->
                                "getInstance".equals(name) ? MEMORY : null;
                        case "javacard/security/KeyAgreement" ->
                                "getInstance".equals(name) ? MEMORY : null;
                        case "javacard/security/RandomData" ->
                                "getInstance".equals(name) ? MEMORY : null;
                        default -> null;
                    };
            if (target != null) {
                String hook =
                        target == MEMORY && "getInstance".equals(name) ? engineHook(owner) : name;
                builder.invokestatic(target, hook, MethodTypeDesc.ofDescriptor(desc));
            } else {
                builder.with(invoke);
            }
        }

        private static String engineHook(String owner) {
            return switch (owner) {
                case "javacardx/crypto/Cipher" -> "cipher";
                case "javacard/security/Signature" -> "signature";
                case "javacard/security/MessageDigest" -> "messageDigest";
                case "javacard/security/KeyAgreement" -> "keyAgreement";
                case "javacard/security/RandomData" -> "randomData";
                default -> throw new IllegalArgumentException(owner);
            };
        }
    }
}
