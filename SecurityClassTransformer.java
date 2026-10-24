package com.rasp;

import org.objectweb.asm.*;
import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;

public class SecurityClassTransformer implements ClassFileTransformer {
    @Override
    public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                            ProtectionDomain protectionDomain, byte[] classfileBuffer) {

        if (!"java/lang/ProcessBuilder".equals(className)) {
            return null;
        }

        try {
            // Save original JDK classfile major version and temporarily set to Java 17 (61)
            // so ASM 9.6 never fails on newer JDKs (JDK 23/24/25+)
            byte origMajorHi = classfileBuffer[6];
            byte origMajorLo = classfileBuffer[7];
            byte[] bufferCopy = classfileBuffer.clone();
            bufferCopy[6] = 0;
            bufferCopy[7] = 61;

            ClassReader reader = new ClassReader(bufferCopy);
            ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_MAXS);

            reader.accept(new ClassVisitor(Opcodes.ASM9, writer) {
                @Override
                public MethodVisitor visitMethod(int access, String name, String descriptor,
                                                 String signature, String[] exceptions) {
                    MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);

                    if ("start".equals(name) && "()Ljava/lang/Process;".equals(descriptor)) {
                        System.out.println("[RASP-TRANSFORMER] Injected SecurityGuard hook into ProcessBuilder.start()!");
                        return new MethodVisitor(Opcodes.ASM9, mv) {
                            @Override
                            public void visitCode() {
                                super.visitCode();
                                super.visitVarInsn(Opcodes.ALOAD, 0);
                                super.visitMethodInsn(
                                        Opcodes.INVOKEVIRTUAL,
                                        "java/lang/ProcessBuilder",
                                        "command",
                                        "()Ljava/util/List;",
                                        false
                                );
                                super.visitMethodInsn(
                                        Opcodes.INVOKESTATIC,
                                        "com/rasp/SecurityGuard",
                                        "inspectCommand",
                                        "(Ljava/util/List;)V",
                                        false
                                );
                            }
                        };
                    }
                    return mv;
                }
            }, 0);

            byte[] transformed = writer.toByteArray();
            // Restore original JDK classfile major version
            transformed[6] = origMajorHi;
            transformed[7] = origMajorLo;
            return transformed;

        } catch (Throwable t) {
            System.err.println("[RASP-TRANSFORMER ERROR] Failed to transform ProcessBuilder:");
            t.printStackTrace();
            return null;
        }
    }
}