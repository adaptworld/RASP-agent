package com.rasp;

import java.io.File;
import java.lang.instrument.Instrumentation;
import java.util.jar.JarFile;

public class RaspAgent {

    // Invoked when attached at JVM startup via -javaagent
    public static void premain(String agentArgs, Instrumentation inst) {
        install(inst, "STARTUP (-javaagent)");
    }

    // Invoked when hot-attached to a live running JVM via jcmd
    public static void agentmain(String agentArgs, Instrumentation inst) {
        install(inst, "LIVE HOT-ATTACH (jcmd)");
    }

    private static synchronized void install(Instrumentation inst, String mode) {
        System.out.println("\n[RASP-AGENT] Attaching to JVM via " + mode + "...");
        try {
            File agentJar = new File(
                    RaspAgent.class.getProtectionDomain().getCodeSource().getLocation().toURI()
            );
            inst.appendToBootstrapClassLoaderSearch(new JarFile(agentJar));

            inst.addTransformer(new SecurityClassTransformer(), true);
            inst.retransformClasses(ProcessBuilder.class);

            System.out.println("[RASP-AGENT] Active! Hooked java.lang.ProcessBuilder.start() globally.\n");
        } catch (Exception e) {
            System.err.println("[RASP-AGENT] Installation failed: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
