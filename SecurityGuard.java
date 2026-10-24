package com.rasp;

import java.nio.file.Paths;
import java.time.Instant;
import java.util.List;
import java.util.Set;

public class SecurityGuard {

    // Permitted diagnostic binaries
    private static final Set<String> ALLOWED_BINARIES = Set.of(
            "ping", "ping.exe", "uptime", "whoami", "whoami.exe"
    );

    // Dangerous shell chaining or injection tokens in arguments
    private static final List<String> FORBIDDEN_ARG_PATTERNS = List.of(
            ";", "|", "&", "`", "$(", "/etc/passwd", "/etc/shadow", "-exec"
    );

    public static void inspectCommand(List<String> commandArgs) {
        String caller = resolveApplicationCaller();

        if (commandArgs == null || commandArgs.isEmpty()) {
            logAndBlock("EMPTY_COMMAND", "[]", caller);
        }

        String rawBinary = commandArgs.get(0);
        String binaryName = Paths.get(rawBinary).getFileName().toString().toLowerCase();

        // 1. Enforce strict binary allowlist (blocks /bin/sh, bash, curl, nc, python, calc.exe)
        if (!ALLOWED_BINARIES.contains(binaryName)) {
            logAndBlock("UNAUTHORIZED_BINARY (" + binaryName + ")", commandArgs.toString(), caller);
        }

        // 2. Inspect arguments passed to allowed binaries
        for (int i = 1; i < commandArgs.size(); i++) {
            String arg = commandArgs.get(i);
            for (String pattern : FORBIDDEN_ARG_PATTERNS) {
                if (arg.contains(pattern)) {
                    logAndBlock("MALICIOUS_ARGUMENT (" + pattern + ")", commandArgs.toString(), caller);
                }
            }
        }

        System.out.printf(
                "[RASP-TELEMETRY] %s | ACTION=ALLOWED | CMD=%s | SOURCE=%s%n",
                Instant.now(), commandArgs, caller
        );
    }

    private static void logAndBlock(String reason, String command, String caller) {
        System.err.printf(
                "[RASP-ALERT]     %s | ACTION=BLOCKED | REASON=%s | CMD=%s | VULNERABLE_CODE=%s%n",
                Instant.now(), reason, command, caller
        );
        throw new SecurityException("RASP blocked command execution [" + reason + "]");
    }

    // Walks the JVM stack to pinpoint the exact application class and line number
    private static String resolveApplicationCaller() {
        for (StackTraceElement frame : Thread.currentThread().getStackTrace()) {
            String cls = frame.getClassName();
            if (!cls.startsWith("java.lang.")
                    && !cls.startsWith("com.rasp.")
                    && !cls.startsWith("jdk.internal.")) {
                return frame.toString();
            }
        }
        return "UnknownSource";
    }
}