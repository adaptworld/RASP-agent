# RASP-Agent (Runtime Application Self-Protection)

A lightweight Java RASP (Runtime Application Self-Protection) agent that dynamically hooks into the JVM bytecode using **ASM** to intercept and block OS command injection attempts in real-time.

---

## Features

* **Dual Attachment Support**: Works both at JVM startup (`-javaagent`) and dynamically live hot-attached via `jcmd`.


* **Bytecode Instrumentation**: Uses ASM 9 to instrument `java.lang.ProcessBuilder.start()` without requiring changes to application source code.


* **Strict Binary Allowlist**: Enforces an allowlist for permitted binaries (e.g., `ping`, `whoami`, `uptime`) and blocks unauthorized executables (e.g., `bash`, `sh`, `nc`, `calc.exe`).


* **Command Injection Defense**: Inspects arguments for dangerous shell chaining and injection tokens (`;`, `|`, `&`, ```, `$()`, `/etc/passwd`, `-exec`).


* **Caller Telemetry & Stack Inspection**: Identifies the exact application class and line number responsible for triggering execution.



---

## How It Works

1. **Attachment**: When loaded, `RaspAgent` injects its classes into the bootstrap class loader and registers `SecurityClassTransformer`.


2. **Bytecode Transformation**: The transformer targets `java.lang.ProcessBuilder.start()` and injects a static call to `SecurityGuard.inspectCommand()` prior to process creation.


3. **Inspection & Enforcement**: `SecurityGuard` evaluates the command binary and arguments:


* **Allowed**: Execution continues, and telemetry is logged.


* **Blocked**: A `SecurityException` is thrown, aborting the process execution immediately.





---

## Building the Agent

### Prerequisites

* JDK 17 or higher
* Apache Maven (or Gradle)
* `org.objectweb.asm:asm:9.x` dependency

### Building the JAR

Ensure your build configuration includes the required manifest attributes:

```manifest
Premain-Class: com.rasp.RaspAgent
Agent-Class: com.rasp.RaspAgent
Can-Retransform-Classes: true

```

Build the JAR using Maven:

```bash
mvn clean package

```

---

## Usage

### 1. Startup Mode (`-javaagent`)

Pass the agent to the target Java application during startup:

```bash
java -javaagent:path/to/rasp-agent.jar -jar your-application.jar

```

### 2. Hot-Attach Mode (`jcmd`)

Attach the agent to an already running JVM process without stopping it:

```bash
jcmd <PID> JVMTI.agent_load /path/to/rasp-agent.jar

```

---

## Security Policy Summary

| Rule | Details |
| --- | --- |
| **Allowed Binaries** | `ping`, `ping.exe`, `uptime`, `whoami`, `whoami.exe`

 |
| **Blocked Characters/Tokens** | `;`, `|`, `&`, ```, `$()`, `/etc/passwd`, `/etc/shadow`, `-exec`

 |
| **Enforcement Action** | Throws `java.lang.SecurityException`

 |