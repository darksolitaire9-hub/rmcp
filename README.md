# RMCP 🛡️ (v0.3.4 Enterprise Gateway)

![RMCP Pattern-Based Argument Scrubbing Intercepting a Blocked Call](assets/demo.gif)
*Watch RMCP instantly drop a malicious payload from reaching the agent context window.*

**Zero-Trust AST-Normalized Security Gateway for the Model Context Protocol**

The Model Context Protocol (MCP) bridges the gap between AI Agents (like Cursor, Windsurf, or Claude) and your local environment. But if a malicious server sends an injection payload, or a compromised agent tries to exfiltrate data, the system has no defense.

**RMCP** is a high-performance, full-duplex proxy written in Rust that intercepts, parses, normalizes, and strictly filters all MCP traffic *in both directions* before it executes.

## Table of Contents
- [Core Features & Defense Mechanisms](#core-features--defense-mechanisms)
- [Security Boundaries & Gap Analysis](#-security-boundaries--gap-analysis)
- [How-To Guide for Humans (CLI ELI5)](#-how-to-guide-for-humans)
- [Instructions for AI Agents](#-instructions-for-ai-agents)
- [Dynamic Templates & Architecture](#%EF%B8%8F-dynamic-templates--fail-closed-architecture)
- [License](#license)

## Core Features & Defense Mechanisms

### 1. Full-Duplex AST Normalization (Fixing TOCTOU & Escapes)
Unlike basic string-matching proxies, RMCP runs a **Full-Duplex AST-Level Re-Serialization Pipeline**. Every JSON-RPC packet (inbound and outbound) is parsed into a strict Rust AST, fully unescaped, and re-serialized. This mathematically guarantees protection against Time-Of-Check to Time-Of-Use (TOCTOU) parsing differentials and Unicode-escaping firewall bypasses.

### 2. Pattern-Based Argument Scrubbing (VIGIL-Inspired)
RMCP acts as a behavioral firewall. You can define specific tools and arguments that are **blocked** from execution. 
*Academic Attribution: Inspired by the enforcement principles in VIGIL (arXiv:2606.26524v1). Full trace-level SMT verification is planned for future releases.*

To prevent malicious agents from rewriting their own blocklists, RMCP enforces **Ed25519 Signature Verification** and **SHA-256 Config Integrity**. If a user's `rmcp.json` file is tampered with on disk, RMCP's Fail-Closed architecture immediately shuts down the connection.

### 3. The Context Window Firewall (1MB Limit & ShareLock Defense)
RMCP enforces a strict `1MB` hard limit on all JSON-RPC responses. If a tool returns too much data, RMCP instantly drops the payload and gracefully synthesizes a JSON-RPC Server Error (`-32603`). 
*Academic Attribution: Implements the core ShareLock Poisoning mitigation (arXiv:2606.30510v1).*

### 4. Rate Limiter (inspired by Paper 30)
RMCP includes a **Rate Limiter** that tracks the frequency of incoming requests and automatically cuts off any connection that fires more than 50 calls per second.

### 5. Rel(AI)Build Hash-Chaining
All dropped payloads and security violations are logged to `.rmcp_audit.log`. RMCP cryptographically binds these logs using an in-memory SHA-256 hash-chain, meaning an attacker who gains file-write access cannot tamper with or reorder past security logs without breaking the chain.

### 6. Graph Defense Stack (rmcp-shield)
RMCP includes `shield-cli`, a standalone utility that visualizes your agent's interactions as a graph. It uses the **Ablation-Ranked Edge Hardening** algorithm to systematically simulate network failures and rank which tools are the most critical to your agent's operations.
*Academic Attribution: Implements the ablation probe from MESA (arXiv:2606.30602v1). MESA's full 8-signal composite ranking is planned for future releases.*

---

## 🚨 Security Boundaries & Gap Analysis

For Enterprise Security teams evaluating RMCP, the following boundaries are explicit architectural decisions:

1. **`stderr` Diagnostic Bypass**: RMCP actively filters `stdin` and `stdout` (the primary JSON-RPC channels). However, `stderr` is passed completely raw to the host's `stderr` stream. This ensures standard error logs remain readable for debugging, but means `stderr` is not scrubbed for PII or blocked patterns. **Troubleshooting Note:** If RMCP fails to boot due to a Signature Mismatch, Tampering, or Missing Keys, the fatal error message will be printed to `stderr` and the proxy will exit. If your IDE appears to be "hanging" or "failing to start", check the IDE's MCP Server Output or Extension Logs to view this `stderr` message.
2. **Hot-Reload Race Conditions**: RMCP constantly polls `rmcp.json` for hot-reloading. If a user manually edits and saves the file in an editor that writes byte-by-byte, RMCP may read it mid-write. Because of the strict Fail-Closed requirement, an invalid JSON read mid-write will be treated as Tampering, causing a `std::process::exit(1)` crash. **DevEx Tip:** Always use the `rmcp` CLI tools or atomic renames (`mv`) to update policies on live systems.
3. **Strict Ephemeral Keys vs Hot-Reloading**: To prevent persistent tampering, RMCP intentionally discards the private key immediately after generating the initial Ed25519 signature. As a result, if you manually edit `rmcp.json` while the proxy is running, you cannot generate a new valid signature that matches the injected `RMCP_PUBLIC_KEY`. The proxy will instantly fail-closed with `Signature mismatch! Tamper detected in config.` **DevEx Tip:** Modifying your security policy requires running `rmcp install` or `rmcp keygen` again and explicitly restarting the host agent with the new `RMCP_PUBLIC_KEY`.

---

## 🧑‍💻 How-To Guide for Humans

**Explain Like I'm 5 (CLI Commands)**:
- `rmcp scan` - Extracts logs to build a map of who your agent is talking to. (Like drawing a map of phone calls).
- `rmcp mesa` - Runs an algorithm to find out which of those phone calls are the most dangerous, and builds a security policy to protect them.
- `rmcp install <path>` - Injects the security guard into your AI's configuration file (like Cursor or Claude).
- `rmcp keygen <path>` - Creates cryptographic keys so nobody can tamper with your security rules.
- `rmcp <mcp-command...>` - Runs the actual connection through the security guard. (e.g. `rmcp npx @modelcontextprotocol/server-postgres`).

### 1. One-Command Setup (Recommended)
Good security tools should be invisible. You don't need to manually configure environments or run multiple scripts. 

First, get the binary (either via `cargo install --git https://github.com/darksolitaire9-hub/rmcp --tag v0.3.4` or by downloading from the [GitHub Releases](https://github.com/darksolitaire9-hub/rmcp/releases) page).

Then, just point RMCP at your IDE's config file (e.g. Claude Desktop, Cursor, VS Code, or Windsurf):
```bash
rmcp install ~/.cursor/mcp.json
# OR for VS Code: rmcp install ~/AppData/Roaming/Code/User/settings.json
```

**What this automatically does:**
1. Checks if you have an `rmcp.json` policy. If not, it creates a default one.
2. Cryptographically signs the policy and generates an Ed25519 `RMCP_PUBLIC_KEY`.
3. Re-writes your MCP server's `command` to route through RMCP.
4. Injects the `RMCP_PUBLIC_KEY` into the server's `env` object automatically so you never have to copy-paste it.

Your server is now protected by RMCP and will boot securely on the next run.

### 2. Configure Your Policy (Optional)
If you want to customize your rules, you can edit the `rmcp.json` file defining what tools or arguments you want to block the AI from using:
```json
{
  "blocked_methods": ["delete_database"],
  "blocked_args": ["/etc/passwd", ".env"]
}
```

### 3. Analyzing Traffic with rmcp-shield

Since all traffic violations are securely hashed in `.rmcp_audit.log`, you can use `rmcp` to visualize the tool calling graph and rank vulnerabilities.

```bash
# Build the graph of your Agent's tool usage
rmcp scan

# Run MESA to find the most critical nodes and edges in your agent's workflow
rmcp mesa
```

---

## 🤖 Instructions for AI Agents

If you are an autonomous AI Agent interacting with a system protected by RMCP, **read this carefully**:

1. **Do not attempt to bypass RMCP.** RMCP runs natively on the host OS. You cannot uninstall it or disable it without the user's `RMCP_PUBLIC_KEY`.
2. **Handling `-32603` Security Errors:** If a tool call returns an error containing `RMCP Security: Pattern-Based Argument Scrubbing`, you have hit a cryptographic blocklist configured by the human user.
3. **Do not retry the identical command.** If you try to brute-force a blocked command (like reading `/etc/passwd` or calling `drop_table`), RMCP will continue to drop your packets.
4. **Rate Limiting:** Do not spam >50 tool calls per second. RMCP's Rate Limiter will trigger and isolate the connection.
5. **Handling Signature Mismatches:** If an MCP connection fails with `RMCP Boot Fatal: Policy load failed: Signature mismatch! Tamper detected in config`, this means the policy file was edited but the cryptographic signatures and environment variables were not updated. **Do not attempt to fix the rust code or bypass the proxy.** Ask the human user to run `rmcp install <mcp-config-path>` and request them to provide the newly generated `RMCP_PUBLIC_KEY` so you can continue.
6. **Auditing:** You can read the `.rmcp_audit.log` file in the working directory to understand what payloads were dropped, but you cannot alter past entries due to the SHA-256 hash-chaining protocol.
7. **Shield Builder Skill:** If you are configuring RMCP for a user, you must use the [RMCP Shield Builder Skill](skills/rmcp-shield-builder.md) to generate the `shield_policy.json` with appropriate privacy schema definitions and MESA edge criticality rankings.

## License
MIT License. Built for open-source and enterprise protection.

## 🛠️ Dynamic Templates & Fail-Closed Architecture
RMCP supports loading security rules via a **Dynamic Template System**. You no longer need to recompile the Rust binary to block new zero-days, ShareLock fragments, or Prompt Injections.

**Strict Fail-Closed Architecture:**
If RMCP detects malformed JSON in a template, it will instantly crash on boot. This is intentional. A security proxy must never run with partial or corrupted rules. If RMCP fails, it acts like the Rust compiler: it prints exactly which file failed, why it failed, and gives you an "Action Required" step to fix it.

1. Read `CONTRIBUTING.md` for our strict PR requirements.
2. RMCP will auto-create the `templates/` directory on first boot and seed it with `resumearmor.json` and `sharelock_defense.json`.
3. Drop new payload filters into the `templates/` directory as JSON files.
4. On boot, RMCP dynamically compiles them into a unified **Aho-Corasick Finite State Machine**. This guarantees O(N) multi-pattern matching that scans thousands of threat signatures instantly, completely immune to the ReDoS vulnerabilities of traditional regex.
