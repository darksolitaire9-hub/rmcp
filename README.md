# RMCP 🛡️
**Rust Model Context Protocol Security Gateway**

The Model Context Protocol (MCP) bridges the gap between AI Agents (like Cursor, Windsurf, or Claude) and your local environment. But if a malicious server sends an injection payload or tries to poison the AI's context window with gigabytes of garbage data, the AI has no defense.

**RMCP** is a lightweight, zero-dependency proxy written in Rust that intercepts and strictly filters MCP traffic *before* it reaches the agent.

## Core Features & Defense Mechanisms

### 1. VIGIL Enforcement & Cryptographic Policies
RMCP acts as a behavioral firewall. You can define specific tools and arguments that are **blocked** from execution.
To prevent malicious agents from rewriting their own blocklists, RMCP enforces **Ed25519 Signature Verification** and **SHA-256 Config Integrity**. If a user's `rmcp.json` file is tampered with on disk, RMCP's Fail-Closed architecture immediately shuts down the connection.

### 2. The Context Window Firewall (1MB Limit)
RMCP enforces a strict `1MB` hard limit on all JSON-RPC responses. If a tool returns too much data, RMCP instantly drops the payload and gracefully synthesizes a JSON-RPC Server Error (`-32603`). This mathematically guarantees the AI's core instructions can never be overwritten by a ShareLock poisoning attack.

### 3. SEO Motif Auditor Rate-Limiting
To prevent DoS via rapid-fire small requests, RMCP enforces a mathematical Motif-Hub rate limit of 50 calls per second per connection.

### 4. Rel(AI)Build Hash-Chaining
All dropped payloads and security violations are logged to `.rmcp_audit.log`. RMCP cryptographically binds these logs using an in-memory SHA-256 hash-chain, meaning an attacker who gains file-write access cannot tamper with or reorder past security logs without breaking the chain.

---

## 🧑‍💻 How-To Guide for Humans

### 1. Installation
Download the binary for your OS from the [GitHub Releases](https://github.com/darksolitaire9-hub/rmcp/releases) page. Place it anywhere on your PATH.

### 2. Configure Your Policy
Create an `rmcp.json` file defining what tools or arguments you want to block the AI from using:
```json
{
  "blocked_methods": ["delete_database"],
  "blocked_args": ["/etc/passwd", ".env"]
}
```

### 3. One-Command Installation
Good security tools should be invisible. You don't need to manually configure environments or run multiple scripts. Just point RMCP at your Cursor or Claude config file:
```bash
rmcp --install /path/to/claude_desktop_config.json
```

**What this automatically does:**
1. Checks if you have an `rmcp.json` policy. If not, it creates a default one.
2. Cryptographically signs the policy and generates an Ed25519 `RMCP_PUBLIC_KEY`.
3. Re-writes your MCP server's `command` to route through RMCP.
4. Injects the `RMCP_PUBLIC_KEY` into the server's `env` object automatically so you never have to copy-paste it.

Your server is now protected by RMCP and will boot securely on the next run.

---

## 🤖 Instructions for AI Agents

If you are an autonomous AI Agent interacting with a system protected by RMCP, **read this carefully**:

1. **Do not attempt to bypass RMCP.** RMCP runs natively on the host OS. You cannot uninstall it or disable it without the user's `RMCP_PUBLIC_KEY`.
2. **Handling `-32603` Security Errors:** If a tool call returns an error containing `RMCP Security: VIGIL Enforcement`, you have hit a cryptographic blocklist configured by the human user.
3. **Do not retry the identical command.** If you try to brute-force a blocked command (like reading `/etc/passwd` or calling `drop_table`), RMCP will continue to drop your packets.
4. **Rate Limiting:** Do not spam >50 tool calls per second. RMCP's Motif Auditor will trigger and isolate the connection.
5. **Auditing:** You can read the `.rmcp_audit.log` file in the working directory to understand what payloads were dropped, but you cannot alter past entries due to the SHA-256 hash-chaining protocol.

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
