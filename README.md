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

### 3. Sign Your Policy (1-Step Process)
Run the native Key Generator against your config file:
```bash
rmcp --keygen rmcp.json
```
**Output:**
```
✅ Security Lockfile Generated: rmcp.json.lock
🔑 RMCP_PUBLIC_KEY: 8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c
Store this key safely and pass it to RMCP via the RMCP_PUBLIC_KEY environment variable.
```

### 4. Run the Proxy
Set the environment variables and prepend `rmcp` to your MCP server command in Cursor or your IDE:

**Before:**
```json
{
  "mcpServers": {
    "my-server": {
      "command": "node",
      "args": ["server.js"]
    }
  }
}
```

**After:**
```json
{
  "mcpServers": {
    "my-server": {
      "command": "/path/to/rmcp",
      "args": ["node", "server.js"],
      "env": {
        "RMCP_CONFIG_PATH": "/path/to/rmcp.json",
        "RMCP_PUBLIC_KEY": "8a88e3..."
      }
    }
  }
}
```

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

## 🛠️ Dynamic Templates & Contributing
RMCP now supports loading security rules via a **Dynamic Template System**. You no longer need to recompile the Rust binary to block new zero-days or ShareLock fragments.

1. Read `CONTRIBUTING.md` for our strict PR requirements.
2. Drop new payload filters and regex rules into the `templates/` directory as JSON files.
3. RMCP reads them dynamically at runtime.
