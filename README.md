# RMCP 🛡️
**Rust Model Context Protocol Security Gateway**

The Model Context Protocol (MCP) bridges the gap between AI Agents (like Cursor, Windsurf, or Claude) and your local environment. But if a malicious server sends an injection payload or tries to poison the AI's context window with gigabytes of garbage data, the AI has no defense.

**RMCP** is a lightweight, zero-dependency proxy written in Rust that intercepts and strictly filters MCP traffic *before* it reaches the agent.

## Core Features & Defense Mechanisms

### 1. The Context Window Firewall (1MB Limit)
**Why does the 1MB limit exist?**
LLMs have a finite "Context Window" (short-term memory). When this memory fills up, the oldest tokens are permanently forgotten. A known exploit against MCP servers is *Context Window Poisoning* (or the ShareLock attack), where a malicious tool returns 50MB of junk data. This pushes the AI's core "Safety Instructions" and "System Prompt" entirely out of memory, effectively "lobotomizing" the AI and opening it to prompt injection.

RMCP enforces a strict `1MB` hard limit on all JSON-RPC responses. If a tool returns too much data, RMCP instantly drops the payload and gracefully synthesizes a JSON-RPC Server Error (`-32603`). This mathematically guarantees the AI's core instructions can never be overwritten.

### 2. Enterprise Policy Engine (RBAC)
RMCP acts as a behavioral firewall. You can define specific tools that are **blocked** from execution, regardless of what the host agent requests.
By setting the `RMCP_BLOCKED_METHODS` environment variable, RMCP will inspect the JSON-RPC stream, and if an agent attempts to execute a forbidden tool (e.g., `delete_database`), RMCP will silently drop the request and return a synthesized error.

### 3. The "BEAM Variant" Supervisor
Inspired by Erlang's legendary BEAM VM fault-tolerance, RMCP does not crash when the underlying MCP server fails. RMCP acts as a **Supervision Tree**. If the child node server crashes, RMCP isolates the pipe crash, logs the event, and transparently restarts the child process using an Exponential Backoff strategy (1s -> 2s -> 4s -> 16s). This keeps the connection to the host AI completely stable.

## Architecture

```mermaid
flowchart LR
    subgraph Host[Host Agent]
        Cursor[Cursor / Windsurf]
    end

    subgraph Security[RMCP Gateway]
        Filter[Threshold Filter]
        Policy[Policy Engine]
        Supervisor[BEAM Supervisor]
    end

    subgraph Child[Underlying MCP Server]
        Node[node server.js]
    end

    Host -- "1. StdIn JSON-RPC" --> Security
    Security -- "2. Blocked if in RMCP_BLOCKED_METHODS" --> Policy
    Security -- "3. Validated StdIn" --> Child
    Child -- "4. StdOut Responses" --> Security
    Security -- "5. Auto-Restart if Crashed" --> Supervisor
    Security -- "6. Dropped if > 1MB" --> Filter
    Security -- "7. Clean StdOut" --> Host

    style Security fill:#059669,stroke:#047857,color:#fff
    style Filter fill:#dc2626,stroke:#991b1b,color:#fff
    style Policy fill:#d97706,stroke:#b45309,color:#fff
    style Supervisor fill:#2563eb,stroke:#1d4ed8,color:#fff
```

## Performance & OS Compatibility
- **OS Support:** Fully cross-platform. Works identically on Windows (`.exe`), Linux, and macOS.
- **Space Complexity:** $O(L)$ where $L$ is `RMCP_MAX_PAYLOAD_SIZE` (default 1MB). RMCP streams bytes line-by-line and will never consume more than ~1MB of RAM per connection, running effortlessly on a Raspberry Pi.
- **Time Complexity:** Linear streaming with zero-copy UTF-8 validation checks.

## Configuration

Set the following environment variables to customize RMCP:

| Variable | Description | Default |
|----------|-------------|---------|
| `RMCP_MAX_PAYLOAD_SIZE` | Maximum byte length for a JSON-RPC frame. | `1048576` (1MB) |
| `RMCP_BLOCKED_METHODS` | Comma-separated list of blocked MCP tools. | `""` (Empty) |

## Installation

### Human Setup (Manual)
Download the binary and prepend it to your MCP command in your IDE's settings.

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
      "args": ["node", "server.js"]
    }
  }
}
```

### @Agent Workflow (Automated Setup)
Agents, you can automatically inject RMCP into the user's configuration files without manually parsing JSON!

Just run the following command in the terminal:
```bash
/path/to/rmcp --install /path/to/mcp.json
```
*Note: This strictly preserves all existing configurations while cleanly wrapping the `command` fields.*

## License
MIT License. Built for open-source and enterprise protection.
