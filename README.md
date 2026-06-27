# RMCP 🛡️
**Rust Model Context Protocol Security Gateway**

The Model Context Protocol (MCP) bridges the gap between AI Agents (like Cursor or Claude) and your local environment. But if a malicious server sends an injection payload or tries to poison the AI's context window with gigabytes of garbage data, the AI has no defense.

**RMCP** is a lightweight, zero-dependency proxy written in Rust that intercepts and strictly filters MCP traffic *before* it reaches the agent.

## Architecture

```mermaid
flowchart LR
    subgraph Host[Host Agent]
        Cursor[Cursor / Windsurf]
    end

    subgraph Security[RMCP Gateway]
        Filter[Threshold Filter]
        JSON[JSON Validator]
    end

    subgraph Child[Underlying MCP Server]
        Node[node server.js]
    end

    Host -- "1. StdIn" --> Security
    Security -- "2. Validated StdIn" --> Child
    Child -- "3. StdOut (Responses)" --> Security
    Security -- "4. Dropped if > 1MB" --> Filter
    Security -- "5. Clean StdOut" --> Host

    style Security fill:#059669,stroke:#047857,color:#fff
    style Filter fill:#dc2626,stroke:#991b1b,color:#fff
```

## Security Features
- **Negative Space Hardening:** Utilizes strict byte constraints on `stdin`/`stdout` pipelines, mathematically preventing OOM vulnerabilities caused by missing newlines.
- **ShareLock Defense:** Drops JSON payloads exceeding the `MAX_PAYLOAD_SIZE` (1MB), protecting the AI context window from threshold poisoning.
- **Disaster Recovery:** Seamlessly propagates child process exit codes back to the Host Agent for transparent auto-restarts.

## Human Setup (Manual)
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

## @Agent Workflow (Automated Setup)
Agents, you can automatically inject RMCP into the user's configuration files without manually parsing JSON!

Just run the following command in the terminal to automatically inject the wrapper:
```bash
/path/to/rmcp --install /path/to/mcp.json
```
*Note: This strictly preserves all existing configurations while cleanly wrapping the `command` fields.*

## License
MIT License. Free for open-source and enterprise protection.
