# Architecture: RMCP (Rust Model Context Protocol Security Gateway)

## Core Philosophy
The gateway adheres to the **Ponytail / Truth-First** mindset. It is completely dependency-light, relying only on standard I/O streams and zero LLM calls. It operates purely as a deterministic filtering layer.

## The Data Flow
1. **Host Agent (Cursor/Windsurf)** spawns the `rmcp-gateway` binary instead of the actual MCP Server.
2. `rmcp-gateway` binds to `stdin/stdout`.
3. `rmcp-gateway` parses incoming JSON-RPC traffic.
4. `rmcp-gateway` executes the true MCP Server (e.g., `node server.js`) as a child process.
5. The gateway intercepts all outgoing JSON-RPC messages from the child process.
6. **Filtering:** If an anomalous payload (e.g., prompt injection patterns, excessive token sizes, or blacklisted tool calls) is detected, the gateway drops the payload and returns an error to the host agent.
7. Otherwise, the JSON-RPC message is forwarded untouched to the host agent.

## Technology Stack
- **Language:** Rust (for zero-latency, memory-safe, dependency-free enterprise deployment)
- **Dependencies:** `serde_json` (JSON-RPC parsing), `tokio` (Async I/O for child processes). No heavy frameworks.
- **License:** MIT / Apache 2.0 (Open Source)

## Security Modules
- **Size Limitation:** Prevent threshold poisoning by dropping payloads over a specific byte size.
- **Behavioral Specs (VIGIL):** Enforce strict schemas on tool descriptions to strip out embedded instruction overrides.
