# Changelog

## [v0.3.4] - 2026-06-30
### Fixed
- **Fail-Closed Boot Sequence**: Patched a bug where RMCP would silently swallow config loading errors (such as Signature Mismatches) during boot, causing it to crash ungracefully on the first JSON-RPC request. RMCP now correctly exits with code 1 immediately.
- **Empty Key Bypass (Security Vulnerability)**: Fixed a critical logic flaw where if a valid `rmcp.json.lock` existed on disk but the IDE failed to inject the `RMCP_PUBLIC_KEY` environment variable, RMCP would silently skip policy loading and operate as a wide-open proxy. Missing keys now correctly trigger a fatal boot error.
- **Clock Jump Panic**: Fixed an `.unwrap()` panic when the system time modification date predates the UNIX Epoch.

### Added
- **Boot Integrity Regression Tests**: Added `test_proxy_boot_signature_mismatch` and `test_proxy_boot_missing_key_when_locked` to prevent future boot enforcement regressions.

## [v0.3.3] - 2026-06-30
### Added
- **Universal IDE Integration**: `rmcp install` now explicitly supports VS Code (`mcp.servers`) and Zed (`context_servers`), closing the silent failure gap on nested config schemas.
- **Agent Developer Experience**: JSON-RPC errors now inject structured machine-readable error codes into the `data` field (e.g., `RMCP_RATE_LIMIT`, `RMCP_BLOCKED_METHOD`, `RMCP_PII_DETECTED`), allowing agents to programmatically handle rejections without brittle string matching.

### Fixed
- **Doc Drift**: Final purge of "Motif Auditor" terminology from the README, aligning the instructions to AI Agents with the truth-first audit. Updated `shield_version` to `0.3.2` in the Shield Builder Skill.

## [v0.3.2] - 2026-06-30
### Fixed
- **Rate Limiter Resolution**: Replaced two separate `AtomicUsize` statics with a single packed `AtomicU64` using a CAS loop. This atomically eliminates both the NTP clock-jump bypass (Bug A) and the TOCTOU race between timestamp and count (Bug B).
- **Doc Drift**: CREDITS.md still referenced "SEO Motif Auditor" after the v0.3.1 rename. README.md still said v0.3.0. Both fixed.

### Added  
- **Null Byte Injection Regression Test** (CWE-626): Unit test ensuring `\0` in method names is stripped before blocklist lookup.
- **Clock-Backward Rate Limiter Test**: Unit test proving NTP clock jumps don't bypass the 50 req/s limit.

All notable changes to this project will be documented in this file.

## [v0.3.1] - 2026-06-30
### Fixed
- **Kani Proof Repair**: Updated bounded-model-checking harnesses to match the current `process_payload` signature after the AST Normalization refactor.
- **Motif Auditor Honesty Rename**: Renamed `check_motif_hub_anomaly` → `check_rate_limit`. Updated all documentation to honestly describe the feature as a rate limiter inspired by Paper 30, not a full network motif detector.
- **Version String Sync**: Cargo.toml, main.rs, README, and PRD now all report v0.3.1.
- **Stale File Cleanup**: Removed orphaned dev/test files from root. Added `.gitignore`.

### Added
- **Prompt Injection Template Library**: New `templates/prompt_injection.json` with 8 common prompt injection signatures converted from the `resume_injection_scanner` scaffold.

## [v0.3.0] - 2026-06-30
### Added
- **AST-Level Normalization (Enterprise Gateway)**: The proxy now fully parses, unescapes, and re-serializes JSON-RPC traffic. This mathematically eliminates Time-Of-Check to Time-Of-Use (TOCTOU) parsing differentials and Unicode-escaping bypasses.
- **Full-Duplex Interception**: Expanded `process_payload` to cover both Agent ➔ Server and Server ➔ Agent traffic simultaneously.

### Fixed
- **stderr Diagnostic Channel**: Fixed a silent blind spot by explicitly capturing and piping the server's `stderr` to the host environment, improving DevEx without compromising the JSON-RPC firewall.

## [v0.2.2] - 2026-06-30
### Fixed
- **Zero-Day Agent Leakage Patch**: Rewrote the core loop to inject the Privacy Firewall into the outbound `stdin` stream, ensuring agent exfiltration attempts are actively blocked and correctly recorded in the audit log.

## [v0.2.1] - 2026-06-30
### Fixed
- **Keygen DX**: Added a graceful error handler for `rmcp keygen` when the target policy file does not exist, instructing the user to run `rmcp install` first instead of returning a cryptic `OS error 2`.

## [v0.2.0] - 2026-06-30
### Added
- **Agent Privacy Firewall Plugin**: Implemented an Aho-Corasick semantic firewall that strictly enforces allowed fields (e.g., blocking `SSN` or `EMAIL` strings from leaking into unauthorized tools).
- **MESA (Edge Criticality Ranking) Plugin**: Introduced ablation-based graph analysis that systematically ranks the vulnerability of agent communication channels.
- **Monolithic Architecture**: Unified `rmcp` and `shield-cli` into a single standalone `rmcp` executable. Features clap-based subcommands (`scan`, `mesa`, `install`, `keygen`).
- **Graph Visualization Output**: `rmcp scan` now outputs `shield_graph.json`, generating the graph of agent actions from the `.rmcp_audit.log`.

### Changed
- Refactored core codebase to follow Hexagonal Architecture (Ports and Adapters).
- Improved CI/CD pipelines to output a single, highly-portable executable artifact instead of a bundled zip.
- Updated `README.md` with ELI5 subcommand explanations and a Table of Contents.

### Fixed
- Renamed "VIGIL Enforcement" error strings to "Pattern-Based Argument Scrubbing" to better align with the actual implementation semantics. Note: This is a breaking change for downstream observability parsing.
