# Changelog

All notable changes to this project will be documented in this file.

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
