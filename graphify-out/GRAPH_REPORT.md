# Graph Report - rmcp  (2026-06-30)

## Corpus Check
- 28 files · ~13,983 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 219 nodes · 287 edges · 23 communities
- Extraction: 100% EXTRACTED · 0% INFERRED · 0% AMBIGUOUS
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `5318362e`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- [[_COMMUNITY_Community 0|Community 0]]
- [[_COMMUNITY_Community 1|Community 1]]
- [[_COMMUNITY_Community 2|Community 2]]
- [[_COMMUNITY_Community 3|Community 3]]
- [[_COMMUNITY_Community 4|Community 4]]
- [[_COMMUNITY_Community 5|Community 5]]
- [[_COMMUNITY_Community 6|Community 6]]
- [[_COMMUNITY_Community 7|Community 7]]
- [[_COMMUNITY_Community 8|Community 8]]
- [[_COMMUNITY_Community 9|Community 9]]
- [[_COMMUNITY_Community 10|Community 10]]
- [[_COMMUNITY_Community 11|Community 11]]
- [[_COMMUNITY_Community 12|Community 12]]
- [[_COMMUNITY_Community 13|Community 13]]
- [[_COMMUNITY_Community 14|Community 14]]
- [[_COMMUNITY_Community 15|Community 15]]
- [[_COMMUNITY_Community 16|Community 16]]
- [[_COMMUNITY_Community 17|Community 17]]
- [[_COMMUNITY_Community 18|Community 18]]
- [[_COMMUNITY_Community 19|Community 19]]
- [[_COMMUNITY_Community 21|Community 21]]

## God Nodes (most connected - your core abstractions)
1. `process_payload()` - 16 edges
2. `Firewall` - 10 edges
3. `ShieldGraph` - 10 edges
4. `PolicyConfig` - 8 edges
5. `check_rate_limit()` - 8 edges
6. `RMCP 🛡️ (v0.3.2 Enterprise Gateway)` - 8 edges
7. `install_rmcp()` - 7 edges
8. `parse_audit_logs()` - 7 edges
9. `Changelog` - 7 edges
10. `Core Features & Defense Mechanisms` - 7 edges

## Surprising Connections (you probably didn't know these)
- `load_combined_policy()` --references--> `Firewall`  [EXTRACTED]
  src/main.rs → crates/shield-firewall/src/lib.rs
- `process_payload()` --references--> `Firewall`  [EXTRACTED]
  src/proxy.rs → crates/shield-firewall/src/lib.rs
- `PolicyConfig` --references--> `MesaEdge`  [EXTRACTED]
  src/policy.rs → crates/shield-mesa/src/lib.rs
- `build_graph()` --references--> `AuditEntry`  [EXTRACTED]
  src/shield.rs → crates/shield-mesa/src/lib.rs
- `parse_audit_logs()` --references--> `AuditEntry`  [EXTRACTED]
  src/shield.rs → crates/shield-mesa/src/lib.rs

## Import Cycles
- None detected.

## Communities (23 total, 0 thin omitted)

### Community 0 - "Community 0"
Cohesion: 0.14
Nodes (26): check_rate_limit(), extract_jsonrpc_id(), log_audit(), process_payload(), rate_pack(), rate_unpack(), Option, Result (+18 more)

### Community 1 - "Community 1"
Cohesion: 0.09
Nodes (21): 1. Full-Duplex AST Normalization (Fixing TOCTOU & Escapes), 1. One-Command Setup (Recommended), 2. Configure Your Policy (Optional), 2. Pattern-Based Argument Scrubbing (VIGIL-Inspired), 3. Analyzing Traffic with rmcp-shield, 3. The Context Window Firewall (1MB Limit & ShareLock Defense), 4. Rate Limiter (inspired by Paper 30), 5. Rel(AI)Build Hash-Chaining (+13 more)

### Community 2 - "Community 2"
Cohesion: 0.40
Nodes (5): load_patterns(), Result, String, Vec, test_malformed_json_fails_closed()

### Community 3 - "Community 3"
Cohesion: 0.17
Nodes (11): [Agent Skills Layer], [Documentation Layer], ELI5 Explanation (Explain Like I'm 5), Goal Description, [NEW] [docs/architecture.md](file:///f:/inputs/jun/hope/rmcp/docs/architecture.md), [NEW] [docs/eli5_readme.md](file:///f:/inputs/jun\hope/rmcp/docs/eli5_readme.md), [NEW] [skills/rmcp-builder.md](file:///f:/inputs/jun\hope/rmcp/skills/rmcp-builder.md), [NEW] [skills/rmcp-qa.md](file:///f:/inputs/jun\hope/rmcp/skills/rmcp-qa.md) (+3 more)

### Community 4 - "Community 4"
Cohesion: 0.33
Nodes (10): Box, Error, generate_keys(), load_policy(), PolicyConfig, HashMap, Result, String (+2 more)

### Community 5 - "Community 5"
Cohesion: 0.39
Nodes (7): cleanup_config(), get_mock_server(), String, Vec, setup_signed_config(), test_proxy_e2e_forwarding(), test_proxy_e2e_pattern_based_scrubbing()

### Community 6 - "Community 6"
Cohesion: 0.33
Nodes (5): Exploit: Sovereign Agent Firewall (The Picks & Shovels), Technical Execution (Next Steps), The Commercial Translation (Ponytail Mode), The Primitive, Why this hits €30k/mo for a Solo Dev

### Community 7 - "Community 7"
Cohesion: 0.33
Nodes (5): Architecture: RMCP (Rust Model Context Protocol Security Gateway), Core Philosophy, Security Modules, Technology Stack, The Data Flow

### Community 8 - "Community 8"
Cohesion: 0.33
Nodes (5): 1. Bulk Ingestion, 2. The Graphify "God Node" Synthesis, Data-Driven Council: Graphify Synthesis (Run 5), The Extraction, The Truth-First Exploit: The MCP Security Gateway

### Community 9 - "Community 9"
Cohesion: 0.33
Nodes (5): Exploit: The MCP Security Gateway (Agentic Reverse Proxy), Technical Execution (Next Steps), The Commercial Translation (Ponytail Mode), The Primitive (The "God Node"), Why this hits €30k/mo for a Solo Dev

### Community 10 - "Community 10"
Cohesion: 0.40
Nodes (4): Academic Research Foundations, Credits & Attribution, Inspiration & Concepts, Testers, Libraries, and Contributors

### Community 11 - "Community 11"
Cohesion: 0.33
Nodes (5): Explain It Like I'm 5 (ELI5), License, RMCP: The Security Guard for AI Agents 🛡️, The New Guards (v0.2.0), Why use RMCP?

### Community 12 - "Community 12"
Cohesion: 0.33
Nodes (5): Conclusion, Current Scope & Future Work (Limitations), Implemented Defenses, Recently Closed Theoretical Gaps, RMCP Security Architecture

### Community 13 - "Community 13"
Cohesion: 0.40
Nodes (4): CODING PHILOSOPHY, CRITICAL DIRECTIVE: ATOMIC COMMITS, CRITICAL DIRECTIVE: TDD, Instruction for RMCP Builder Agent

### Community 14 - "Community 14"
Cohesion: 0.31
Nodes (9): Map, install_rmcp(), Result, String, Value, test_install_logic(), test_install_logic_vscode(), test_install_logic_zed() (+1 more)

### Community 15 - "Community 15"
Cohesion: 0.50
Nodes (3): Contributing to RMCP, Rule Templates, The 4 Golden PR Questions

### Community 16 - "Community 16"
Cohesion: 0.50
Nodes (3): CRITICAL DIRECTIVES, Instruction for RMCP QA Agent, REPORTING

### Community 17 - "Community 17"
Cohesion: 0.39
Nodes (8): Cli, Commands, load_combined_policy(), main(), Result, String, Vec, run_proxy()

### Community 18 - "Community 18"
Cohesion: 0.23
Nodes (12): AhoCorasick, Firewall, HashMap, Option, Result, String, Value, Vec (+4 more)

### Community 19 - "Community 19"
Cohesion: 0.20
Nodes (16): AuditEntry, Edge, MesaEdge, String, Value, Vec, ShieldGraph, test_ablation_ranking() (+8 more)

### Community 21 - "Community 21"
Cohesion: 0.11
Nodes (18): Added, Added, Added, Added, Changed, Changelog, Fixed, Fixed (+10 more)

## Knowledge Gaps
- **68 isolated node(s):** `Fixed`, `Added`, `Fixed`, `Added`, `Added` (+63 more)
  These have ≤1 connection - possible missing edges or undocumented components.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Firewall` connect `Community 18` to `Community 0`, `Community 17`?**
  _High betweenness centrality (0.093) - this node is a cross-community bridge._
- **Why does `load_combined_policy()` connect `Community 17` to `Community 18`, `Community 4`?**
  _High betweenness centrality (0.086) - this node is a cross-community bridge._
- **Why does `PolicyConfig` connect `Community 4` to `Community 17`, `Community 19`?**
  _High betweenness centrality (0.076) - this node is a cross-community bridge._
- **What connects `Fixed`, `Added`, `Fixed` to the rest of the system?**
  _68 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Community 0` be split into smaller, more focused modules?**
  _Cohesion score 0.14245014245014245 - nodes in this community are weakly interconnected._
- **Should `Community 1` be split into smaller, more focused modules?**
  _Cohesion score 0.08695652173913043 - nodes in this community are weakly interconnected._
- **Should `Community 21` be split into smaller, more focused modules?**
  _Cohesion score 0.10526315789473684 - nodes in this community are weakly interconnected._