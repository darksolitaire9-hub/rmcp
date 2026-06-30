# Graph Report - rmcp  (2026-06-30)

## Corpus Check
- 26 files · ~10,101 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 135 nodes · 152 edges · 18 communities (17 shown, 1 thin omitted)
- Extraction: 100% EXTRACTED · 0% INFERRED · 0% AMBIGUOUS
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `e16bc397`
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

## God Nodes (most connected - your core abstractions)
1. `process_payload()` - 13 edges
2. `TemplateEngine` - 7 edges
3. `RMCP 🛡️` - 6 edges
4. `generate_keys()` - 5 edges
5. `check_motif_hub_anomaly()` - 5 edges
6. `extract_jsonrpc_id()` - 5 edges
7. `Core Features & Defense Mechanisms` - 5 edges
8. `Exploit: Sovereign Agent Firewall (The Picks & Shovels)` - 5 edges
9. `Architecture: RMCP (Rust Model Context Protocol Security Gateway)` - 5 edges
10. `Goal Description` - 5 edges

## Surprising Connections (you probably didn't know these)
- `process_payload()` --references--> `TemplateEngine`  [EXTRACTED]
  src/proxy.rs → src/template.rs

## Import Cycles
- None detected.

## Communities (18 total, 1 thin omitted)

### Community 0 - "Community 0"
Cohesion: 0.19
Nodes (20): check_motif_hub_anomaly(), extract_jsonrpc_id(), log_audit(), process_payload(), Result, String, synthesize_error(), test_audit_hash_chaining() (+12 more)

### Community 1 - "Community 1"
Cohesion: 0.15
Nodes (12): 1. One-Command Setup (Recommended), 1. VIGIL Enforcement & Cryptographic Policies, 2. Configure Your Policy (Optional), 2. The Context Window Firewall (1MB Limit), 3. Motif Auditor Rate-Limiting, 4. Rel(AI)Build Hash-Chaining, Core Features & Defense Mechanisms, 🛠️ Dynamic Templates & Fail-Closed Architecture (+4 more)

### Community 2 - "Community 2"
Cohesion: 0.24
Nodes (9): AhoCorasick, Self, Result, String, Vec, TemplateEngine, test_engine_compilation(), test_malformed_json_fails_closed() (+1 more)

### Community 3 - "Community 3"
Cohesion: 0.17
Nodes (11): [Agent Skills Layer], [Documentation Layer], ELI5 Explanation (Explain Like I'm 5), Goal Description, [NEW] [docs/architecture.md](file:///f:/inputs/jun/hope/rmcp/docs/architecture.md), [NEW] [docs/eli5_readme.md](file:///f:/inputs/jun\hope/rmcp/docs/eli5_readme.md), [NEW] [skills/rmcp-builder.md](file:///f:/inputs/jun\hope/rmcp/skills/rmcp-builder.md), [NEW] [skills/rmcp-qa.md](file:///f:/inputs/jun\hope/rmcp/skills/rmcp-qa.md) (+3 more)

### Community 4 - "Community 4"
Cohesion: 0.33
Nodes (8): Box, Error, generate_keys(), load_policy(), PolicyConfig, Result, String, Vec

### Community 5 - "Community 5"
Cohesion: 0.39
Nodes (7): cleanup_config(), get_mock_server(), String, Vec, setup_signed_config(), test_proxy_e2e_forwarding(), test_proxy_e2e_vigil_enforcement()

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
Cohesion: 0.40
Nodes (4): Explain It Like I'm 5 (ELI5), License, RMCP: The Security Guard for AI Agents 🛡️, Why use RMCP?

### Community 12 - "Community 12"
Cohesion: 0.40
Nodes (4): Conclusion, Implemented Defenses, Recently Closed Theoretical Gaps, RMCP Security Architecture

### Community 13 - "Community 13"
Cohesion: 0.40
Nodes (4): CODING PHILOSOPHY, CRITICAL DIRECTIVE: ATOMIC COMMITS, CRITICAL DIRECTIVE: TDD, Instruction for RMCP Builder Agent

### Community 14 - "Community 14"
Cohesion: 0.50
Nodes (4): install_rmcp(), Result, String, test_install_logic()

### Community 15 - "Community 15"
Cohesion: 0.50
Nodes (3): Contributing to RMCP, Rule Templates, The 4 Golden PR Questions

### Community 16 - "Community 16"
Cohesion: 0.50
Nodes (3): CRITICAL DIRECTIVES, Instruction for RMCP QA Agent, REPORTING

## Knowledge Gaps
- **47 isolated node(s):** `The 4 Golden PR Questions`, `Rule Templates`, `Inspiration & Concepts`, `Testers, Libraries, and Contributors`, `Academic Research Foundations` (+42 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **1 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `process_payload()` connect `Community 0` to `Community 2`?**
  _High betweenness centrality (0.025) - this node is a cross-community bridge._
- **Why does `TemplateEngine` connect `Community 2` to `Community 0`?**
  _High betweenness centrality (0.023) - this node is a cross-community bridge._
- **What connects `The 4 Golden PR Questions`, `Rule Templates`, `Inspiration & Concepts` to the rest of the system?**
  _47 weakly-connected nodes found - possible documentation gaps or missing edges._