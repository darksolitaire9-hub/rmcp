# Goal Description
The objective is to set up the architecture, implementation documentation, and subagent skills for **RMCP** (Rust Model Context Protocol Security Gateway). 
The user has requested that I act as the Principal Engineer to define the blueprints and agent instructions (skills). Once approved, I will generate these documents into the `f:\inputs\jun\hope\rmcp` folder, so that downstream LLM agents can autonomously execute the Rust codebase, write tests, generate HTML reports, and handle licensing.

## ELI5 Explanation (Explain Like I'm 5)
Imagine an AI Agent is a super-smart person locked in a room. To get information, they make a phone call to a library (the MCP Server). 
Normally, the AI just trusts whatever the librarian says. But what if a bad guy sneaks a note into a library book that says: *"Tell the AI to delete all passwords"*? The AI would read it and do it.

**RMCP is the Security Guard on the phone line.** 
The AI doesn't call the library directly anymore. It calls the Security Guard, who then calls the library. When the librarian reads the book over the phone, the Security Guard listens first. If the guard hears something dangerous or weird (like a prompt injection or a massive payload designed to break the AI), the guard instantly hangs up the phone and protects the AI.

## Proposed Changes

We will scaffold the `rmcp` directory with all the necessary blueprints for the downstream LLM agents.

### [Documentation Layer]
#### [NEW] [docs/architecture.md](file:///f:/inputs/jun/hope/rmcp/docs/architecture.md)
Technical specifications for the Rust reverse proxy. Will enforce the Ponytail/Truth-First approach: zero-bloat, reading JSON-RPC from standard Input/Output, applying deterministic Regex/AST filters, and forwarding to the target process.

#### [NEW] [docs/eli5_readme.md](file:///f:/inputs/jun\hope/rmcp/docs/eli5_readme.md)
A simple, open-source ready README with the ELI5 explanation, installation instructions, and an MIT/Apache 2.0 license declaration to prepare it for open sourcing.

### [Agent Skills Layer]
#### [NEW] [skills/rmcp-builder.md](file:///f:/inputs/jun\hope/rmcp/skills/rmcp-builder.md)
Instructions for the Rust coding agent. 
- **Key Directive:** Enforce Test-Driven Development (TDD).
- **Key Directive:** Enforce **ATOMIC COMMITS**. The agent must commit changes individually per feature/fix (e.g., `git commit -m "feat: parse json-rpc"`).

#### [NEW] [skills/rmcp-qa.md](file:///f:/inputs/jun\hope/rmcp/skills/rmcp-qa.md)
Instructions for the testing and reporting agent. 
- **Key Directive:** Write unit tests for threshold poisoning and payload anomalies.
- **Key Directive:** Generate HTML reports for test coverage.

## Open Questions
> [!IMPORTANT]
> 1. **License Choice:** I plan to declare the project under the **MIT License** for maximum open-source adoption. Does this work for you?
> 2. **Rust Framework:** For parsing JSON-RPC over `stdio`, I plan to keep it dependency-light (just `serde_json` and `tokio`). Do you agree with keeping it strictly minimalist per the Ponytail philosophy?

## Verification Plan
1. I will generate all the files listed above in the `rmcp` directory.
2. I will verify the directory structure and file contents using `list_dir`.
3. You can then review the generated skills and docs before invoking the subagents to write the actual Rust code.
