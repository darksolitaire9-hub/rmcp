# Credits & Attribution

RMCP (Rust Model Context Protocol Security Gateway) owes its existence to the open-source community, brilliant testers, and the original creators of the Model Context Protocol.

## Inspiration & Concepts
- **ShareLock Threshold Defense**: Inspired by the community's research into context window overflow attacks and threshold poisoning vectors in AI agents.
- **Model Context Protocol (MCP)**: Developed by Anthropic and the open-source community to standardize context retrieval. This project builds upon their open specification to secure agentic workflows.

## Testers, Libraries, and Contributors
- **Aho-Corasick Algorithm & Engine**: Special thanks to Andrew Gallant (BurntSushi) and the Rust community for the `aho-corasick` crate (MIT/Unlicense), which provides RMCP with immunity against ReDoS attacks and O(N) multi-pattern string matching.
- Special thanks to the human users and AI agent peers who continuously tested, audited, and suggested improvements for edge cases such as memory exhaustion vulnerabilities in standard I/O proxying.
- Thanks to the GitHub open-source community for providing transparent CI/CD systems and security frameworks that made this zero-bloat gateway possible.

## Academic Research Foundations
We explicitly credit the following theoretical frameworks and research papers which form the backbone of RMCP's security architecture:
- **ShareLock (Paper 10):** "A Stealthy Multi-Tool Threshold Poisoning Attack Against MCP". RMCP's 1MB threshold limit directly mitigates this vector.
- **Rel(AI)Build Control Plane (Paper 14):** "A Deterministic Control Plane for LLM Coding Agents". Inspires our roadmap for deterministic lockfiles and audit logs.
- **VIGIL (Paper 27):** "Runtime Enforcement of Behavioral Specifications". **Inspired by** this paper, we built a pattern-based argument scrubber. Note: We do not currently implement full SMT-based trace verification as described in the paper.
- **The Unfireable Safety Kernel (Paper 43):** "Execution-Time AI Alignment". Provides the theoretical basis for our Kani bounded-model-checking verifications.
- **Rate Limiter (Paper 30):** "Systematic identification of statistically significant network measures". Inspires our call-frequency rate limiter.
- **MESA (Paper 89):** "Minimalist Embedded Subgraph Ablation". Implements the ablation probe from MESA (arXiv:2606.30602v1) for our `shield-mesa` incremental criticality ranking algorithm. Note: MESA's full 8-signal composite ranking is planned for future releases.
- **Agents That Know Too Much (Paper 12):** "The Threat of Privacy-Invasive AI Agents". Inspires our `shield-firewall` privacy validation and PII detection engine.
