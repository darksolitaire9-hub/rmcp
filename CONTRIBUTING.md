# Contributing to RMCP

RMCP is a strict, zero-latency security proxy for the Model Context Protocol. We accept contributions from both Humans and Autonomous Agents.

However, to maintain the integrity and speed of the proxy, **ALL** Pull Requests (PRs) must explicitly answer the following 4 Golden Questions in the PR description. If a PR does not include these answers, it will be automatically closed by the maintainer.

## The 4 Golden PR Questions

When submitting a PR, copy and paste this checklist into your PR description and fill it out:

1. **Threat Model Origin**
   *What specific academic paper, CVE, or zero-day exploit does this address? Provide the arXiv ID or direct link.*
   - Answer: 

2. **Dependency Check**
   *Does this PR add new external crates or dependencies? RMCP is designed to be dependency-light. (Default should be NO).*
   - Answer: 

3. **Latency Impact**
   *What is the estimated byte-size overhead or regex evaluation time? RMCP must remain near-zero latency.*
   - Answer: 

4. **Template Verification**
   *Is the rule provided as a JSON template in the `templates/` directory rather than hardcoded in Rust? (Hardcoded rules require compilation and will be rejected).*
   - Answer: 

## Rule Templates

Do NOT bake security rules directly into the Rust binary. 
RMCP loads security policies dynamically from the `templates/` directory at runtime. This allows AI agents and human operators to patch vulnerabilities instantly without recompiling the proxy.

If you are adding a new defense mechanism (e.g., against ShareLock threshold poisoning), create a new `.json` file in the `templates/` directory and ensure it matches the RMCP schema.

Thank you for helping secure the future of Agentic Infrastructure!
