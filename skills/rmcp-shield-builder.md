---
name: rmcp-shield-builder
description: Generates and validates `shield_policy.json` for the RMCP gateway, ensuring proper configuration of graph-aware security and privacy firewall schemas.
---

# RMCP Shield Builder Skill

You are an agent responsible for configuring the **RMCP Shield** security gateway for a given project. RMCP Shield relies on a configuration file named `shield_policy.json`.

## Responsibilities

1. **Schema Generation**: You must generate the `shield_policy.json` file to define `blocked_methods`, `blocked_args`, `tool_schemas`, and `mesa_edges`.
2. **Privacy Firewall**: For `tool_schemas`, you must strictly define `allowed_fields` for each tool. If a tool should not accept PII, ensure you populate `pii_patterns` with required string literals (e.g., "SSN", "EMAIL") that match the active Aho-Corasick templates in RMCP.
3. **MESA Rankings**: Populate `mesa_edges` with the structural criticality of edges. By default, you can invoke `rmcp scan` or `rmcp mesa` to automatically calculate and inject `mesa_edges`.

## Example `shield_policy.json`

```json
{
  "shield_version": "0.2.0",
  "blocked_methods": ["delete_database"],
  "blocked_args": ["/etc/passwd", "API_KEY"],
  "tool_schemas": {
    "WeatherAPI": {
      "allowed_fields": ["location", "date"],
      "pii_patterns": ["SSN", "EMAIL"]
    },
    "FileEditor": {
      "allowed_fields": ["path", "content"],
      "pii_patterns": []
    }
  },
  "mesa_edges": [
    {
      "source": "AgentA",
      "target": "WeatherAPI",
      "criticality": 3
    }
  ]
}
```

## Troubleshooting
- If RMCP returns a `FIREWALL BLOCK` error, it means a field was sent to a tool that is not present in its `allowed_fields`. You must either stop sending the field or update `shield_policy.json`.
- If RMCP returns a `PII DETECTED` error, it means the firewall identified sensitive data based on the `pii_patterns` for that tool. Scrub the data before sending it.
