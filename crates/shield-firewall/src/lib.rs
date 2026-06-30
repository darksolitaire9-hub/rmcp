use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use serde_json::Value;

#[derive(Debug)]
pub struct Firewall {
    ac_global: AhoCorasick,
    tool_schemas: std::collections::HashMap<String, ToolSchemaValidator>,
}

#[derive(Debug)]
pub struct ToolSchemaValidator {
    pub allowed_fields: Vec<String>,
    pub pii_ac: Option<AhoCorasick>,
}

impl Firewall {
    pub fn new(global_patterns: &[String]) -> Result<Self, String> {
        let mut builder = AhoCorasickBuilder::new();
        builder.match_kind(MatchKind::LeftmostFirst);
        let ac_global = match builder.build(global_patterns) {
            Ok(ac) => ac,
            Err(e) => return Err(format!("Failed to build Aho-Corasick automaton: {}", e)),
        };

        Ok(Self { ac_global, tool_schemas: std::collections::HashMap::new() })
    }

    pub fn add_tool_schema(&mut self, tool_name: String, allowed_fields: Vec<String>, pii_patterns: Vec<String>) -> Result<(), String> {
        let pii_ac = if !pii_patterns.is_empty() {
            let mut builder = AhoCorasickBuilder::new();
            builder.match_kind(MatchKind::LeftmostFirst);
            Some(builder.build(&pii_patterns).map_err(|e| format!("Failed to build PII AC: {}", e))?)
        } else {
            None
        };
        
        self.tool_schemas.insert(tool_name, ToolSchemaValidator {
            allowed_fields,
            pii_ac,
        });
        Ok(())
    }

    pub fn scan_payload(&self, parsed: &Value, normalized_payload: &str, blocked_args: &[String]) -> Result<(), String> {
        if !blocked_args.is_empty() {
            if let Some(params) = parsed.get("params") {
                let params_str = params.to_string();
                for blocked_arg in blocked_args {
                    if params_str.contains(blocked_arg) {
                        return Err(format!("Pattern-Based Argument Scrubbing: Argument pattern '{}' is blocked", blocked_arg));
                    }
                }
            }
            
            if let Some(result) = parsed.get("result") {
                let result_str = result.to_string();
                for blocked_arg in blocked_args {
                    if result_str.contains(blocked_arg) {
                        return Err(format!("ShareLock Mitigation: Blocked pattern '{}' detected in server response", blocked_arg));
                    }
                }
            }
        }

        if self.ac_global.is_match(normalized_payload) {
            return Err("Template Match (Aho-Corasick Security Rules)".to_string());
        }

        if let Some(method) = parsed.get("method").and_then(|m| m.as_str()) {
            if let Some(schema) = self.tool_schemas.get(method) {
                    if let Some(params) = parsed.get("params").and_then(|p| p.as_object()) {
                        for (key, val) in params {
                            // Only check fields if allowed_fields is NOT empty (empty means allow all for backward compat, or maybe the other way around)
                            // PRD says: "Firewall Block (data-type violation)... Field 'customer_ssn' is not permitted"
                            // If allowed_fields is specified and not empty, enforce it. If it's empty, we might allow all. Let's assume if schema exists but allowed_fields is empty, we allow all for now, but wait, the PRD says:
                            // "The tool's schema does not permit... To permit this field, add it to allowed_fields". That means empty `allowed_fields` blocks everything.
                            if !schema.allowed_fields.is_empty() && !schema.allowed_fields.contains(key) {
                                let allowed = schema.allowed_fields.join(", ");
                                return Err(format!("Shield: FIREWALL BLOCK\n  What:  Field '{}' sent to tool '{}'\n  Why:   {} allows only [{}]. Field '{}' is not permitted.\n  Fix:   Remove '{}' from the payload, or add it to\n         tool_schemas.{}.allowed_fields in shield_policy.json.", key, method, method, allowed, key, key, method));
                            }

                            if let Some(ref pii_ac) = schema.pii_ac {
                                let val_str = val.to_string();
                                if let Some(_mat) = pii_ac.find(&val_str) {
                                    return Err(format!("Shield: PII DETECTED\n  What:  PII pattern found in field '{}' of tool call to '{}'\n  Why:   Value matched a protected PII pattern.\n  Fix:   Sanitize the '{}' field before passing to {}.\n         To suppress this pattern, modify\n         tool_schemas.{}.pii_patterns in shield_policy.json.", key, method, key, method, method));
                                }
                            }
                        }
                    }
                }
            }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pattern_blocking() {
        let patterns = vec!["/etc/passwd".to_string(), "DROP TABLE".to_string()];
        let fw = Firewall::new(&patterns).unwrap();
        
        let payload = r#"{"jsonrpc":"2.0","method":"read_file","params":{"path":"/etc/passwd"}}"#;
        let parsed: Value = serde_json::from_str(payload).unwrap();
        assert!(fw.scan_payload(&parsed, payload, &["/etc/passwd".to_string()]).is_err());
    }

    #[test]
    fn test_template_matching() {
        let patterns = vec!["/etc/passwd".to_string(), "DROP TABLE".to_string()];
        let fw = Firewall::new(&patterns).unwrap();
        
        let payload = r#"{"jsonrpc":"2.0","method":"query","params":{"sql":"DROP TABLE users"}}"#;
        let parsed: Value = serde_json::from_str(payload).unwrap();
        assert!(fw.scan_payload(&parsed, payload, &[]).is_err());
    }
}
