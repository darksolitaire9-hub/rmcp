use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use serde_json::Value;

#[derive(Debug)]
pub struct Firewall {
    ac: AhoCorasick,
}

impl Firewall {
    pub fn new(patterns: &[String]) -> Result<Self, String> {
        let mut builder = AhoCorasickBuilder::new();
        builder.match_kind(MatchKind::LeftmostFirst);
        let ac = match builder.build(patterns) {
            Ok(ac) => ac,
            Err(e) => return Err(format!("Failed to build Aho-Corasick automaton: {}", e)),
        };

        Ok(Self { ac })
    }

    pub fn scan_payload(&self, payload: &str, blocked_args: &[String]) -> Result<(), String> {
        // Pattern-Based Argument Scrubbing & ShareLock Bidirectional Scanning
        if !blocked_args.is_empty() {
            if let Ok(parsed) = serde_json::from_str::<Value>(payload) {
                // Client -> Server (params)
                if let Some(params) = parsed.get("params") {
                    let params_str = params.to_string();
                    for blocked_arg in blocked_args {
                        if params_str.contains(blocked_arg) {
                            return Err(format!("Pattern-Based Argument Scrubbing: Argument pattern '{}' is blocked", blocked_arg));
                        }
                    }
                }
                
                // Server -> Client (result)
                if let Some(result) = parsed.get("result") {
                    let result_str = result.to_string();
                    for blocked_arg in blocked_args {
                        if result_str.contains(blocked_arg) {
                            return Err(format!("ShareLock Mitigation: Blocked pattern '{}' detected in server response", blocked_arg));
                        }
                    }
                }
            }
        }

        // Aho-Corasick structural template matching
        if self.ac.is_match(payload) {
            return Err("Template Match (Aho-Corasick Security Rules)".to_string());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_firewall_blocks_substring() {
        let fw = Firewall::new(&[]).unwrap();
        let payload = r#"{"jsonrpc":"2.0","method":"read","params":{"path":"/etc/passwd"}}"#;
        assert!(fw.scan_payload(payload, &["/etc/passwd".to_string()]).is_err());
    }

    #[test]
    fn test_firewall_aho_corasick() {
        let fw = Firewall::new(&["malicious_pattern".to_string()]).unwrap();
        let payload = r#"{"jsonrpc":"2.0","method":"read","params":{"data":"some malicious_pattern string"}}"#;
        assert!(fw.scan_payload(payload, &[]).is_err());
    }
}
