use std::fs;
use serde_json::Value;
use walkdir::WalkDir;
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};

#[derive(Debug)]
pub struct TemplateEngine {
    ac: AhoCorasick,
    patterns: Vec<String>,
}

impl TemplateEngine {
    pub fn build(template_dir: &str) -> Result<Self, String> {
        let mut patterns = Vec::new();

        if !std::path::Path::new(template_dir).exists() {
            if let Err(e) = std::fs::create_dir_all(template_dir) {
                return Err(format!(
                    "RMCP SECURITY FAULT: Could not auto-create the '{}' directory.\n\
                     Reason: {}\n\
                     Action Required: Please ensure RMCP has write permissions in the current directory so it can initialize its security templates.",
                    template_dir, e
                ));
            }
            
            // Provide great out-of-the-box defaults by seeding the templates directory
            let _ = std::fs::write(
                std::path::Path::new(template_dir).join("resumearmor.json"),
                include_bytes!("../templates/resumearmor.json")
            );
            let _ = std::fs::write(
                std::path::Path::new(template_dir).join("sharelock_defense.json"),
                include_bytes!("../templates/sharelock_defense.json")
            );
        }

        for entry in WalkDir::new(template_dir).into_iter().filter_map(|e| e.ok()) {
                if entry.path().extension().and_then(|s| s.to_str()) == Some("json") {
                    let content = match fs::read_to_string(entry.path()) {
                        Ok(c) => c,
                        Err(e) => return Err(format!(
                            "\n[!] RMCP BOOT FAILURE: Cannot read template file.\n    File: {:?}\n    Error: {}\n    Action Required: Ensure the file has read permissions.", 
                            entry.path(), e
                        )),
                    };

                    let parsed: Value = match serde_json::from_str(&content) {
                        Ok(v) => v,
                        Err(e) => return Err(format!(
                            "\n[!] RMCP BOOT FAILURE: Malformed JSON detected in security template.\n    File: {:?}\n    Error: {}\n    Action Required: Fix the JSON syntax error in the file above. RMCP will refuse to boot until security rules are perfectly formed.", 
                            entry.path(), e
                        )),
                    };

                    if let Some(rules) = parsed.get("rules").and_then(|v| v.as_array()) {
                        for rule in rules {
                            if let Some(pattern) = rule.get("pattern").and_then(|v| v.as_str()) {
                                patterns.push(pattern.to_string());
                            }
                        }
                    }
                }
            }

        // Always add a dummy pattern if empty, because AhoCorasick requires at least something, 
        // wait, AhoCorasick can be built with empty patterns, but is_match will just return false.
        
        let ac = match AhoCorasickBuilder::new()
            .match_kind(MatchKind::Standard)
            .build(&patterns) 
        {
            Ok(ac) => ac,
            Err(e) => return Err(format!(
                "\n[!] RMCP BOOT FAILURE: Aho-Corasick Automaton Compilation Failed.\n    Error: {}\n    Action Required: This is an internal engine failure. Please report this bug.", e
            )),
        };

        Ok(Self { ac, patterns })
    }

    pub fn is_match(&self, payload: &[u8]) -> bool {
        if self.patterns.is_empty() {
            return false;
        }
        self.ac.is_match(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_engine_compilation() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.json");
        let mut file = File::create(file_path).unwrap();
        writeln!(file, r#"{{ "rules": [ {{ "pattern": "malicious payload" }} ] }}"#).unwrap();

        let engine = TemplateEngine::build(dir.path().to_str().unwrap()).unwrap();
        assert!(engine.is_match(b"some malicious payload here"));
        assert!(!engine.is_match(b"benign text"));
    }

    #[test]
    fn test_malformed_json_fails_closed() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("bad.json");
        let mut file = File::create(file_path).unwrap();
        writeln!(file, r#"{{ "rules": [ "pattern": "missing braces" ] }}"#).unwrap();

        let result = TemplateEngine::build(dir.path().to_str().unwrap());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Malformed JSON"));
    }
}

#[cfg(kani)]
mod verification {
    use super::*;

    #[kani::proof]
    fn verify_ahocorasick_memory_safety() {
        let patterns = vec!["drop_table".to_string(), "ignore previous".to_string()];
        let ac = AhoCorasickBuilder::new().dfa(false).build(&patterns).unwrap();
        let engine = TemplateEngine { ac, patterns };

        let payload: [u8; 128] = kani::any();
        // Mathematical proof that scanning arbitrary 128 bytes never panics
        let _ = engine.is_match(&payload);
    }
}
