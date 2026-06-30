use std::fs;
use serde_json::Value;
use walkdir::WalkDir;

pub fn load_patterns(template_dir: &str) -> Result<Vec<String>, String> {
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
    
    Ok(patterns)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_malformed_json_fails_closed() {
        let dir = "templates_test_dummy";
        let _ = std::fs::remove_dir_all(dir);
        std::fs::create_dir(dir).unwrap();
        std::fs::write(format!("{}/bad.json", dir), "{ bad json }").unwrap();

        let result = load_patterns(dir);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Malformed JSON detected"));
        
        let _ = std::fs::remove_dir_all(dir);
    }
}
