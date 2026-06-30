use serde_json::Value;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::RwLock;
use sha2::{Sha256, Digest};

static AUDIT_CHAIN: RwLock<[u8; 32]> = RwLock::new([0u8; 32]);

static CALL_COUNT: AtomicUsize = AtomicUsize::new(0);
static LAST_CALL_TIME: AtomicUsize = AtomicUsize::new(0);

// SEO Motif Auditor (Paper 30): Detects high-frequency call clusters (motif-hubs)
pub fn check_motif_hub_anomaly() -> Result<(), String> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as usize;
    let last = LAST_CALL_TIME.swap(now, Ordering::Relaxed);
    
    if now == last {
        let count = CALL_COUNT.fetch_add(1, Ordering::Relaxed);
        if count >= 50 {
            return Err("SEO Motif Auditor: Rate Limit Exceeded. Detected anomalous high-frequency tool call cluster (Motif-Hub). Possible autonomous loop.".to_string());
        }
    } else {
        CALL_COUNT.store(1, Ordering::Relaxed);
    }
    Ok(())
}

// Rel(AI)Build Audit Log (Paper 14)
fn log_audit(payload: &[u8]) {
    let mut chain = AUDIT_CHAIN.write().unwrap();
    let mut hasher = Sha256::new();
    hasher.update(*chain);
    hasher.update(payload);
    let new_hash: [u8; 32] = hasher.finalize().into();
    *chain = new_hash;

    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(".rmcp_audit.log") {
        let _ = file.write_all(b"[AUDIT] ");
        let _ = file.write_all(hex::encode(*chain).as_bytes());
        let _ = file.write_all(b" ");
        let _ = file.write_all(payload);
        let _ = file.write_all(b"\n");
    }
}
pub fn process_payload(line_bytes: &[u8], max_payload_size: usize, blocked_methods: &[String], blocked_args: &[String], firewall: &shield_firewall::Firewall) -> Result<bool, String> {
    if line_bytes.len() > max_payload_size {
        return Err("Payload exceeds maximum allowed size".to_string());
    }

    let line_str = std::str::from_utf8(line_bytes).unwrap_or("").trim();
    if line_str.is_empty() {
        return Ok(false);
    }

    log_audit(line_bytes); // Rel(AI)Build Logging

    #[cfg(not(test))]
    check_motif_hub_anomaly()?; // SEO Motif Auditor

    let parsed: Value = match serde_json::from_str(line_str) {
        Ok(v) => v,
        Err(_) => return Err("Invalid JSON".to_string()),
    };

    if let Some(m) = parsed.get("method").and_then(|v| v.as_str())
        && blocked_methods.contains(&m.to_string())
    {
        return Err(format!("Method '{}' is blocked by enterprise policy", m));
    }

    // Delegate deep pattern inspection to Firewall
    if let Err(e) = firewall.scan_payload(line_str, blocked_args) {
        return Err(e);
    }
    
    Ok(true)
}

pub fn extract_jsonrpc_id(bytes: &[u8]) -> Value {
    let text = String::from_utf8_lossy(bytes);
    if let Some(idx) = text.find("\"id\"") {
        let rest = &text[idx + 4..];
        if let Some(colon_idx) = rest.find(':') {
            let value_str = rest[colon_idx + 1..].trim_start();
            let end_idx = value_str.find([',', '}']).unwrap_or(value_str.len());
            let val = value_str[..end_idx].trim();
            if let Ok(parsed) = serde_json::from_str::<Value>(val) {
                return parsed;
            }
        }
    }
    Value::Null
}

pub fn synthesize_error(bytes: &[u8], reason: &str) -> String {
    let id = extract_jsonrpc_id(bytes);
    let message = if reason.starts_with("Shield:") {
        format!("RMCP {}", reason)
    } else {
        format!("RMCP Security: {}", reason)
    };
    
    let error_msg = serde_json::json!({
        "jsonrpc": "2.0",
        "error": {
            "code": -32603,
            "message": message
        },
        "id": id
    });
    format!("{}\n", error_msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_valid_payload() {
        let firewall = shield_firewall::Firewall::new(&[]).unwrap();
        let payload = json!({"jsonrpc": "2.0", "method": "test", "id": 1}).to_string();
        let result = process_payload(payload.as_bytes(), 1024 * 1024, &[], &[], &firewall);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), true);
    }

    #[test]
    fn test_invalid_json() {
        let firewall = shield_firewall::Firewall::new(&[]).unwrap();
        let payload = "invalid json";
        let result = process_payload(payload.as_bytes(), 1024 * 1024, &[], &[], &firewall);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid JSON");
    }

    #[test]
    fn test_sharelock_threshold_poisoning() {
        let firewall = shield_firewall::Firewall::new(&[]).unwrap();
        let limit = 1024 * 1024;
        let large_string = "a".repeat(limit + 10);
        let payload = json!({"jsonrpc": "2.0", "method": "test", "params": {"data": large_string}}).to_string();
        
        let result = process_payload(payload.as_bytes(), limit, &[], &[], &firewall);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Payload exceeds maximum allowed size");
    }

    #[test]
    fn test_policy_engine_blocklist() {
        let firewall = shield_firewall::Firewall::new(&[]).unwrap();
        let payload = json!({"jsonrpc": "2.0", "method": "delete_database", "id": 1}).to_string();
        let blocked = vec!["delete_database".to_string()];
        
        let result = process_payload(payload.as_bytes(), 1024 * 1024, &blocked, &[], &firewall);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("blocked by enterprise policy"));
        
        let safe_payload = json!({"jsonrpc": "2.0", "method": "read_file", "id": 1}).to_string();
        let safe_result = process_payload(safe_payload.as_bytes(), 1024 * 1024, &blocked, &[], &firewall);
        assert!(safe_result.is_ok());
    }

    #[test]
    fn test_pattern_based_argument_scrubbing() {
        let firewall = shield_firewall::Firewall::new(&[]).unwrap();
        let payload = json!({"jsonrpc": "2.0", "method": "read_file", "params": {"path": "/etc/passwd"}}).to_string();
        let blocked_args = vec!["/etc/passwd".to_string()];
        let result = process_payload(payload.as_bytes(), 1024 * 1024, &[], &blocked_args, &firewall);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Pattern-Based Argument Scrubbing"));
    }

    #[test]
    fn test_sharelock_response_scanning() {
        let firewall = shield_firewall::Firewall::new(&[]).unwrap();
        let payload = json!({"jsonrpc": "2.0", "id": 1, "result": {"description": "some text containing /etc/passwd share"}}).to_string();
        let blocked_args = vec!["/etc/passwd".to_string()];
        let result = process_payload(payload.as_bytes(), 1024 * 1024, &[], &blocked_args, &firewall);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("ShareLock Mitigation"));
    }

    #[test]
    fn test_audit_hash_chaining() {
        let payload1 = b"test payload 1";
        let payload2 = b"test payload 2";
        
        let initial_hash = *super::AUDIT_CHAIN.read().unwrap();
        
        super::log_audit(payload1);
        let hash1 = *super::AUDIT_CHAIN.read().unwrap();
        assert_ne!(initial_hash, hash1);
        
        super::log_audit(payload2);
        let hash2 = *super::AUDIT_CHAIN.read().unwrap();
        assert_ne!(hash1, hash2);
        
        // Cleanup test artifacts
        let _ = std::fs::remove_file(".rmcp_audit.log");
    }

    #[test]
    fn test_extract_jsonrpc_id() {
        let payload = b"{\"jsonrpc\": \"2.0\", \"id\": 42, \"result\": \"huge...\"";
        let id = extract_jsonrpc_id(payload);
        assert_eq!(id, json!(42));
        
        let payload_str = b"{\"jsonrpc\": \"2.0\", \"id\": \"req-1\", \"result\": \"huge...\"";
        let id_str = extract_jsonrpc_id(payload_str);
        assert_eq!(id_str, json!("req-1"));

        let payload_missing = b"{\"jsonrpc\": \"2.0\", \"result\": \"huge...\"";
        let id_missing = extract_jsonrpc_id(payload_missing);
        assert_eq!(id_missing, Value::Null);
    }

    #[test]
    fn test_synthesize_error_format() {
        let payload = b"{\"jsonrpc\": \"2.0\", \"id\": 99, \"method\": \"bad_tool\"}";
        let error_str = synthesize_error(payload, "Policy blocked");
        
        // Parse the generated error string to verify it is strict JSON-RPC 2.0 compliant
        let parsed: Value = serde_json::from_str(&error_str).expect("Should synthesize valid JSON");
        
        assert_eq!(parsed["jsonrpc"], "2.0");
        assert_eq!(parsed["id"], 99);
        assert!(parsed["error"].is_object());
        assert_eq!(parsed["error"]["code"], -32603);
        assert_eq!(parsed["error"]["message"], "RMCP Security: Policy blocked");
    }
    #[test]
    fn test_seo_motif_auditor() {
        // Reset state
        super::CALL_COUNT.store(0, std::sync::atomic::Ordering::Relaxed);
        super::LAST_CALL_TIME.store(0, std::sync::atomic::Ordering::Relaxed);
        
        for _ in 0..50 {
            assert!(super::check_motif_hub_anomaly().is_ok());
        }
        
        // The 51st call within the same second should trigger the motif-hub anomaly
        let result = super::check_motif_hub_anomaly();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("SEO Motif Auditor"));
    }
}

#[cfg(kani)]
mod verification {
    use super::*;

    #[kani::proof]
    fn verify_process_payload_memory_safety() {
        let max_size: usize = kani::any();
        kani::assume(max_size <= 1024 * 1024); // Up to 1MB

        // Verify that any arbitrary 128-byte slice processed by the proxy
        // will never panic, guaranteeing the Unfireable Safety Kernel property (Paper 43).
        let payload: [u8; 128] = kani::any();
        let blocked = vec![String::from("malicious_tool")];
        let engine = crate::template::TemplateEngine::build("").unwrap();
        
        let _ = process_payload(&payload, max_size, &blocked, &[], &engine);
    }

    #[kani::proof]
    fn verify_extract_jsonrpc_id_safety() {
        let payload: [u8; 128] = kani::any();
        let _ = extract_jsonrpc_id(&payload);
    }
}

