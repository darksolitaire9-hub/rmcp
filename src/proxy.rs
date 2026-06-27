use serde_json::Value;

pub fn process_payload(line_bytes: &[u8], max_payload_size: usize, blocked_methods: &[String]) -> Result<bool, String> {
    if line_bytes.len() > max_payload_size {
        return Err("Payload exceeds maximum allowed size".to_string());
    }

    // Attempt to convert and parse, ignore empty lines
    let line_str = std::str::from_utf8(line_bytes).unwrap_or("").trim();
    if line_str.is_empty() {
        return Ok(false);
    }

    if serde_json::from_str::<Value>(line_str).is_err() {
        return Err("Invalid JSON".to_string());
    }

    let method = extract_jsonrpc_method(line_bytes);
    if let Some(m) = method {
        if blocked_methods.contains(&m) {
            return Err(format!("Method '{}' is blocked by enterprise policy", m));
        }
    }
    
    Ok(true)
}

pub fn extract_jsonrpc_id(bytes: &[u8]) -> Value {
    let text = String::from_utf8_lossy(bytes);
    if let Some(idx) = text.find("\"id\"") {
        let rest = &text[idx + 4..];
        if let Some(colon_idx) = rest.find(':') {
            let value_str = rest[colon_idx + 1..].trim_start();
            let end_idx = value_str.find(|c| c == ',' || c == '}').unwrap_or(value_str.len());
            let val = value_str[..end_idx].trim();
            if let Ok(parsed) = serde_json::from_str::<Value>(val) {
                return parsed;
            }
        }
    }
    Value::Null
}

pub fn extract_jsonrpc_method(bytes: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(bytes);
    if let Some(idx) = text.find("\"method\"") {
        let rest = &text[idx + 8..];
        if let Some(colon_idx) = rest.find(':') {
            let value_str = rest[colon_idx + 1..].trim_start();
            let end_idx = value_str.find(|c| c == ',' || c == '}').unwrap_or(value_str.len());
            let val = value_str[..end_idx].trim();
            if let Ok(parsed) = serde_json::from_str::<Value>(val) {
                if let Some(s) = parsed.as_str() {
                    return Some(s.to_string());
                }
            }
        }
    }
    None
}

pub fn synthesize_error(bytes: &[u8], reason: &str) -> String {
    let id = extract_jsonrpc_id(bytes);
    let error_msg = serde_json::json!({
        "jsonrpc": "2.0",
        "error": {
            "code": -32603,
            "message": format!("RMCP Security: {}", reason)
        },
        "id": id
    });
    format!("{}\n", error_msg.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_valid_payload() {
        let payload = json!({"jsonrpc": "2.0", "method": "test", "id": 1}).to_string();
        let result = process_payload(payload.as_bytes(), 1024 * 1024, &[]);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), true);
    }

    #[test]
    fn test_invalid_json() {
        let payload = "invalid json";
        let result = process_payload(payload.as_bytes(), 1024 * 1024, &[]);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid JSON");
    }

    #[test]
    fn test_sharelock_threshold_poisoning() {
        let limit = 1024 * 1024;
        let large_string = "a".repeat(limit + 10);
        let payload = json!({"jsonrpc": "2.0", "method": "test", "params": {"data": large_string}}).to_string();
        
        let result = process_payload(payload.as_bytes(), limit, &[]);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Payload exceeds maximum allowed size");
    }

    #[test]
    fn test_policy_engine_blocklist() {
        let payload = json!({"jsonrpc": "2.0", "method": "delete_database", "id": 1}).to_string();
        let blocked = vec!["delete_database".to_string()];
        
        let result = process_payload(payload.as_bytes(), 1024 * 1024, &blocked);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("blocked by enterprise policy"));
        
        let safe_payload = json!({"jsonrpc": "2.0", "method": "read_file", "id": 1}).to_string();
        let safe_result = process_payload(safe_payload.as_bytes(), 1024 * 1024, &blocked);
        assert!(safe_result.is_ok());
    }

    #[test]
    fn test_extract_jsonrpc_id() {
        let payload = b"{\"jsonrpc\": \"2.0\", \"id\": 42, \"result\": \"huge...\"";
        let id = extract_jsonrpc_id(payload);
        assert_eq!(id, json!(42));
        
        let payload_str = b"{\"jsonrpc\": \"2.0\", \"id\": \"abc\", \"result\": \"huge...\"";
        let id_str = extract_jsonrpc_id(payload_str);
        assert_eq!(id_str, json!("abc"));
    }
}
