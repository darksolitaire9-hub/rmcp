use serde_json::Value;

pub fn process_payload(line_bytes: &[u8], max_payload_size: usize) -> Result<bool, String> {
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
    
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_valid_payload() {
        let payload = json!({"jsonrpc": "2.0", "method": "test", "id": 1}).to_string();
        let result = process_payload(payload.as_bytes(), 1024 * 1024);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), true);
    }

    #[test]
    fn test_invalid_json() {
        let payload = "invalid json";
        let result = process_payload(payload.as_bytes(), 1024 * 1024);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid JSON");
    }

    #[test]
    fn test_sharelock_threshold_poisoning() {
        let limit = 1024 * 1024;
        let large_string = "a".repeat(limit + 10);
        let payload = json!({"jsonrpc": "2.0", "method": "test", "params": {"data": large_string}}).to_string();
        
        let result = process_payload(payload.as_bytes(), limit);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Payload exceeds maximum allowed size");
    }
}
