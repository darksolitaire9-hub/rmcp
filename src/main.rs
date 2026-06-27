use std::io::{self, BufRead, Write};
use serde_json::Value;

pub fn process_payload(line: &str) -> Result<Option<Value>, String> {
    let parsed: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(_) => return Err("Invalid JSON".to_string()),
    };
    Ok(Some(parsed))
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    let mut reader = stdin.lock();
    let mut line = String::new();

    while reader.read_line(&mut line)? > 0 {
        match process_payload(&line) {
            Ok(Some(val)) => {
                let out = serde_json::to_string(&val).unwrap();
                stdout.write_all(out.as_bytes())?;
                stdout.write_all(b"\n")?;
                stdout.flush()?;
            }
            Ok(None) => {}
            Err(e) => {
                eprintln!("Error: {}", e);
            }
        }
        line.clear();
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_valid_payload() {
        let payload = json!({"jsonrpc": "2.0", "method": "test", "id": 1}).to_string();
        let result = process_payload(&payload);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().unwrap(), json!({"jsonrpc": "2.0", "method": "test", "id": 1}));
    }

    #[test]
    fn test_invalid_json() {
        let payload = "invalid json";
        let result = process_payload(payload);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid JSON");
    }
}
