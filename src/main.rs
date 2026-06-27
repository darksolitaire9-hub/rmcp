use std::io::{self};
use std::env;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use serde_json::Value;

const MAX_PAYLOAD_SIZE: usize = 1024 * 1024; // 1 MB limit

pub fn process_payload(line: &str) -> Result<Option<Value>, String> {
    if line.len() > MAX_PAYLOAD_SIZE {
        return Err("Payload exceeds maximum allowed size".to_string());
    }

    let parsed: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(_) => return Err("Invalid JSON".to_string()),
    };
    Ok(Some(parsed))
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <command> [args...]", args[0]);
        std::process::exit(1);
    }

    let mut child = Command::new(&args[1])
        .args(&args[2..])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()?;

    let mut child_stdin = child.stdin.take().expect("Failed to open child stdin");
    let child_stdout = child.stdout.take().expect("Failed to open child stdout");

    // Task 1: Forward Host stdin -> Child stdin (Unfiltered for now, as per architecture)
    let stdin_forward = tokio::spawn(async move {
        let mut stdin_reader = BufReader::new(tokio::io::stdin());
        let mut line = String::new();
        while let Ok(n) = stdin_reader.read_line(&mut line).await {
            if n == 0 { break; }
            if child_stdin.write_all(line.as_bytes()).await.is_err() {
                break;
            }
            line.clear();
        }
    });

    // Task 2: Filter Child stdout -> Host stdout
    let stdout_filter = tokio::spawn(async move {
        let mut stdout_reader = BufReader::new(child_stdout);
        let mut host_stdout = tokio::io::stdout();
        let mut line = String::new();
        
        while let Ok(n) = stdout_reader.read_line(&mut line).await {
            if n == 0 { break; }
            
            match process_payload(&line) {
                Ok(Some(val)) => {
                    let out = format!("{}\n", serde_json::to_string(&val).unwrap());
                    if host_stdout.write_all(out.as_bytes()).await.is_err() {
                        break;
                    }
                    let _ = host_stdout.flush().await;
                }
                Ok(None) => {}
                Err(e) => {
                    eprintln!("RMCP Security Error: {}", e);
                    std::process::exit(1); // Hang up connection
                }
            }
            line.clear();
        }
    });

    let _ = tokio::join!(stdin_forward, stdout_filter);
    let _ = child.wait().await;

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

    #[test]
    fn test_sharelock_threshold_poisoning() {
        let large_string = "a".repeat(MAX_PAYLOAD_SIZE + 10);
        let payload = json!({"jsonrpc": "2.0", "method": "test", "params": {"data": large_string}}).to_string();
        
        let result = process_payload(&payload);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Payload exceeds maximum allowed size");
    }
}

