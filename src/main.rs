use std::io::{self};
use std::env;
use std::fs;
use std::path::Path;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use serde_json::Value;

const MAX_PAYLOAD_SIZE: usize = 1024 * 1024; // 1 MB limit

pub fn process_payload(line_bytes: &[u8]) -> Result<bool, String> {
    if line_bytes.len() > MAX_PAYLOAD_SIZE {
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

pub fn install_rmcp(config_path: &str) -> Result<(), String> {
    let content = fs::read_to_string(config_path).map_err(|e| format!("Failed to read config: {}", e))?;
    let mut config: Value = serde_json::from_str(&content).map_err(|e| format!("Invalid JSON: {}", e))?;
    
    let exe_path = env::current_exe().map_err(|e| format!("Failed to get exe path: {}", e))?;
    let exe_str = exe_path.to_string_lossy().replace("\\", "/");

    let servers = config.get_mut("mcpServers").and_then(|v| v.as_object_mut());
    
    if let Some(servers_map) = servers {
        for (_name, server) in servers_map.iter_mut() {
            if let Some(command) = server.get("command").and_then(|v| v.as_str()) {
                if command.contains("rmcp") {
                    continue; // Already wrapped
                }
                
                let mut new_args = vec![Value::String(command.to_string())];
                if let Some(args) = server.get("args").and_then(|v| v.as_array()) {
                    new_args.extend(args.clone());
                }
                
                if let Some(obj) = server.as_object_mut() {
                    obj.insert("command".to_string(), Value::String(exe_str.clone()));
                    obj.insert("args".to_string(), Value::Array(new_args));
                }
            }
        }
    } else {
        return Err("No 'mcpServers' object found in config".to_string());
    }

    let out_content = serde_json::to_string_pretty(&config).map_err(|e| format!("Failed to serialize: {}", e))?;
    fs::write(config_path, out_content).map_err(|e| format!("Failed to write config: {}", e))?;
    
    Ok(())
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <command> [args...]", args[0]);
        eprintln!("       {} --install <mcp.json>", args[0]);
        std::process::exit(1);
    }

    if args[1] == "--install" {
        if args.len() < 3 {
            eprintln!("Missing path to config file.");
            std::process::exit(1);
        }
        match install_rmcp(&args[2]) {
            Ok(_) => {
                println!("Successfully installed RMCP wrapper into {}", args[2]);
                return Ok(());
            }
            Err(e) => {
                eprintln!("Installation failed: {}", e);
                std::process::exit(1);
            }
        }
    }

    let mut child = Command::new(&args[1])
        .args(&args[2..])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()?;

    let mut child_stdin = child.stdin.take().expect("Failed to open child stdin");
    let child_stdout = child.stdout.take().expect("Failed to open child stdout");

    // Task 1: Forward Host stdin -> Child stdin (With safety bound)
    let stdin_forward = tokio::spawn(async move {
        let mut stdin_reader = BufReader::new(tokio::io::stdin());
        let mut line_buf = Vec::new();
        loop {
            let buf = match stdin_reader.fill_buf().await {
                Ok(b) if b.is_empty() => break,
                Ok(b) => b,
                Err(_) => break,
            };

            match buf.iter().position(|&b| b == b'\n') {
                Some(pos) => {
                    line_buf.extend_from_slice(&buf[..=pos]);
                    stdin_reader.consume(pos + 1);
                    if child_stdin.write_all(&line_buf).await.is_err() { break; }
                    line_buf.clear();
                }
                None => {
                    let len = buf.len();
                    line_buf.extend_from_slice(buf);
                    stdin_reader.consume(len);
                    if line_buf.len() > MAX_PAYLOAD_SIZE {
                        // Drop excessive input for safety
                        break;
                    }
                }
            }
        }
    });

    // Task 2: Filter Child stdout -> Host stdout
    let stdout_filter = tokio::spawn(async move {
        let mut stdout_reader = BufReader::new(child_stdout);
        let mut host_stdout = tokio::io::stdout();
        let mut line_buf = Vec::new();
        
        loop {
            let buf = match stdout_reader.fill_buf().await {
                Ok(b) if b.is_empty() => break,
                Ok(b) => b,
                Err(_) => break,
            };

            match buf.iter().position(|&b| b == b'\n') {
                Some(pos) => {
                    line_buf.extend_from_slice(&buf[..=pos]);
                    stdout_reader.consume(pos + 1);
                    
                    match process_payload(&line_buf) {
                        Ok(true) => {
                            if host_stdout.write_all(&line_buf).await.is_err() { break; }
                            let _ = host_stdout.flush().await;
                        }
                        Ok(false) => {}
                        Err(e) => {
                            eprintln!("RMCP Security Error: {}", e);
                            std::process::exit(1);
                        }
                    }
                    line_buf.clear();
                }
                None => {
                    let len = buf.len();
                    line_buf.extend_from_slice(buf);
                    stdout_reader.consume(len);
                    if line_buf.len() > MAX_PAYLOAD_SIZE {
                        eprintln!("RMCP Security Error: Payload exceeds maximum allowed size");
                        std::process::exit(1);
                    }
                }
            }
        }
    });

    let _ = tokio::join!(stdin_forward, stdout_filter);
    
    // Disaster Recovery: Bubble up exact exit code
    let status = child.wait().await?;
    std::process::exit(status.code().unwrap_or(1));
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_valid_payload() {
        let payload = json!({"jsonrpc": "2.0", "method": "test", "id": 1}).to_string();
        let result = process_payload(payload.as_bytes());
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), true);
    }

    #[test]
    fn test_invalid_json() {
        let payload = "invalid json";
        let result = process_payload(payload.as_bytes());
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid JSON");
    }

    #[test]
    fn test_sharelock_threshold_poisoning() {
        let large_string = "a".repeat(MAX_PAYLOAD_SIZE + 10);
        let payload = json!({"jsonrpc": "2.0", "method": "test", "params": {"data": large_string}}).to_string();
        
        let result = process_payload(payload.as_bytes());
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Payload exceeds maximum allowed size");
    }

    #[test]
    fn test_install_logic() {
        let test_config = json!({
            "mcpServers": {
                "test-server": {
                    "command": "node",
                    "args": ["index.js"]
                }
            }
        });
        
        let file_path = "test_mcp.json";
        fs::write(file_path, test_config.to_string()).unwrap();
        
        let _ = install_rmcp(file_path);
        
        let modified_content = fs::read_to_string(file_path).unwrap();
        let modified_json: Value = serde_json::from_str(&modified_content).unwrap();
        
        let cmd = modified_json["mcpServers"]["test-server"]["command"].as_str().unwrap();
        assert!(cmd.contains("rmcp"));
        
        let args = modified_json["mcpServers"]["test-server"]["args"].as_array().unwrap();
        assert_eq!(args[0].as_str().unwrap(), "node");
        assert_eq!(args[1].as_str().unwrap(), "index.js");
        
        fs::remove_file(file_path).unwrap();
    }
}

