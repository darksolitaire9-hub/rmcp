mod config;
mod proxy;

use std::io::{self};
use std::env;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

#[tokio::main]
async fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <command> [args...]", args[0]);
        eprintln!("       {} --install <mcp.json>", args[0]);
        std::process::exit(1);
    }
    
    let max_payload_size: usize = env::var("RMCP_MAX_PAYLOAD_SIZE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1024 * 1024); // Default to 1MB
        
    let blocked_methods: Vec<String> = env::var("RMCP_BLOCKED_METHODS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if args[1] == "--install" {
        if args.len() < 3 {
            eprintln!("Missing path to config file.");
            std::process::exit(1);
        }
        match config::install_rmcp(&args[2]) {
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

    let mut crash_count = 0;
    loop {
        let mut child = Command::new(&args[1])
            .args(&args[2..])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;

        let mut child_stdin = child.stdin.take().expect("Failed to open child stdin");
        let child_stdout = child.stdout.take().expect("Failed to open child stdout");

        // Task 1: Forward Host stdin -> Child stdin (With safety bound)
        let stdin_forward = tokio::spawn(async move {
            let mut stdin_reader = BufReader::new(tokio::io::stdin());
            let mut line_buf = Vec::new();
            loop {
                let buf = match stdin_reader.fill_buf().await {
                    Ok([]) => break,
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
                        if line_buf.len() > max_payload_size {
                            // Drop excessive input for safety
                            break;
                        }
                    }
                }
            }
        });

        // Task 2: Filter Child stdout -> Host stdout
        let blocked_methods_clone = blocked_methods.clone();
        let stdout_filter = tokio::spawn(async move {
            let mut stdout_reader = BufReader::new(child_stdout);
            let mut host_stdout = tokio::io::stdout();
            let mut line_buf = Vec::new();
            
            loop {
                let buf = match stdout_reader.fill_buf().await {
                    Ok([]) => break,
                    Ok(b) => b,
                    Err(_) => break,
                };

                match buf.iter().position(|&b| b == b'\n') {
                    Some(pos) => {
                        line_buf.extend_from_slice(&buf[..=pos]);
                        stdout_reader.consume(pos + 1);
                        
                        match proxy::process_payload(&line_buf, max_payload_size, &blocked_methods_clone) {
                            Ok(true) => {
                                if host_stdout.write_all(&line_buf).await.is_err() { break; }
                                let _ = host_stdout.flush().await;
                            }
                            Ok(false) => {}
                            Err(e) => {
                                let error_msg = proxy::synthesize_error(&line_buf, &e);
                                let _ = host_stdout.write_all(error_msg.as_bytes()).await;
                                let _ = host_stdout.flush().await;
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
                        if line_buf.len() > max_payload_size {
                            let e = "Payload exceeds maximum allowed size";
                            let error_msg = proxy::synthesize_error(&line_buf, e);
                            let _ = host_stdout.write_all(error_msg.as_bytes()).await;
                            let _ = host_stdout.flush().await;
                            eprintln!("RMCP Security Error: {}", e);
                            std::process::exit(1);
                        }
                    }
                }
            }
        });

        let _ = tokio::join!(stdin_forward, stdout_filter);
        
        let status = child.wait().await?;
        if status.success() {
            std::process::exit(0);
        } else {
            crash_count += 1;
            let backoff = std::cmp::min(1 << crash_count, 16);
            eprintln!("RMCP: Child process crashed with {}. Restarting in {}s... (BEAM Variant)", status, backoff);
            tokio::time::sleep(tokio::time::Duration::from_secs(backoff)).await;
            continue;
        }
    }
}
