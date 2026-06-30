mod config;
mod proxy;
mod policy;
mod template;
mod shield;

use std::io::{self};
use std::env;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "rmcp", version = "0.3.3", about = "Rust Model Context Protocol Security Gateway")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Build the agent tool calling graph from audit logs
    Scan,
    /// Run MESA Ablation-Based Edge Criticality Ranking
    Mesa,
    /// Install RMCP wrapper into a given MCP config file
    Install {
        path: String,
    },
    /// Generate a new RMCP public/private keypair and lockfile
    Keygen {
        path: String,
    },
    /// Start the proxy (e.g. rmcp npx @modelcontextprotocol/server-postgres)
    #[command(external_subcommand)]
    Proxy(Vec<String>),
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan => {
            return shield::run_scan();
        }
        Commands::Mesa => {
            return shield::run_mesa();
        }
        Commands::Install { path } => {
            match config::install_rmcp(&path) {
                Ok(_) => {
                    println!("Successfully installed RMCP wrapper into {}", path);
                    return Ok(());
                }
                Err(e) => {
                    eprintln!("Installation failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Keygen { path } => {
            match policy::generate_keys(&path) {
                Ok(_) => return Ok(()),
                Err(e) => {
                    eprintln!("Key generation failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Commands::Proxy(args) => {
            if args.is_empty() {
                eprintln!("Error: Proxy requires a command to execute.");
                std::process::exit(1);
            }
            return run_proxy(args).await;
        }
    }
}
fn load_combined_policy(config_path: &str, pubkey_hex: &str, template_patterns: &[String], firewall: &mut shield_firewall::Firewall) -> Result<(policy::PolicyConfig, u64, u64), String> {
    let mut policy = policy::load_policy(config_path, pubkey_hex)?;
    let mut rmcp_time = 0;
    if let Ok(meta) = std::fs::metadata(config_path) {
        rmcp_time = meta.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH)
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    }

    let shield_policy_path = "shield_policy.json";
    let mut shield_time = 0;
    if std::path::Path::new(shield_policy_path).exists() {
        if let Ok(meta) = std::fs::metadata(shield_policy_path) {
            shield_time = meta.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH)
                .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        }
        if let Ok(file) = std::fs::File::open(shield_policy_path) {
            if let Ok(shield_policy) = serde_json::from_reader::<_, policy::PolicyConfig>(file) {
                policy.tool_schemas = shield_policy.tool_schemas;
            }
        }
    }

    // Rebuild firewall schemas
    *firewall = shield_firewall::Firewall::new(template_patterns).unwrap();
    for (tool_name, schema) in &policy.tool_schemas {
        let _ = firewall.add_tool_schema(tool_name.clone(), schema.allowed_fields.clone(), schema.pii_patterns.clone());
    }

    Ok((policy, rmcp_time, shield_time))
}

async fn run_proxy(args: Vec<String>) -> io::Result<()> {
    let max_payload_size: usize = env::var("RMCP_MAX_PAYLOAD_SIZE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1024 * 1024); // Default to 1MB
        
    let config_path = env::var("RMCP_CONFIG_PATH").unwrap_or_else(|_| "rmcp.json".to_string());
    let pubkey_hex = env::var("RMCP_PUBLIC_KEY").unwrap_or_default();

    // Fail-Closed Boot: Compile the Aho-Corasick NFA Template Engine
    let template_patterns = match template::load_patterns("templates") {
        Ok(patterns) => patterns,
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    };
    
    let mut child = Command::new(&args[0])
            .args(&args[1..])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;

        let mut child_stdin = child.stdin.take().expect("Failed to open child stdin");
        let child_stdout = child.stdout.take().expect("Failed to open child stdout");
        let mut child_stderr = child.stderr.take().expect("Failed to open child stderr");

        let config_path_clone1 = config_path.clone();
        let pubkey_hex_clone1 = pubkey_hex.clone();
        let template_patterns_clone1 = template_patterns.clone();

        // Task 1: Forward Host stdin -> Child stdin (With safety bound & Full-Duplex Scanning)
        let stdin_forward = tokio::spawn(async move {
            let mut stdin_reader = BufReader::new(tokio::io::stdin());
            let mut host_stdout = tokio::io::stdout(); // Need to write errors back to Agent
            let mut line_buf = Vec::new();
            
            let mut last_modified_rmcp: u64 = 0;
            let mut last_modified_shield: u64 = 0;
            let mut current_policy = policy::PolicyConfig::default();
            let mut current_firewall = shield_firewall::Firewall::new(&template_patterns_clone1).unwrap();
            let shield_policy_path = "shield_policy.json";

            if !pubkey_hex_clone1.is_empty() {
                if let Ok((p, t1, t2)) = load_combined_policy(&config_path_clone1, &pubkey_hex_clone1, &template_patterns_clone1, &mut current_firewall) {
                    current_policy = p;
                    last_modified_rmcp = t1;
                    last_modified_shield = t2;
                }
            }

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
                        
                        // Policy Hot-Reloading
                        if !pubkey_hex_clone1.is_empty() {
                            let mut needs_reload = false;
                            if let Ok(meta) = std::fs::metadata(&config_path_clone1) {
                                let mtime = meta.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH).duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
                                if mtime > last_modified_rmcp { needs_reload = true; }
                            }
                            if let Ok(meta) = std::fs::metadata(shield_policy_path) {
                                let mtime = meta.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH).duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
                                if mtime > last_modified_shield { needs_reload = true; }
                            }
                            if needs_reload {
                                match load_combined_policy(&config_path_clone1, &pubkey_hex_clone1, &template_patterns_clone1, &mut current_firewall) {
                                    Ok((p, t1, t2)) => {
                                        current_policy = p; last_modified_rmcp = t1; last_modified_shield = t2;
                                    }
                                    Err(e) => {
                                        eprintln!("RMCP Fatal: Config tampered during hot-reload: {}", e);
                                        std::process::exit(1);
                                    }
                                }
                            }
                        }
                        
                        match proxy::process_payload(&line_buf, max_payload_size, &current_policy.blocked_methods, &current_policy.blocked_args, &current_firewall) {
                            Ok(Some(normalized_bytes)) => {
                                if child_stdin.write_all(&normalized_bytes).await.is_err() { break; }
                            }
                            Ok(None) => {}
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
                        stdin_reader.consume(len);
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

        // Task 2: Filter Child stdout -> Host stdout
        let config_path_clone2 = config_path.clone();
        let pubkey_hex_clone2 = pubkey_hex.clone();
        let template_patterns_clone2 = template_patterns.clone();
        
        let stdout_filter = tokio::spawn(async move {
            let mut stdout_reader = BufReader::new(child_stdout);
            let mut host_stdout = tokio::io::stdout();
            let mut line_buf = Vec::new();
            
            let mut last_modified_rmcp: u64 = 0;
            let mut last_modified_shield: u64 = 0;
            let mut current_policy = policy::PolicyConfig::default();
            let mut current_firewall = shield_firewall::Firewall::new(&template_patterns_clone2).unwrap();
            let shield_policy_path = "shield_policy.json";

            if !pubkey_hex_clone2.is_empty() {
                if let Ok((p, t1, t2)) = load_combined_policy(&config_path_clone2, &pubkey_hex_clone2, &template_patterns_clone2, &mut current_firewall) {
                    current_policy = p;
                    last_modified_rmcp = t1;
                    last_modified_shield = t2;
                }
            }
            
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
                        
                        // Policy Hot-Reloading
                        if !pubkey_hex_clone2.is_empty() {
                            let mut needs_reload = false;
                            if let Ok(meta) = std::fs::metadata(&config_path_clone2) {
                                let mtime = meta.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH).duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
                                if mtime > last_modified_rmcp { needs_reload = true; }
                            }
                            if let Ok(meta) = std::fs::metadata(shield_policy_path) {
                                let mtime = meta.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH).duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
                                if mtime > last_modified_shield { needs_reload = true; }
                            }
                            if needs_reload {
                                match load_combined_policy(&config_path_clone2, &pubkey_hex_clone2, &template_patterns_clone2, &mut current_firewall) {
                                    Ok((p, t1, t2)) => {
                                        current_policy = p; last_modified_rmcp = t1; last_modified_shield = t2;
                                    }
                                    Err(e) => {
                                        eprintln!("RMCP Fatal: Config tampered during hot-reload: {}", e);
                                        std::process::exit(1);
                                    }
                                }
                            }
                        }
                        
                        match proxy::process_payload(&line_buf, max_payload_size, &current_policy.blocked_methods, &current_policy.blocked_args, &current_firewall) {
                            Ok(Some(normalized_bytes)) => {
                                if host_stdout.write_all(&normalized_bytes).await.is_err() { break; }
                                let _ = host_stdout.flush().await;
                            }
                            Ok(None) => {}
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

        // Task 3: Forward Child stderr -> Host stderr (Diagnostic Channel)
        let stderr_forward = tokio::spawn(async move {
            let mut host_stderr = tokio::io::stderr();
            let _ = tokio::io::copy(&mut child_stderr, &mut host_stderr).await;
        });

        let _ = tokio::join!(stdin_forward, stdout_filter, stderr_forward);
        
        let status = child.wait().await?;
        if status.success() {
            std::process::exit(0);
        } else {
            eprintln!("RMCP Fatal: Child process crashed with {}. Failing closed.", status);
            std::process::exit(1);
        }
}

