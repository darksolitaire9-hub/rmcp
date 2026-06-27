use std::process::{Command, Stdio};
use std::io::Write;
use std::fs;
use ed25519_dalek::{SigningKey, Signer};
use sha2::{Sha256, Digest};

fn setup_signed_config() -> (String, String, String) {
    let config_path = "test_rmcp.json";
    let lock_path = "test_rmcp.json.lock";
    let config_content = "{\"blocked_args\": [\"/etc/passwd\"]}";
    
    fs::write(config_path, config_content).unwrap();
    
    let secret: [u8; 32] = [1; 32];
    let signing_key = SigningKey::from_bytes(&secret);
    let pubkey = signing_key.verifying_key();
    let pubkey_hex = hex::encode(pubkey.as_bytes());
    
    let mut hasher = Sha256::new();
    hasher.update(config_content.as_bytes());
    let config_hash = hasher.finalize();
    
    let signature = signing_key.sign(&config_hash);
    let signature_hex = hex::encode(signature.to_bytes());
    
    fs::write(lock_path, signature_hex).unwrap();
    
    (config_path.to_string(), pubkey_hex, lock_path.to_string())
}

fn cleanup_config(config: &str, lock: &str) {
    let _ = fs::remove_file(config);
    let _ = fs::remove_file(lock);
}

fn get_mock_server() -> Vec<&'static str> {
    #[cfg(target_os = "windows")]
    { vec!["cmd", "/C", "more"] }
    #[cfg(not(target_os = "windows"))]
    { vec!["cat"] }
}

#[test]
fn test_proxy_e2e_forwarding() {
    let mock_server = get_mock_server();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rmcp"));
    for arg in mock_server {
        cmd.arg(arg);
    }
    
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to spawn RMCP");
    
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"ok\"}\n").unwrap();
    drop(stdin); // close stdin to signal EOF

    let output = child.wait_with_output().unwrap();
    let out_str = String::from_utf8_lossy(&output.stdout);
    
    assert!(out_str.contains("jsonrpc"));
    assert!(out_str.contains("\"id\":1"));
}

#[test]
fn test_proxy_e2e_vigil_enforcement() {
    let (config_path, pubkey_hex, lock_path) = setup_signed_config();

    let mock_server = get_mock_server();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rmcp"));
    for arg in mock_server {
        cmd.arg(arg);
    }

    let mut child = cmd
        .env("RMCP_CONFIG_PATH", &config_path)
        .env("RMCP_PUBLIC_KEY", &pubkey_hex)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to spawn RMCP");

    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":99,\"method\":\"read_file\",\"params\":{\"path\":\"/etc/passwd\"}}\n").unwrap();
    drop(stdin); // close stdin

    let output = child.wait_with_output().unwrap();
    let out_str = String::from_utf8_lossy(&output.stdout);
    
    cleanup_config(&config_path, &lock_path);
    
    assert!(out_str.contains("-32603"));
    assert!(out_str.contains("VIGIL Enforcement"));
}
