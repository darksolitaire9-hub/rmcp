
use std::fs;
use sha2::{Sha256, Digest};
use ed25519_dalek::{VerifyingKey, Signature, Verifier};
use std::convert::TryInto;

use std::collections::HashMap;

#[derive(serde::Serialize, serde::Deserialize, Clone, Default)]
pub struct ToolSchema {
    #[serde(default)]
    pub allowed_fields: Vec<String>,
    #[serde(default)]
    pub pii_patterns: Vec<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Default)]
pub struct PolicyConfig {
    #[serde(default)]
    pub shield_version: String,
    #[serde(default)]
    pub blocked_methods: Vec<String>,
    #[serde(default)]
    pub blocked_args: Vec<String>,
    #[serde(default)]
    pub tool_schemas: HashMap<String, ToolSchema>,
}

pub fn load_policy(config_path: &str, pubkey_hex: &str) -> Result<PolicyConfig, String> {
    let content = fs::read(config_path).map_err(|e| format!("Failed to read config: {}", e))?;
    
    // Config integrity check
    let lock_path = format!("{}.lock", config_path);
    let lock_hex = fs::read_to_string(&lock_path).map_err(|e| format!("Missing lockfile: {}", e))?;
    
    // SHA-256 hashing
    let mut hasher = Sha256::new();
    hasher.update(&content);
    let config_hash = hasher.finalize();
    
    // Signature verification
    let sig_bytes = hex::decode(lock_hex.trim()).map_err(|_| "Invalid lockfile hex")?;
    let pubkey_bytes = hex::decode(pubkey_hex.trim()).map_err(|_| "Invalid pubkey hex")?;
    
    if pubkey_bytes.len() != 32 { return Err("Pubkey must be 32 bytes".to_string()); }
    if sig_bytes.len() != 64 { return Err("Signature must be 64 bytes".to_string()); }
    
    let public_key = VerifyingKey::from_bytes(pubkey_bytes.as_slice().try_into().unwrap())
        .map_err(|_| "Invalid pubkey format")?;
    let signature = Signature::from_bytes(sig_bytes.as_slice().try_into().unwrap());
    
    // Verify the SHA-256 hash signature
    public_key.verify(&config_hash, &signature)
        .map_err(|_| "Signature mismatch! Tamper detected in config.")?;
    
    let config: PolicyConfig = serde_json::from_slice(&content)
        .map_err(|e| format!("Invalid JSON config: {}", e))?;
        
    Ok(config)
}

pub fn generate_keys(config_path: &str) -> Result<String, Box<dyn std::error::Error>> {
    let content = fs::read_to_string(config_path)?;
    let lock_path = format!("{}.lock", config_path);
    
    // Generate a secure random keypair
    use rand_core::OsRng;
    use ed25519_dalek::{SigningKey, Signer};
    
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();
    
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    let config_hash = hasher.finalize();
    
    let signature = signing_key.sign(&config_hash);
    let signature_hex = hex::encode(signature.to_bytes());
    
    fs::write(&lock_path, signature_hex)?;
    
    let pubkey_hex = hex::encode(verifying_key.as_bytes());
    println!("✅ Security Lockfile Generated: {}", lock_path);
    println!("🔑 RMCP_PUBLIC_KEY: {}", pubkey_hex);
    println!("Store this key safely and pass it to RMCP via the RMCP_PUBLIC_KEY environment variable.");
    Ok(pubkey_hex)
}
