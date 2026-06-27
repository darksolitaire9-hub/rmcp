use std::env;
use std::fs;
use serde_json::Value;

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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
