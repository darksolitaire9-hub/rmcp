use shield_mesa::{AuditEntry, Edge, ShieldGraph};
use std::collections::HashSet;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;
use std::time::SystemTime;
use crate::policy::{PolicyConfig, ToolSchema};

pub fn parse_audit_logs(path: &Path) -> io::Result<Vec<AuditEntry>> {
    let file = File::open(path)?;
    let reader = io::BufReader::new(file);
    let mut entries = Vec::new();

    for line in reader.lines() {
        let line = line?;
        if line.starts_with("[AUDIT] ") {
            let parts: Vec<&str> = line.splitn(3, ' ').collect();
            if parts.len() == 3 {
                if let Ok(payload) = serde_json::from_str(parts[2]) {
                    entries.push(AuditEntry {
                        hash: parts[1].to_string(),
                        payload,
                    });
                }
            }
        }
    }
    Ok(entries)
}

pub fn build_graph(entries: &[AuditEntry]) -> ShieldGraph {
    let mut graph = ShieldGraph::default();
    graph.nodes.insert("Agent".to_string());
    graph.nodes.insert("Server".to_string());

    for entry in entries {
        if let Some(method) = entry.payload.get("method").and_then(|m| m.as_str()) {
            let tool_name = format!("Tool:{}", method);
            graph.nodes.insert(tool_name.clone());
            graph.edges.push(Edge {
                source: "Agent".to_string(),
                target: tool_name.clone(),
                label: "call".to_string(),
            });
            graph.edges.push(Edge {
                source: tool_name,
                target: "Server".to_string(),
                label: "execute".to_string(),
            });
        } else if entry.payload.get("result").is_some() || entry.payload.get("error").is_some() {
            graph.edges.push(Edge {
                source: "Server".to_string(),
                target: "Agent".to_string(),
                label: "response".to_string(),
            });
        }
    }
    
    let unique_edges: HashSet<_> = graph.edges.into_iter().collect();
    graph.edges = unique_edges.into_iter().collect();
    
    graph
}

pub fn run_scan() -> io::Result<()> {
    let path = Path::new(".rmcp_audit.log");
    if !path.exists() {
        println!("No audit log found at {:?}", path);
        return Ok(());
    }
    
    let entries = parse_audit_logs(path)?;
    let graph = build_graph(&entries);

    println!("Parsed {} audit entries.", entries.len());
    println!("Graph has {} nodes and {} edges.", graph.nodes.len(), graph.edges.len());
    
    let out_file = File::create("shield_graph.json")?;
    serde_json::to_writer_pretty(out_file, &graph)?;
    println!("Wrote graph to shield_graph.json");
    
    Ok(())
}

pub fn run_mesa() -> io::Result<()> {
    let path = Path::new(".rmcp_audit.log");
    if !path.exists() {
        println!("No audit log found at {:?}", path);
        return Ok(());
    }
    
    let entries = parse_audit_logs(path)?;
    let graph = build_graph(&entries);

    println!("Running MESA Ablation-Based Edge Criticality Ranking...");
    let rankings = graph.rank_edges_criticality();
    
    let mut critical_edges = 0;
    let mut elevated_edges = 0;
    let mut standard_edges = 0;

    for rank in &rankings {
        match rank.policy_tier.as_str() {
            "critical" => critical_edges += 1,
            "elevated" => elevated_edges += 1,
            _ => standard_edges += 1,
        }
    }

    let confidence = if entries.len() > 100 {
        "high"
    } else if entries.len() >= 50 {
        "medium"
    } else {
        "low"
    };

    let shield_policy_path = "shield_policy.json";
    let mut policy = if Path::new(shield_policy_path).exists() {
        let file = File::open(shield_policy_path)?;
        serde_json::from_reader(file).unwrap_or_else(|_| PolicyConfig::default())
    } else {
        PolicyConfig::default()
    };

    policy.mesa_edges = rankings;

    let mut tools_with_schemas = 0;
    let mut tools_without_schemas = 0;
    
    for node in &graph.nodes {
        if node.starts_with("Tool:") {
            let tool_name = node.trim_start_matches("Tool:");
            if policy.tool_schemas.contains_key(tool_name) {
                tools_with_schemas += 1;
            } else {
                policy.tool_schemas.insert(tool_name.to_string(), ToolSchema {
                    allowed_fields: vec![],
                    pii_patterns: vec![],
                });
                tools_without_schemas += 1;
            }
        }
    }

    let pii_patterns_loaded: usize = policy.tool_schemas.values().map(|s| s.pii_patterns.len()).sum();

    let out_policy = File::create(shield_policy_path)?;
    serde_json::to_writer_pretty(out_policy, &policy)?;

    let report = serde_json::json!({
        "timestamp": SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs(),
        "audit_entries_parsed": entries.len(),
        "graph": {
            "nodes": graph.nodes.len(),
            "edges": graph.edges.len(),
            "coverage": 1.0
        },
        "mesa": {
            "critical_edges": critical_edges,
            "elevated_edges": elevated_edges,
            "standard_edges": standard_edges,
            "confidence": confidence
        },
        "firewall": {
            "tools_with_schemas": tools_with_schemas,
            "tools_without_schemas": tools_without_schemas,
            "pii_patterns_loaded": pii_patterns_loaded
        }
    });

    let out_report = File::create("shield_report.json")?;
    serde_json::to_writer_pretty(out_report, &report)?;

    println!("Shield Report:");
    println!("  Edges discovered: {} (from {} audit entries)", graph.edges.len(), entries.len());
    println!("  Critical edges:   {}", critical_edges);
    println!("  Elevated edges:   {}", elevated_edges);
    println!("  Policy generated: shield_policy.json");
    
    Ok(())
}
