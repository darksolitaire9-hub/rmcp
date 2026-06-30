use shield_mesa::{AuditEntry, Edge, ShieldGraph};
use std::collections::HashSet;
use std::env;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

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
    
    // Deduplicate edges
    let unique_edges: HashSet<_> = graph.edges.into_iter().collect();
    graph.edges = unique_edges.into_iter().collect();
    
    graph
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    
    let path = Path::new(".rmcp_audit.log");
    if !path.exists() {
        println!("No audit log found at {:?}", path);
        return Ok(());
    }
    
    let entries = parse_audit_logs(path)?;
    let graph = build_graph(&entries);
    
    if args.len() > 1 && args[1] == "mesa" {
        println!("Running MESA Ablation-Based Edge Criticality Ranking...");
        let rankings = graph.rank_edges_criticality();
        for (i, rank) in rankings.iter().enumerate() {
            println!("#{} Edge {} -> {} ({}) - Score: {}", 
                     i+1, rank.edge.source, rank.edge.target, rank.edge.label, rank.score);
        }
    } else {
        println!("Parsed {} audit entries.", entries.len());
        println!("Graph has {} nodes and {} edges.", graph.nodes.len(), graph.edges.len());
        
        let out_file = File::create("shield_graph.json")?;
        serde_json::to_writer_pretty(out_file, &graph)?;
        println!("Wrote graph to shield_graph.json");
    }
    
    Ok(())
}
