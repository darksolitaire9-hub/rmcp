use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditEntry {
    pub hash: String,
    pub payload: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct ShieldGraph {
    pub nodes: HashSet<String>,
    pub edges: Vec<Edge>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone)]
pub struct Edge {
    pub source: String,
    pub target: String,
    pub label: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EdgeCriticality {
    pub edge: Edge,
    pub score: usize,
}

impl ShieldGraph {
    /// Returns the number of nodes reachable from the given starting node.
    pub fn reachable_nodes(&self, start: &str) -> usize {
        if !self.nodes.contains(start) {
            return 0;
        }

        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        
        visited.insert(start.to_string());
        queue.push_back(start.to_string());
        
        // Build adjacency list for fast lookup
        let mut adj: HashMap<&str, Vec<&str>> = HashMap::new();
        for edge in &self.edges {
            adj.entry(&edge.source).or_default().push(&edge.target);
        }

        while let Some(node) = queue.pop_front() {
            if let Some(neighbors) = adj.get(node.as_str()) {
                for &neighbor in neighbors {
                    if visited.insert(neighbor.to_string()) {
                        queue.push_back(neighbor.to_string());
                    }
                }
            }
        }
        
        visited.len()
    }

    /// Ranks edges by their criticality (how many fewer nodes are reachable from 'Agent' when the edge is removed)
    pub fn rank_edges_criticality(&self) -> Vec<EdgeCriticality> {
        let baseline = self.reachable_nodes("Agent");
        let mut rankings = Vec::new();

        for i in 0..self.edges.len() {
            let mut ablated_graph = self.clone();
            let removed_edge = ablated_graph.edges.remove(i);
            
            let new_reachability = ablated_graph.reachable_nodes("Agent");
            let score = baseline.saturating_sub(new_reachability);
            
            rankings.push(EdgeCriticality {
                edge: removed_edge,
                score,
            });
        }

        // Sort descending by score
        rankings.sort_by(|a, b| b.score.cmp(&a.score));
        rankings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ablation_ranking() {
        let mut graph = ShieldGraph::default();
        graph.nodes.insert("Agent".to_string());
        graph.nodes.insert("Tool:A".to_string());
        graph.nodes.insert("Tool:B".to_string());
        graph.nodes.insert("Server".to_string());
        
        graph.edges.push(Edge { source: "Agent".to_string(), target: "Tool:A".to_string(), label: "call".to_string() });
        graph.edges.push(Edge { source: "Tool:A".to_string(), target: "Server".to_string(), label: "execute".to_string() });
        
        // Tool B is isolated, doesn't go to Server
        graph.edges.push(Edge { source: "Agent".to_string(), target: "Tool:B".to_string(), label: "call".to_string() });
        
        let rankings = graph.rank_edges_criticality();
        
        // Removing Agent -> Tool:A cuts off Tool:A and Server (2 nodes)
        let first = &rankings[0];
        assert_eq!(first.edge.target, "Tool:A");
        assert_eq!(first.score, 2);
    }
}
