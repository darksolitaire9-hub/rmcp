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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MesaEdge {
    pub source: String,
    pub target: String,
    pub impact_score: f64,
    pub policy_tier: String,
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

    fn calculate_tier(impact: f64) -> String {
        if impact >= 0.3 { "critical".to_string() }
        else if impact >= 0.1 { "elevated".to_string() }
        else { "standard".to_string() }
    }

    /// Ranks all edges by their criticality (how many fewer nodes are reachable from 'Agent' when the edge is removed)
    pub fn rank_edges_criticality(&self) -> Vec<MesaEdge> {
        let baseline = self.reachable_nodes("Agent");
        let mut rankings = Vec::new();

        for i in 0..self.edges.len() {
            let mut ablated_graph = self.clone();
            let removed_edge = ablated_graph.edges.remove(i);
            
            let new_reachability = ablated_graph.reachable_nodes("Agent");
            let score = baseline.saturating_sub(new_reachability);
            let impact_score = if baseline > 0 { score as f64 / baseline as f64 } else { 0.0 };
            
            rankings.push(MesaEdge {
                source: removed_edge.source,
                target: removed_edge.target,
                impact_score,
                policy_tier: Self::calculate_tier(impact_score),
            });
        }

        rankings.sort_by(|a, b| b.impact_score.partial_cmp(&a.impact_score).unwrap_or(std::cmp::Ordering::Equal));
        rankings
    }

    /// Incrementally re-ranks only edges that share a source or target with the new_edges.
    pub fn incremental_rank(&self, mut previous_rankings: Vec<MesaEdge>, new_edges: &[Edge]) -> Vec<MesaEdge> {
        let baseline = self.reachable_nodes("Agent");
        
        let mut affected_nodes = HashSet::new();
        for edge in new_edges {
            affected_nodes.insert(&edge.source);
            affected_nodes.insert(&edge.target);
        }

        // Re-calculate for new edges and affected edges
        let mut recomputed = HashSet::new();
        for i in 0..self.edges.len() {
            let edge = &self.edges[i];
            if affected_nodes.contains(&edge.source) || affected_nodes.contains(&edge.target) {
                let mut ablated_graph = self.clone();
                let removed_edge = ablated_graph.edges.remove(i);
                let new_reachability = ablated_graph.reachable_nodes("Agent");
                let score = baseline.saturating_sub(new_reachability);
                let impact_score = if baseline > 0 { score as f64 / baseline as f64 } else { 0.0 };
                
                recomputed.insert((removed_edge.source.clone(), removed_edge.target.clone()));
                
                // Remove old ranking if exists
                previous_rankings.retain(|r| !(r.source == removed_edge.source && r.target == removed_edge.target));
                
                previous_rankings.push(MesaEdge {
                    source: removed_edge.source,
                    target: removed_edge.target,
                    impact_score,
                    policy_tier: Self::calculate_tier(impact_score),
                });
            }
        }

        previous_rankings.sort_by(|a, b| b.impact_score.partial_cmp(&a.impact_score).unwrap_or(std::cmp::Ordering::Equal));
        previous_rankings
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
        // Baseline is 4, new reachability is 2, score is 2. Impact is 2/4 = 0.5.
        let first = &rankings[0];
        assert_eq!(first.target, "Tool:A");
        assert_eq!(first.impact_score, 0.5);
        assert_eq!(first.policy_tier, "critical");
    }
}
