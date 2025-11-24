
use anyhow::{anyhow, Result};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

use crate::fs_types::ChunkMeta;

// -----------------------------------------------------------
// Structures describing cluster state
// -----------------------------------------------------------

#[derive(Debug, Clone)]
pub struct DriveStatus {
    pub drive_id: String,
    pub free_bytes: u64,
    pub allocated_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct NodeStatus {
    pub node_id: String,
    pub mesh_score: f32,
    pub drives: Vec<DriveStatus>,
}

#[derive(Debug, Clone)]
pub struct ClusterState {
    pub nodes: Vec<NodeStatus>,
}

// -----------------------------------------------------------
// CHUNK ALLOCATION ALGORITHM
// -----------------------------------------------------------
//
// Inputs:
//   - file_path: string identifying file
//   - chunk_idx: zero-based chunk index
//   - cluster: snapshot of cluster node info
//
// Output:
//   ChunkMeta: { index, node_id, drive_id, chunk_hash }
//
// -----------------------------------------------------------

pub fn allocate_chunk(
    file_path: &str,
    chunk_idx: u64,
    cluster: &ClusterState,
    content_hash: &str,
) -> Result<ChunkMeta> {
    if cluster.nodes.is_empty() {
        return Err(anyhow!("no nodes available"));
    }

    // -------------------------------------------------------
    // Compute maximum free space across all nodes for scaling
    // -------------------------------------------------------
    let max_free = cluster
        .nodes
        .iter()
        .map(|n| n.drives.iter().map(|d| d.free_bytes).sum::<u64>())
        .max()
        .unwrap_or(1);

    // -------------------------------------------------------
    // Weight function
    //
    // Balanced to prefer:
    //   - nodes with high mesh score
    //   - nodes with lots of free space
    // -------------------------------------------------------
    const W_SCORE: f32 = 0.6;
    const W_SPACE: f32 = 0.4;

    let mut candidates = Vec::new();

    for node in &cluster.nodes {
        let free_bytes: u64 = node.drives.iter().map(|d| d.free_bytes).sum();

        let free_ratio = free_bytes as f32 / max_free as f32;
        let combined = W_SCORE * node.mesh_score + W_SPACE * free_ratio;

        candidates.push((node, combined));
    }

    // pick best node
    candidates.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
    let best_node = candidates[0].0;

    // pick best drive on that node: most free space
    let mut drives_sorted = best_node.drives.clone();
    drives_sorted.sort_by(|a, b| b.free_bytes.cmp(&a.free_bytes));

    let best_drive = drives_sorted
        .first()
        .ok_or_else(|| anyhow!("node has zero drives"))?;

    // -------------------------------------------------------
    // Construct chunk metadata
    // -------------------------------------------------------

    Ok(ChunkMeta {
        index: chunk_idx,
        node_id: best_node.node_id.clone(),
        drive_id: best_drive.drive_id.clone(),
        chunk_hash: content_hash.into(),
    })
}

