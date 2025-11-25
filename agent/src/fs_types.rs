use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum FsNodeType {
    File,
    Directory,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ChunkMeta {
    pub index: u64,
    pub node_id: String,
    pub drive_id: String,
    pub chunk_hash: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FsEntry {
    pub path: String,
    pub node_type: FsNodeType,
    pub size: u64,
    pub mode: u32,
    pub mtime: u64,
    pub ctime: u64,
    pub chunks: Vec<ChunkMeta>,
    pub children: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ListResponse {
    pub path: String,
    pub entries: std::collections::HashMap<String, FsEntry>,
}
