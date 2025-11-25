use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Debug, Clone, Default)]
pub struct DriveInfo {
    pub id: String,
    pub free_bytes: u64,
    pub allocated_bytes: u64,
}

#[derive(Debug, Clone, Default)]
pub struct NodeInfo {
    pub drives: Vec<DriveInfo>,
    pub mesh_score: f32,
}

#[derive(Debug, Default)]
pub struct AgentState {
    pub node_info: HashMap<String, NodeInfo>,
}

pub static AGENT_STATE: Lazy<Mutex<AgentState>> = Lazy::new(|| Mutex::new(AgentState::default()));
