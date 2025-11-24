use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::SharedState;

// -------------------------------------------
// Types
// -------------------------------------------

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

#[derive(Debug, Deserialize)]
pub struct PathQuery {
    pub path: String,
}

// -------------------------------------------
// Lookups
// -------------------------------------------

pub async fn lookup(
    State(state): State<SharedState>,
    Query(q): Query<PathQuery>,
) -> Result<Json<FsEntry>, StatusCode> {
    let st = state.lock().unwrap();
    let e = st.fs_entries.get(&q.path).cloned();
    match e {
        Some(x) => Ok(Json(x)),
        None => Err(StatusCode::NOT_FOUND),
    }
}

#[derive(Debug, Serialize)]
pub struct ListResponse {
    pub path: String,
    pub entries: HashMap<String, FsEntry>,
}

pub async fn list(
    State(state): State<SharedState>,
    Query(q): Query<PathQuery>,
) -> Result<Json<ListResponse>, StatusCode> {
    let st = state.lock().unwrap();
    let dir = st.fs_entries.get(&q.path).ok_or(StatusCode::NOT_FOUND)?;

    if dir.node_type != FsNodeType::Directory {
        return Err(StatusCode::BAD_REQUEST);
    }

    let mut map = HashMap::new();
    for child in &dir.children {
        let full = if q.path == "/" {
            format!("/{}", child)
        } else {
            format!("{}/{}", q.path.trim_end_matches('/'), child)
        };
        if let Some(e) = st.fs_entries.get(&full) {
            map.insert(child.clone(), e.clone());
        }
    }

    Ok(Json(ListResponse {
        path: q.path,
        entries: map,
    }))
}

// --------------------------------------------
// CREATE FILE OR DIRECTORY
// --------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateRequest {
    pub path: String,
    pub node_type: FsNodeType,
    pub mode: u32,
}

pub async fn create(
    State(state): State<SharedState>,
    Json(req): Json<CreateRequest>,
) -> Result<Json<FsEntry>, StatusCode> {
    if req.path == "/" {
        return Err(StatusCode::BAD_REQUEST);
    }

    let parent = parent_of(&req.path).map_err(|_| StatusCode::BAD_REQUEST)?;
    let name = name_of(&req.path).map_err(|_| StatusCode::BAD_REQUEST)?;

    let mut st = state.lock().unwrap();

    if !st.fs_entries.contains_key(&parent) {
        return Err(StatusCode::BAD_REQUEST);
    }

    let now = Utc::now().timestamp() as u64;

    let entry = FsEntry {
        path: req.path.clone(),
        node_type: req.node_type,
        size: 0,
        mode: req.mode,
        mtime: now,
        ctime: now,
        chunks: Vec::new(),
        children: Vec::new(),
    };

    st.fs_entries.entry(parent.clone()).and_modify(|p| {
        if !p.children.contains(&name) {
            p.children.push(name.clone());
        }
    });

    st.fs_entries.insert(req.path.clone(), entry.clone());

    Ok(Json(entry))
}

// --------------------------------------------
// UPDATE FILE SIZE
// --------------------------------------------

#[derive(Debug, Deserialize)]
pub struct UpdateSizeRequest {
    pub path: String,
    pub new_size: u64,
}

pub async fn update_size(
    State(state): State<SharedState>,
    Json(req): Json<UpdateSizeRequest>,
) -> Result<StatusCode, StatusCode> {
    let mut st = state.lock().unwrap();
    let e = st
        .fs_entries
        .get_mut(&req.path)
        .ok_or(StatusCode::NOT_FOUND)?;

    if e.node_type != FsNodeType::File {
        return Err(StatusCode::BAD_REQUEST);
    }

    e.size = req.new_size;
    e.mtime = Utc::now().timestamp() as u64;
    Ok(StatusCode::OK)
}

// --------------------------------------------
// UPDATE CHUNK LAYOUT
// --------------------------------------------

#[derive(Debug, Deserialize)]
pub struct UpdateChunksRequest {
    pub path: String,
    pub chunks: Vec<ChunkMeta>,
}

pub async fn update_chunks(
    State(state): State<SharedState>,
    Json(req): Json<UpdateChunksRequest>,
) -> Result<StatusCode, StatusCode> {
    let mut st = state.lock().unwrap();
    let e = st
        .fs_entries
        .get_mut(&req.path)
        .ok_or(StatusCode::NOT_FOUND)?;

    if e.node_type != FsNodeType::File {
        return Err(StatusCode::BAD_REQUEST);
    }

    e.chunks = req.chunks;
    e.mtime = Utc::now().timestamp() as u64;

    Ok(StatusCode::OK)
}

// --------------------------------------------
// DELETE
// --------------------------------------------

pub async fn delete(
    State(state): State<SharedState>,
    Query(q): Query<PathQuery>,
) -> Result<StatusCode, StatusCode> {
    let mut st = state.lock().unwrap();

    if q.path == "/" {
        return Err(StatusCode::BAD_REQUEST);
    }

    let parent = parent_of(&q.path).map_err(|_| StatusCode::BAD_REQUEST)?;
    let name = name_of(&q.path).map_err(|_| StatusCode::BAD_REQUEST)?;

    st.fs_entries
        .entry(parent)
        .and_modify(|p| p.children.retain(|c| c != &name));

    st.fs_entries.remove(&q.path).ok_or(StatusCode::NOT_FOUND)?;

    Ok(StatusCode::NO_CONTENT)
}

// --------------------------------------------
// Helpers
// --------------------------------------------

fn parent_of(path: &str) -> Result<String, ()> {
    if path == "/" {
        return Err(());
    }
    let s = path.trim_end_matches('/');
    let pos = s.rfind('/').ok_or(())?;
    if pos == 0 {
        Ok("/".into())
    } else {
        Ok(s[..pos].to_string())
    }
}

fn name_of(path: &str) -> Result<String, ()> {
    if path == "/" {
        return Err(());
    }
    let s = path.trim_end_matches('/');
    let pos = s.rfind('/').ok_or(())?;
    Ok(s[pos + 1..].to_string())
}
