
use anyhow::{anyhow, Result};
use fuse3::{
    raw::{
        FileAttr, FileType, ReplyAttr, ReplyEntry, ReplyDirectory,
        ReplyData, ReplyOpen, ReplyWrite,
    },
    AsyncFileSystem, MountOptions,
};
use libc::{EIO, ENOENT, ENOSYS, EISDIR};
use once_cell::sync::OnceCell;
use reqwest::Client;
use serde::Deserialize;
use sha2::{Sha256, Digest};
use tokio::runtime::Runtime;

use std::{
    collections::HashMap,
    ffi::OsStr,
    fs,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

// bring in metadata types
use crate::fs_types::{FsEntry, FsNodeType, ListResponse, ChunkMeta};

// bring in allocation engine + mesh
use crate::allocation::{allocate_chunk, ClusterState, NodeStatus, DriveStatus};
use crate::mesh;

pub static GLOBAL_FS: OnceCell<JunkNasFs> = OnceCell::new();

// ===========================================================
// inode_for()
// ===========================================================

fn inode_for(path: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    path.hash(&mut h);
    let v = h.finish();
    if v == 0 { 1 } else { v }
}

// ===========================================================
// Internal helpers for reading/writing local chunks
// used internally and by mesh RPC
// ===========================================================

pub fn internal_read_local_chunk(path: &str, index: u64) -> Result<Vec<u8>> {
    let fs = GLOBAL_FS.get().expect("FUSE not initialized");

    let rt = Runtime::new()?;
    let entry_opt = rt.block_on(async {
        fs.get_entry(path).await.ok().flatten()
    });

    let entry = entry_opt.ok_or_else(|| anyhow!("metadata not found"))?;

    let meta = entry
        .chunks
        .iter()
        .find(|c| c.index == index)
        .ok_or_else(|| anyhow!("chunk missing"))?;

    if meta.node_id != fs.node_id {
        return Err(anyhow!("chunk not local"));
    }

    let path = fs
        .base_dir
        .join(&meta.drive_id)
        .join(format!("chunk_{}", meta.index));

    Ok(fs::read(path)?)
}

pub fn internal_store_local_chunk(
    path: &str,
    index: u64,
    drive_id: &str,
    data: &[u8],
    hash: &str,
) -> Result<()> {
    let fs = GLOBAL_FS.get().expect("FUSE not initialized");

    let chunk_path = fs
        .base_dir
        .join(drive_id)
        .join(format!("chunk_{}", index));

    fs::create_dir_all(fs.base_dir.join(drive_id))?;
    fs::write(&chunk_path, data)?;
    Ok(())
}

// ===========================================================
// JunkNasFs struct
// ===========================================================

#[derive(Clone)]
pub struct JunkNasFs {
    pub controller_url: String,
    pub node_id: String,
    pub base_dir: PathBuf,
    pub client: Client,
    pub cache: Arc<Mutex<HashMap<String, FsEntry>>>,
}

impl JunkNasFs {
    pub fn new(controller_url: String, node_id: String, base_dir: PathBuf) -> Self {
        JunkNasFs {
            controller_url,
            node_id,
            base_dir,
            client: Client::new(),
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    // ---------------------------------------------------
    // controller interaction
    // ---------------------------------------------------

    async fn fetch_entry(&self, path: &str) -> Result<Option<FsEntry>> {
        let url = format!("{}/fs/lookup?path={}", self.controller_url, path);
        let res = self.client.get(&url).send().await?;
        if res.status().is_success() {
            Ok(Some(res.json::<FsEntry>().await?))
        } else if res.status().as_u16() == 404 {
            Ok(None)
        } else {
            Err(anyhow!("lookup failed"))
        }
    }

    async fn create_file_in_controller(&self, path: &str, mode: u32) -> Result<()> {
        let url = format!("{}/fs/create", self.controller_url);
        let req = serde_json::json!({
            "path": path,
            "node_type": "File",
            "mode": mode,
        });
        let res = self.client.post(&url).json(&req).send().await?;
        if !res.status().is_success() {
            return Err(anyhow!("controller: create failed {}", res.status()));
        }
        Ok(())
    }

    async fn update_file_size(&self, path: &str, size: u64) -> Result<()> {
        let url = format!("{}/fs/update-size", self.controller_url);
        let req = serde_json::json!({
            "path": path,
            "new_size": size,
        });
        let res = self.client.post(&url).json(&req).send().await?;
        if !res.status().is_success() {
            return Err(anyhow!("update-size failed"));
        }
        Ok(())
    }

    async fn update_file_chunks(&self, path: &str, chunks: &Vec<ChunkMeta>) -> Result<()> {
        let url = format!("{}/fs/update-chunks", self.controller_url);
        let req = serde_json::json!({
            "path": path,
            "chunks": chunks,
        });
        let res = self.client.post(&url).json(&req).send().await?;
        if !res.status().is_success() {
            return Err(anyhow!("update-chunks failed"));
        }
        Ok(())
    }

    async fn get_entry(&self, path: &str) -> Result<Option<FsEntry>> {
        {
            let cache = self.cache.lock().unwrap();
            if let Some(e) = cache.get(path) {
                return Ok(Some(e.clone()));
            }
        }

        let fetched = self.fetch_entry(path).await?;
        if let Some(ref e) = fetched {
            self.cache.lock().unwrap().insert(path.into(), e.clone());
        }
        Ok(fetched)
    }

    // ---------------------------------------------------
    // local chunk read
    // ---------------------------------------------------

    fn read_local_chunk(&self, meta: &ChunkMeta) -> Result<Vec<u8>> {
        if meta.node_id != self.node_id {
            return Err(anyhow!("not local"));
        }
        let f = self
            .base_dir
            .join(&meta.drive_id)
            .join(format!("chunk_{}", meta.index));
        Ok(fs::read(f)?)
    }

    // ---------------------------------------------------
    // remote chunk read
    // ---------------------------------------------------

    async fn fetch_remote_chunk(&self, meta: &ChunkMeta, path: &str) -> Result<Vec<u8>> {
        let peers = mesh::get_active_peers();
        let peers = peers.lock().unwrap();

        let peer = peers
            .iter()
            .find(|p| p.node_id == meta.node_id)
            .ok_or_else(|| anyhow!("peer not found"))?
            .clone();

        let transport = mesh::global_transport();
        mesh::fetch_remote_chunk(transport, &peer, path, meta.index)
    }

    // ---------------------------------------------------
    // remote chunk store
    // ---------------------------------------------------

    async fn store_remote_chunk(
        &self,
        meta: &ChunkMeta,
        path: &str,
        data: &[u8],
    ) -> Result<()> {
        let peers = mesh::get_active_peers();
        let peers = peers.lock().unwrap();

        let peer = peers
            .iter()
            .find(|p| p.node_id == meta.node_id)
            .ok_or_else(|| anyhow!("peer not found"))?
            .clone();

        let transport = mesh::global_transport();
        mesh::store_remote_chunk(
            transport,
            &peer,
            path,
            meta.index,
            &meta.drive_id,
            data,
            &meta.chunk_hash,
        )
    }

    // ---------------------------------------------------
    // local chunk store
    // ---------------------------------------------------

    fn store_local_chunk(&self, meta: &ChunkMeta, data: &[u8]) -> Result<()> {
        let dir = self.base_dir.join(&meta.drive_id);
        fs::create_dir_all(&dir)?;
        let f = dir.join(format!("chunk_{}", meta.index));
        fs::write(&f, data)?;
        Ok(())
    }
}

// ===========================================================
// attribute builder
// ===========================================================

fn entry_to_attr(entry: &FsEntry) -> FileAttr {
    let ino = inode_for(&entry.path);
    let ftype = match entry.node_type {
        FsNodeType::Directory => FileType::Directory,
        FsNodeType::File => FileType::RegularFile,
    };
    FileAttr {
        ino,
        size: entry.size,
        blocks: (entry.size + 511) / 512,
        atime: entry.mtime.into(),
        mtime: entry.mtime.into(),
        ctime: entry.ctime.into(),
        crtime: entry.ctime.into(),
        kind: ftype,
        perm: entry.mode as u16,
        uid: 1000,
        gid: 1000,
        rdev: 0,
        nlink: 1,
        flags: 0,
    }
}

// ===========================================================
// FUSE IMPLEMENTATION
// ===========================================================

#[async_trait::async_trait]
impl AsyncFileSystem for JunkNasFs {
    type FileHandle = ();
    type DirHandle = ();

    // ------------------------------------------------------
    // LOOKUP (unchanged)
    // ------------------------------------------------------
    async fn lookup(&self, _parent: u64, name: &OsStr, reply: ReplyEntry) {
        let n = name.to_string_lossy();
        let path = format!("/{}", n);

        match self.get_entry(&path).await {
            Ok(Some(e)) => {
                let attr = entry_to_attr(&e);
                reply.entry(&Duration::from_secs(1), &attr, 0);
            }
            Ok(None) => reply.error(ENOENT),
            Err(_) => reply.error(EIO),
        }
    }

    // ------------------------------------------------------
    // GETATTR (unchanged)
    // ------------------------------------------------------
    async fn getattr(&self, ino: u64, reply: ReplyAttr) {
        if ino == inode_for("/") {
            if let Ok(Some(e)) = self.get_entry("/").await {
                reply.attr(&Duration::from_secs(1), &entry_to_attr(&e));
                return;
            }
        }

        let c = self.cache.lock().unwrap();
        let e = c.values().find(|e| inode_for(&e.path) == ino).cloned();
        drop(c);

        if let Some(e) = e {
            reply.attr(&Duration::from_secs(1), &entry_to_attr(&e));
        } else {
            reply.error(ENOENT);
        }
    }

    // ------------------------------------------------------
    // READDIR (unchanged)
    // ------------------------------------------------------
    async fn readdir(
        &self,
        ino: u64,
        _fh: &Self::DirHandle,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        if offset != 0 {
            reply.ok();
            return;
        }

        let path = if ino == inode_for("/") {
            "/".into()
        } else {
            let c = self.cache.lock().unwrap();
            match c.values().find(|e| inode_for(&e.path) == ino) {
                Some(e) => e.path.clone(),
                None => {
                    reply.error(EIO);
                    return;
                }
            }
        };

        match self.fetch_list(&path).await {
            Ok(Some(list)) => {
                let mut idx = 1;
                for (name, entry) in list.entries {
                    let ino2 = inode_for(&entry.path);
                    let ft = match entry.node_type {
                        FsNodeType::Directory => FileType::Directory,
                        FsNodeType::File => FileType::RegularFile,
                    };
                    reply.add(ino2, idx, ft, name);
                    idx += 1;

                    self.cache.lock().unwrap().insert(entry.path.clone(), entry);
                }
                reply.ok();
            }
            Ok(None) => reply.error(ENOENT),
            Err(_) => reply.error(EIO),
        }
    }

    // ------------------------------------------------------
    // OPEN (we accept O_CREAT via write() logic)
    // ------------------------------------------------------
    async fn open(&self, _ino: u64, _flags: i32, reply: ReplyOpen) {
        reply.opened(0, 0);
    }

    // ------------------------------------------------------
    // READ (unchanged from step 4)
    // ------------------------------------------------------
    async fn read(
        &self,
        ino: u64,
        _fh: &Self::FileHandle,
        offset: i64,
        size: u32,
        reply: ReplyData,
    ) {
        let entry = {
            let c = self.cache.lock().unwrap();
            c.values().find(|e| inode_for(&e.path) == ino).cloned()
        };

        let entry = match entry {
            Some(e) => e,
            None => {
                reply.error(ENOENT);
                return;
            }
        };

        if entry.node_type != FsNodeType::File {
            reply.error(EISDIR);
            return;
        }

        let offset = offset as u64;
        let end = (offset + size as u64).min(entry.size);

        if offset >= entry.size {
            reply.data(&[]);
            return;
        }

        const CHUNK: u64 = 64 * 1024;

        let first = offset / CHUNK;
        let last = (end - 1) / CHUNK;

        let mut out = Vec::new();

        for idx in first..=last {
            let meta = entry.chunks.iter().find(|c| c.index == idx);
            let meta = match meta {
                Some(m) => m,
                None => {
                    reply.error(EIO);
                    return;
                }
            };

            let data = match self.read_local_chunk(meta) {
                Ok(d) => d,
                Err(_) => match self.fetch_remote_chunk(meta, &entry.path).await {
                    Ok(d) => d,
                    Err(_) => {
                        reply.error(EIO);
                        return;
                    }
                },
            };

            let chunk_off = idx * CHUNK;
            let start = if offset > chunk_off {
                (offset - chunk_off) as usize
            } else {
                0
            };

            let end2 = ((end - chunk_off) as usize).min(data.len());

            if start < end2 {
                out.extend_from_slice(&data[start..end2]);
            }
        }

        reply.data(&out);
    }

    // ------------------------------------------------------
    // WRITE — FULL DISTRIBUTED WRITE PIPELINE
    // ------------------------------------------------------
    async fn write(
        &self,
        ino: u64,
        _fh: &Self::FileHandle,
        offset: i64,
        data: Vec<u8>,
        reply: ReplyWrite,
    ) {
        let mut entry = {
            let c = self.cache.lock().unwrap();
            c.values().find(|e| inode_for(&e.path) == ino).cloned()
        };

        // --------------------------------------------------
        // If missing: implicit create
        // --------------------------------------------------
        if entry.is_none() {
            let path = {
                let c = self.cache.lock().unwrap();
                let e = c.values().find(|e| inode_for(&e.path) == ino);
                match e {
                    Some(e) => e.path.clone(),
                    None => {
                        reply.error(ENOENT);
                        return;
                    }
                }
            };
            println!("[write] creating file {}", path);
            self.create_file_in_controller(&path, 0o644).await.unwrap();
            entry = self.get_entry(&path).await.unwrap();
        }

        let mut entry = entry.unwrap();
        let path = entry.path.clone();

        // --------------------------------------------------
        // Write parameters
        // --------------------------------------------------
        let offset = offset as u64;
        let write_len = data.len() as u64;
        let end_pos = offset + write_len;

        const CHUNK: u64 = 64 * 1024;

        let first = offset / CHUNK;
        let last = (end_pos - 1) / CHUNK;

        let mut new_chunks = entry.chunks.clone();

        // cluster state for allocation
        let cluster = get_cluster_state();

        // --------------------------------------------------
        // Write each chunk
        // --------------------------------------------------
        for idx in first..=last {
            let chunk_off = idx * CHUNK;
            let start_off = if offset > chunk_off {
                (offset - chunk_off) as usize
            } else {
                0
            };
            let end_off = ((end_pos - chunk_off) as usize).min(CHUNK as usize);

            // slice of user data for this chunk
            let mut chunk_new = data[(offset + (idx * CHUNK) - offset) as usize..].to_vec();
            if chunk_new.len() > (end_off - start_off) {
                chunk_new.resize(end_off - start_off, 0);
            }

            // load old chunk if needed for partial overwrite
            let mut merged = vec![0u8; end_off];

            if let Some(old_meta) = new_chunks.iter().find(|c| c.index == idx) {
                let old_data = if old_meta.node_id == self.node_id {
                    self.read_local_chunk(old_meta).unwrap_or(vec![0; CHUNK as usize])
                } else {
                    self.fetch_remote_chunk(old_meta, &path).await.unwrap_or(vec![0; CHUNK as usize])
                };

                // overlay old data
                let size = merged.len().min(old_data.len());
                merged[..size].copy_from_slice(&old_data[..size]);
            }

            // overlay new data
            let new_len = chunk_new.len();
            let end_idx = (start_off + new_len).min(merged.len());
            if start_off < end_idx {
                merged[start_off..end_idx].copy_from_slice(&chunk_new[..(end_idx - start_off)]);
            }

            // compute hash
            let mut h = Sha256::new();
            h.update(&merged);
            let hash_hex = format!("{:x}", h.finalize());

            // allocate location if new
            let meta = if let Some(existing) = new_chunks.iter().find(|c| c.index == idx).cloned() {
                ChunkMeta {
                    index: idx,
                    node_id: existing.node_id,
                    drive_id: existing.drive_id,
                    chunk_hash: hash_hex.clone(),
                }
            } else {
                allocate_chunk(
                    &path,
                    idx,
                    &cluster,
                    &hash_hex,
                )?
            };

            // store locally or remote
            if meta.node_id == self.node_id {
                self.store_local_chunk(&meta, &merged).unwrap();
            } else {
                if let Err(e) = self.store_remote_chunk(&meta, &path, &merged).await {
                    reply.error(EIO);
                    return;
                }
            }

            // update chunk list
            if let Some(i) = new_chunks.iter().position(|c| c.index == idx) {
                new_chunks[i] = meta.clone();
            } else {
                new_chunks.push(meta);
            }
        }

        // --------------------------------------------------
        // Update metadata on controller
        // --------------------------------------------------

        // new file size
        let new_size = end_pos.max(entry.size);

        if let Err(_) = self.update_file_size(&path, new_size).await {
            reply.error(EIO);
            return;
        }

        if let Err(_) = self.update_file_chunks(&path, &new_chunks).await {
            reply.error(EIO);
            return;
        }

        // update cache entry
        let mut new_entry = entry.clone();
        new_entry.size = new_size;
        new_entry.chunks = new_chunks;

        self.cache
            .lock()
            .unwrap()
            .insert(path.clone(), new_entry.clone());

        reply.written(write_len as u32);
    }

    async fn mkdir(&self, _p: u64, _n: &OsStr, _m: u32, reply: ReplyEntry) {
        reply.error(ENOSYS)
    }

    async fn unlink(&self, _p: u64, _n: &OsStr, reply: fuse3::raw::ReplyEmpty) {
        reply.error(ENOSYS)
    }
}

// ===========================================================
// RUN FUSE
// ===========================================================

pub async fn run_fuse(mountpoint: PathBuf, controller_url: String) -> Result<()> {
    let node_id = hostname::get()?.to_string_lossy().into_owned();
    let base_dir = dirs::data_local_dir().unwrap().join("junknas/storage");

    let fs = JunkNasFs::new(controller_url, node_id, base_dir);

    GLOBAL_FS.set(fs.clone()).ok();

    let opts = MountOptions::default()
        .mount_point(mountpoint)
        .readonly(false)
        .fs_name("junknas")
        .auto_unmount();

    fuse3::raw::mount(fs, opts).await?;
    Ok(())
}

// ===========================================================
// Helper: gather cluster state for allocation
// ===========================================================

fn get_cluster_state() -> ClusterState {
    use crate::agent_state::*;

    let st = AGENT_STATE
        .get()
        .expect("agent state not initialized")
        .lock()
        .unwrap();

    let mut nodes = Vec::new();

    for (node_id, info) in &st.node_info {
        let drives = info
            .drives
            .iter()
            .map(|d| DriveStatus {
                drive_id: d.id.clone(),
                free_bytes: d.free_bytes,
                allocated_bytes: d.allocated_bytes,
            })
            .collect();

        nodes.push(NodeStatus {
            node_id: node_id.clone(),
            mesh_score: info.mesh_score,
            drives,
        });
    }

    ClusterState { nodes }
}
