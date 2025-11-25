use anyhow::{anyhow, Result};
use bytes::Bytes;
use fuse3::raw::prelude::*;
use fuse3::raw::Session;
use fuse3::Inode;
use fuse3::Result as FuseResult;
use fuse3::{Errno, FileType, MountOptions, Timestamp};
use futures_util::stream;
use libc::{EIO, EISDIR, ENOENT};
use once_cell::sync::OnceCell;
use reqwest::Client;
use sha2::{Digest, Sha256};
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
use crate::fs_types::{ChunkMeta, FsEntry, FsNodeType, ListResponse};

// bring in allocation engine + mesh
use crate::allocation::{allocate_chunk, ClusterState, DriveStatus, NodeStatus};
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
    if v == 0 {
        1
    } else {
        v
    }
}

// ===========================================================
// Internal helpers for reading/writing local chunks
// used internally and by mesh RPC
// ===========================================================

pub fn internal_read_local_chunk(path: &str, index: u64) -> Result<Vec<u8>> {
    let fs = GLOBAL_FS.get().expect("FUSE not initialized");

    let rt = Runtime::new()?;
    let entry_opt = rt.block_on(async { fs.get_entry(path).await.ok().flatten() });

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
    _path: &str,
    index: u64,
    drive_id: &str,
    data: &[u8],
    _hash: &str,
) -> Result<()> {
    let fs = GLOBAL_FS.get().expect("FUSE not initialized");

    let chunk_path = fs.base_dir.join(drive_id).join(format!("chunk_{}", index));

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

    async fn fetch_list(&self, path: &str) -> Result<Option<ListResponse>> {
        let url = format!("{}/fs/list?path={}", self.controller_url, path);
        let res = self.client.get(&url).send().await?;
        if res.status().is_success() {
            Ok(Some(res.json::<ListResponse>().await?))
        } else if res.status().as_u16() == 404 {
            Ok(None)
        } else {
            Err(anyhow!("list failed"))
        }
    }

    async fn create_file_in_controller(&self, path: &str, mode: u32) -> Result<FsEntry> {
        self.create_entry_in_controller(path, FsNodeType::File, mode)
            .await
    }

    async fn create_dir_in_controller(&self, path: &str, mode: u32) -> Result<FsEntry> {
        self.create_entry_in_controller(path, FsNodeType::Directory, mode)
            .await
    }

    async fn create_entry_in_controller(
        &self,
        path: &str,
        node_type: FsNodeType,
        mode: u32,
    ) -> Result<FsEntry> {
        let url = format!("{}/fs/create", self.controller_url);
        let req = serde_json::json!({
            "path": path,
            "node_type": node_type,
            "mode": mode,
        });
        let res = self.client.post(&url).json(&req).send().await?;
        if !res.status().is_success() {
            return Err(anyhow!("controller: create failed {}", res.status()));
        }
        Ok(res.json::<FsEntry>().await?)
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

    async fn delete_entry_in_controller(&self, path: &str) -> Result<()> {
        let url = format!("{}/fs/delete?path={}", self.controller_url, path);
        let res = self.client.delete(&url).send().await?;
        if res.status().is_success() {
            Ok(())
        } else {
            Err(anyhow!("delete failed"))
        }
    }

    fn path_from_ino(&self, ino: u64) -> Option<String> {
        if ino == inode_for("/") {
            return Some("/".into());
        }

        let cache = self.cache.lock().unwrap();
        cache
            .values()
            .find(|e| inode_for(&e.path) == ino)
            .map(|e| e.path.clone())
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
        let peer = mesh::get_active_peers()
            .into_iter()
            .find(|p| p.node_id == meta.node_id)
            .ok_or_else(|| anyhow!("peer not found"))?;

        let transport = mesh::global_transport();
        mesh::fetch_remote_chunk(transport, &peer, path, meta.index)
    }

    // ---------------------------------------------------
    // remote chunk store
    // ---------------------------------------------------

    async fn store_remote_chunk(&self, meta: &ChunkMeta, path: &str, data: &[u8]) -> Result<()> {
        let peer = mesh::get_active_peers()
            .into_iter()
            .find(|p| p.node_id == meta.node_id)
            .ok_or_else(|| anyhow!("peer not found"))?;

        let transport = mesh::global_transport();
        mesh::store_remote_chunk(transport, &peer, path, meta.index, data)
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
        generation: 0,
        size: entry.size,
        blocks: (entry.size + 511) / 512,
        atime: Timestamp::new(entry.mtime as i64, 0),
        mtime: Timestamp::new(entry.mtime as i64, 0),
        ctime: Timestamp::new(entry.ctime as i64, 0),
        #[cfg(target_os = "macos")]
        crtime: Timestamp::new(entry.ctime as i64, 0),
        kind: ftype,
        perm: entry.mode as u16,
        uid: 1000,
        gid: 1000,
        rdev: 0,
        #[cfg(target_os = "macos")]
        flags: 0,
        blksize: 512,
        nlink: 1,
    }
}

// ===========================================================
// FUSE IMPLEMENTATION
// ===========================================================

#[async_trait::async_trait]
impl Filesystem for JunkNasFs {
    type DirEntryStream = stream::Iter<std::vec::IntoIter<FuseResult<DirectoryEntry>>>;
    type DirEntryPlusStream = stream::Iter<std::vec::IntoIter<FuseResult<DirectoryEntryPlus>>>;

    async fn init(&self, _req: Request) -> FuseResult<()> {
        Ok(())
    }

    async fn destroy(&self, _req: Request) {}

    async fn lookup(&self, _req: Request, _parent: Inode, name: &OsStr) -> FuseResult<ReplyEntry> {
        let n = name.to_string_lossy();
        let path = format!("/{}", n);

        match self.get_entry(&path).await {
            Ok(Some(e)) => {
                let attr = entry_to_attr(&e);
                Ok(ReplyEntry {
                    ttl: Duration::from_secs(1),
                    attr,
                    generation: 0,
                })
            }
            Ok(None) => Err(ENOENT.into()),
            Err(_) => Err(EIO.into()),
        }
    }

    async fn getattr(
        &self,
        _req: Request,
        ino: Inode,
        _fh: Option<u64>,
        _flags: u32,
    ) -> FuseResult<ReplyAttr> {
        if ino == inode_for("/") {
            if let Ok(Some(e)) = self.get_entry("/").await {
                return Ok(ReplyAttr {
                    ttl: Duration::from_secs(1),
                    attr: entry_to_attr(&e),
                });
            }
        }

        let c = self.cache.lock().unwrap();
        let e = c.values().find(|e| inode_for(&e.path) == ino).cloned();
        drop(c);

        if let Some(e) = e {
            Ok(ReplyAttr {
                ttl: Duration::from_secs(1),
                attr: entry_to_attr(&e),
            })
        } else {
            Err(ENOENT.into())
        }
    }

    async fn readdir(
        &self,
        _req: Request,
        ino: Inode,
        _fh: u64,
        offset: i64,
    ) -> FuseResult<ReplyDirectory<Self::DirEntryStream>> {
        if offset != 0 {
            return Ok(ReplyDirectory {
                entries: stream::iter(Vec::new().into_iter()),
            });
        }

        let path = self.path_from_ino(ino).ok_or_else(|| Errno::from(EIO))?;

        match self.fetch_list(&path).await {
            Ok(Some(list)) => {
                let mut idx = 1;
                let mut entries = Vec::new();
                for (name, entry) in list.entries {
                    let ino2 = inode_for(&entry.path);
                    let ft = match entry.node_type {
                        FsNodeType::Directory => FileType::Directory,
                        FsNodeType::File => FileType::RegularFile,
                    };
                    entries.push(Ok(DirectoryEntry {
                        inode: ino2,
                        kind: ft,
                        name: name.into(),
                        offset: idx,
                    }));
                    idx += 1;

                    self.cache.lock().unwrap().insert(entry.path.clone(), entry);
                }

                Ok(ReplyDirectory {
                    entries: stream::iter(entries.into_iter()),
                })
            }
            Ok(None) => Err(ENOENT.into()),
            Err(_) => Err(EIO.into()),
        }
    }

    async fn open(&self, _req: Request, _ino: Inode, _flags: u32) -> FuseResult<ReplyOpen> {
        Ok(ReplyOpen { fh: 0, flags: 0 })
    }

    async fn read(
        &self,
        _req: Request,
        ino: Inode,
        _fh: u64,
        offset: u64,
        size: u32,
    ) -> FuseResult<ReplyData> {
        let entry = {
            let c = self.cache.lock().unwrap();
            c.values().find(|e| inode_for(&e.path) == ino).cloned()
        };

        let entry = match entry {
            Some(e) => e,
            None => return Err(ENOENT.into()),
        };

        if entry.node_type != FsNodeType::File {
            return Err(EISDIR.into());
        }

        let end = (offset + size as u64).min(entry.size);

        if offset >= entry.size {
            return Ok(ReplyData::from(Bytes::new()));
        }

        const CHUNK: u64 = 64 * 1024;

        let first = offset / CHUNK;
        let last = (end - 1) / CHUNK;

        let mut out = Vec::new();

        for idx in first..=last {
            let meta = match entry.chunks.iter().find(|c| c.index == idx) {
                Some(m) => m,
                None => return Err(EIO.into()),
            };

            let buf = if meta.node_id == self.node_id {
                self.read_local_chunk(meta)
            } else {
                self.fetch_remote_chunk(meta, &entry.path).await
            };

            let mut data = match buf {
                Ok(d) => d,
                Err(_) => return Err(EIO.into()),
            };

            // truncate to requested range
            let chunk_start = idx * CHUNK;
            let chunk_end = chunk_start + CHUNK;
            let start = offset.max(chunk_start);
            let end = end.min(chunk_end);
            let start_off = (start - chunk_start) as usize;
            let len = (end - start) as usize;
            data = data[start_off..start_off + len].to_vec();

            out.extend_from_slice(&data);
        }

        Ok(ReplyData::from(Bytes::from(out)))
    }

    async fn write(
        &self,
        _req: Request,
        ino: Inode,
        _fh: u64,
        offset: u64,
        data: &[u8],
        _flags: u32,
    ) -> FuseResult<ReplyWrite> {
        let path = self.path_from_ino(ino).ok_or_else(|| Errno::from(ENOENT))?;

        // fetch metadata
        let entry = match self.get_entry(&path).await {
            Ok(Some(e)) => e,
            Ok(None) => return Err(ENOENT.into()),
            Err(_) => return Err(EIO.into()),
        };

        let cluster = get_cluster_state();

        let mut new_chunks = entry.chunks.clone();

        let end_pos = offset + data.len() as u64;

        const CHUNK: u64 = 64 * 1024;

        // --------------------------------------------------
        // For each chunk, merge old + new data
        // --------------------------------------------------
        let mut write_len = 0;

        for idx in offset / CHUNK..=(end_pos - 1) / CHUNK {
            // existing chunk data (or zeroes)
            let chunk_start = idx * CHUNK;
            let chunk_end = chunk_start + CHUNK;

            let start = offset.max(chunk_start);
            let end = end_pos.min(chunk_end);

            // portion of new data that belongs to this chunk
            let start_off = (start - offset) as usize;
            let end_off = (end - offset) as usize;

            let chunk_new = &data[start_off..end_off];

            write_len += chunk_new.len();

            // start with zeros
            let mut merged = vec![0u8; CHUNK as usize];

            if let Some(old_meta) = new_chunks.iter().find(|c| c.index == idx) {
                let old_data = if old_meta.node_id == self.node_id {
                    self.read_local_chunk(old_meta)
                        .unwrap_or(vec![0; CHUNK as usize])
                } else {
                    self.fetch_remote_chunk(old_meta, &path)
                        .await
                        .unwrap_or(vec![0; CHUNK as usize])
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
                allocate_chunk(&path, idx, &cluster, &hash_hex).map_err(|_| Errno::from(EIO))?
            };

            // store locally or remote
            if meta.node_id == self.node_id {
                self.store_local_chunk(&meta, &merged).unwrap();
            } else if let Err(_) = self.store_remote_chunk(&meta, &path, &merged).await {
                return Err(EIO.into());
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

        self.update_file_size(&path, new_size)
            .await
            .map_err(|_| EIO)?;
        self.update_file_chunks(&path, &new_chunks)
            .await
            .map_err(|_| EIO)?;

        // update cache entry
        let mut new_entry = entry.clone();
        new_entry.size = new_size;
        new_entry.chunks = new_chunks;

        self.cache
            .lock()
            .unwrap()
            .insert(path.clone(), new_entry.clone());

        Ok(ReplyWrite {
            written: write_len as u32,
        })
    }

    async fn mkdir(
        &self,
        _req: Request,
        parent: Inode,
        name: &OsStr,
        mode: u32,
        _umask: u32,
    ) -> FuseResult<ReplyEntry> {
        let parent_path = self
            .path_from_ino(parent)
            .ok_or_else(|| Errno::from(ENOENT))?;

        let child = name.to_string_lossy();
        let path = if parent_path == "/" {
            format!("/{}", child)
        } else {
            format!("{}/{}", parent_path.trim_end_matches('/'), child)
        };

        match self.create_dir_in_controller(&path, mode).await {
            Ok(entry) => {
                let attr = entry_to_attr(&entry);
                self.cache.lock().unwrap().insert(path, entry);
                Ok(ReplyEntry {
                    ttl: Duration::from_secs(1),
                    attr,
                    generation: 0,
                })
            }
            Err(_) => Err(EIO.into()),
        }
    }

    async fn unlink(&self, _req: Request, parent: Inode, name: &OsStr) -> FuseResult<()> {
        let parent_path = self
            .path_from_ino(parent)
            .ok_or_else(|| Errno::from(ENOENT))?;

        let child = name.to_string_lossy();
        let path = if parent_path == "/" {
            format!("/{}", child)
        } else {
            format!("{}/{}", parent_path.trim_end_matches('/'), child)
        };

        self.delete_entry_in_controller(&path)
            .await
            .map_err(|_| EIO)?;
        self.cache.lock().unwrap().remove(&path);

        Ok(())
    }
}
// ===========================================================
// RUN FUSE
// ===========================================================

pub async fn run_fuse(mountpoint: PathBuf, controller_url: String) -> Result<()> {
    let node_id = hostname::get()?.to_string_lossy().into_owned();
    let base_dir = dirs::data_local_dir().unwrap().join("junknas/storage");

    let fs = JunkNasFs::new(controller_url, node_id, base_dir);

    if let Err(e) = fs.create_file_in_controller("/.junknas_alive", 0o644).await {
        eprintln!("[fuse] unable to ensure controller keepalive file: {e:?}");
    }

    GLOBAL_FS.set(fs.clone()).ok();

    let mut opts = MountOptions::default();
    opts.fs_name("junknas");
    let session = Session::new(opts);

    session.mount(fs, mountpoint).await?;
    Ok(())
}

// ===========================================================
// Helper: gather cluster state for allocation
// ===========================================================

fn get_cluster_state() -> ClusterState {
    use crate::agent_state::*;

    let st = AGENT_STATE.lock().unwrap();

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
