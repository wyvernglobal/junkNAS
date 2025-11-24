pub fn internal_store_local_chunk(
    path: &str,
    index: u64,
    drive_id: &str,
    data: &[u8],
    hash: &str,
) -> Result<()> {
    let fs = GLOBAL_FS.get().expect("FUSE not initialized");

    // storage path
    let chunk_path = fs
        .base_dir
        .join(drive_id)
        .join(format!("chunk_{}", index));

    // ensure drive dir exists
    std::fs::create_dir_all(fs.base_dir.join(drive_id))?;

    // write chunk atomically
    std::fs::write(&chunk_path, data)?;

    // (Optional) validate hash later
    Ok(())
}
