//! Encrypted snapshot cache at `<cache_dir>/<app_id>/<vault_id>.snapshot`, shared with the npm SDK.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use coffrebox_core::encoding::fill_random;
use coffrebox_core::snapshot::EncryptedSnapshot;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::Error;

const CACHE_FORMAT_VERSION: u32 = 1;

/// File stored on disk (identical to the npm SDK). It only holds the encrypted snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskSnapshotEnvelope {
    pub fetched_at_ms: u64,
    pub snapshot: EncryptedSnapshot,
    pub v: u32,
}

pub(crate) fn current_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Atomic write (temp file + rename), folder 0700 and file 0600 on Unix.
pub(crate) fn write_disk_snapshot(
    app_cache_dir: &Path,
    vault_id: Uuid,
    snapshot: &EncryptedSnapshot,
) -> Result<(), Error> {
    let io = |what: &str, e: std::io::Error| Error::config(format!("cache {what} failed: {e}"));
    std::fs::create_dir_all(app_cache_dir).map_err(|e| io("directory creation", e))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(app_cache_dir, std::fs::Permissions::from_mode(0o700));
    }

    let envelope = DiskSnapshotEnvelope {
        fetched_at_ms: current_epoch_ms(),
        snapshot: snapshot.clone(),
        v: CACHE_FORMAT_VERSION,
    };
    let bytes = serde_json::to_vec(&envelope)
        .map_err(|e| Error::config(format!("cache serialization failed: {e}")))?;

    let mut rand_suffix = [0u8; 6];
    let _ = fill_random(&mut rand_suffix);
    let tmp_path = app_cache_dir.join(format!(
        "{vault_id}.snapshot.tmp.{}",
        hex::encode(rand_suffix)
    ));
    let final_path = app_cache_dir.join(format!("{vault_id}.snapshot"));

    {
        use std::io::Write;
        #[cfg(unix)]
        let mut file = {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&tmp_path)
                .map_err(|e| io("write", e))?
        };
        #[cfg(not(unix))]
        let mut file = std::fs::File::create(&tmp_path).map_err(|e| io("write", e))?;

        file.write_all(&bytes).map_err(|e| io("write", e))?;
        file.sync_all().map_err(|e| io("fsync", e))?;
    }

    std::fs::rename(&tmp_path, &final_path).map_err(|e| io("rename", e))?;
    Ok(())
}

pub(crate) fn read_latest_disk_snapshot(
    app_cache_dir: &Path,
) -> Result<Option<DiskSnapshotEnvelope>, Error> {
    if !app_cache_dir.exists() {
        return Ok(None);
    }
    let entries = std::fs::read_dir(app_cache_dir)
        .map_err(|e| Error::config(format!("cache directory read failed: {e}")))?;

    let mut best: Option<DiskSnapshotEnvelope> = None;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("snapshot") {
            continue;
        }
        let raw = std::fs::read_to_string(&path)
            .map_err(|_| Error::tampered("the .snapshot cache file is unreadable"))?;
        let parsed: DiskSnapshotEnvelope = serde_json::from_str(&raw)
            .map_err(|_| Error::tampered("the .snapshot cache file is corrupted"))?;
        if parsed.v != CACHE_FORMAT_VERSION {
            return Err(Error::tampered(
                "the .snapshot cache file has an unknown format or version",
            ));
        }
        match &best {
            None => best = Some(parsed),
            Some(prev) if parsed.fetched_at_ms >= prev.fetched_at_ms => best = Some(parsed),
            _ => {}
        }
    }
    Ok(best)
}

pub(crate) fn wipe_app_cache(app_cache_dir: &Path) {
    if app_cache_dir.exists() {
        let _ = std::fs::remove_dir_all(app_cache_dir);
    }
}
