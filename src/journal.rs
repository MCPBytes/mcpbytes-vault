//! Metadata-only, fail-closed idempotency. Interrupted operations are never regenerated.
use crate::{
    app::{Input, Saved},
    storage,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub input: Input,
    pub version: u64,
    pub receipt: Option<Saved>,
    pub error: Option<String>,
    /// Unix seconds; absent in records written before 0.2.
    #[serde(default)]
    pub created_at: Option<u64>,
    /// Set by the owner's `delete` command. The record stays so versions are never reused.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub deleted: bool,
}
pub struct Journal {
    directory: PathBuf,
    _lock: File,
}
impl Journal {
    pub fn open(directory: &Path) -> Result<Self, &'static str> {
        let metadata =
            fs::symlink_metadata(directory).map_err(|_| "state_directory_unavailable")?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err("unsafe_state_directory");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.mode() & 0o077 != 0 || metadata.uid() != unsafe { libc::geteuid() } {
                return Err("unsafe_state_directory");
            }
        }
        let lock_path = directory.join(".lock");
        if !lock_path.exists() {
            let _ = storage::create_private(&lock_path);
        }
        let lock_meta = fs::symlink_metadata(&lock_path).map_err(|_| "state_unavailable")?;
        if !lock_meta.is_file() || lock_meta.file_type().is_symlink() {
            return Err("unsafe_state_directory");
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .open(lock_path)
            .map_err(|_| "state_unavailable")?;
        fs2::FileExt::try_lock_exclusive(&lock).map_err(|_| "vault_busy")?;
        Ok(Self {
            directory: directory.to_owned(),
            _lock: lock,
        })
    }
    fn path(&self, operation: &str) -> PathBuf {
        let hash = Sha256::digest(operation.as_bytes());
        let name: String = hash.iter().map(|b| format!("{b:02x}")).collect();
        self.directory.join(format!("op-{name}.json"))
    }
    fn read(path: &Path) -> Result<Record, &'static str> {
        let meta = fs::symlink_metadata(path).map_err(|_| "state_unavailable")?;
        if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > 8192 {
            return Err("invalid_state");
        }
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|_| "state_unavailable")?
            .take(8193)
            .read_to_end(&mut bytes)
            .map_err(|_| "state_unavailable")?;
        if bytes.len() > 8192 {
            return Err("invalid_state");
        }
        serde_json::from_slice(&bytes).map_err(|_| "invalid_state")
    }
    pub fn existing(&self, input: &Input) -> Result<Option<Saved>, &'static str> {
        let path = self.path(&input.operation_id);
        if !path.try_exists().map_err(|_| "state_unavailable")? {
            return Ok(None);
        }
        let record = Self::read(&path)?;
        if record.input != *input {
            return Err("operation_conflict");
        }
        if record.deleted {
            return Err("secret_deleted");
        }
        match record.receipt {
            Some(receipt) => Ok(Some(receipt)),
            None => Err("operation_interrupted_or_failed"),
        }
    }
    /// Every record, sorted by label and version.
    pub fn records(&self) -> Result<Vec<Record>, &'static str> {
        let mut records = Vec::new();
        for entry in fs::read_dir(&self.directory).map_err(|_| "state_unavailable")? {
            let entry = entry.map_err(|_| "state_unavailable")?;
            let name = entry.file_name();
            if name.to_string_lossy().starts_with("op-")
                && name.to_string_lossy().ends_with(".json")
            {
                if records.len() >= 10000 {
                    return Err("state_capacity_reached");
                }
                records.push(Self::read(&entry.path())?);
            }
        }
        records.sort_by(|a, b| (&a.input.label, a.version).cmp(&(&b.input.label, b.version)));
        Ok(records)
    }
    pub fn begin(&self, input: &Input) -> Result<Record, &'static str> {
        let records = self.records()?;
        if records.len() >= 10000 {
            return Err("state_capacity_reached");
        }
        let version = records
            .iter()
            .filter(|record| record.input.label == input.label)
            .map(|record| record.version)
            .max()
            .unwrap_or(0);
        let record = Record {
            input: input.clone(),
            version: version.checked_add(1).ok_or("state_capacity_reached")?,
            receipt: None,
            error: None,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()
                .map(|elapsed| elapsed.as_secs()),
            deleted: false,
        };
        self.write(&record)?;
        Ok(record)
    }
    pub fn write(&self, record: &Record) -> Result<(), &'static str> {
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce).map_err(|_| "entropy_unavailable")?;
        let suffix: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
        let temporary = self.directory.join(format!(".tmp-{suffix}"));
        let mut file = storage::create_private(&temporary).map_err(|_| "state_unavailable")?;
        let bytes = serde_json::to_vec(record).map_err(|_| "invalid_state")?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| "state_unavailable")?;
        drop(file);
        fs::rename(&temporary, self.path(&record.input.operation_id))
            .map_err(|_| "state_unavailable")?;
        #[cfg(unix)]
        File::open(&self.directory)
            .and_then(|f| f.sync_all())
            .map_err(|_| "state_unavailable")?;
        Ok(())
    }
}
