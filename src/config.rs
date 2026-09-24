#[cfg(feature = "remote")]
use crate::protocol;
use crate::storage::Destination;
use serde::Deserialize;
use std::{
    io::Read,
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    LocalOnly,
    RemoteRequired,
    RemotePreferred,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pin {
    pub public_key: String,
    pub firmware_digests: Vec<String>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Remote {
    pub url: String,
    pub api_key_env: String,
    pub pins: Vec<Pin>,
}

#[derive(Clone, Deserialize)]
#[serde(tag = "backend", rename_all = "snake_case", deny_unknown_fields)]
pub enum Store {
    PrivateFile { directory: PathBuf },
    WindowsCredentialManager,
    MacosKeychain,
    LinuxSecretService,
}
impl Store {
    pub fn destination(&self) -> Destination {
        match self {
            Self::PrivateFile { directory } => Destination::PrivateFile(directory.clone()),
            Self::WindowsCredentialManager => Destination::WindowsCredentialManager,
            Self::MacosKeychain => Destination::MacosKeychain,
            Self::LinuxSecretService => Destination::LinuxSecretService,
        }
    }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub state_dir: PathBuf,
    pub store: Store,
    pub label_prefix: String,
    pub mode: Mode,
    pub remote: Option<Remote>,
}
impl Config {
    pub fn load(path: &Path) -> Result<Self, &'static str> {
        let meta = std::fs::symlink_metadata(path).map_err(|_| "config_unreadable")?;
        if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > 16384 {
            return Err("invalid_config");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o022 != 0 {
                return Err("unsafe_config_permissions");
            }
        }
        let mut data = Vec::new();
        std::fs::File::open(path)
            .map_err(|_| "config_unreadable")?
            .take(16385)
            .read_to_end(&mut data)
            .map_err(|_| "config_unreadable")?;
        if data.len() > 16384 {
            return Err("invalid_config");
        }
        let config: Self = serde_json::from_slice(&data).map_err(|_| "invalid_config")?;
        config.validate()?;
        Ok(config)
    }
    pub fn validate(&self) -> Result<(), &'static str> {
        if !self.state_dir.is_absolute() || !valid_label(&self.label_prefix) {
            return Err("invalid_config");
        }
        if let Store::PrivateFile { directory } = &self.store {
            if !directory.is_absolute() {
                return Err("invalid_config");
            }
        }
        // A build without the `remote` feature has no network code: remote modes cannot start.
        #[cfg(not(feature = "remote"))]
        if self.mode != Mode::LocalOnly {
            return Err("remote_not_built");
        }
        #[cfg(feature = "remote")]
        if self.mode != Mode::LocalOnly {
            let remote = self.remote.as_ref().ok_or("remote_not_configured")?;
            validate_remote_url(&remote.url)?;
            if remote.api_key_env.is_empty()
                || remote.api_key_env.len() > 100
                || !remote
                    .api_key_env
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_')
                || remote.pins.is_empty()
                || remote.pins.len() > 16
            {
                return Err("invalid_config");
            }
            for pin in &remote.pins {
                let public = protocol::decode::<32>(&pin.public_key).map_err(|_| "invalid_pin")?;
                if public == [0; 32]
                    || pin.firmware_digests.is_empty()
                    || pin.firmware_digests.len() > 16
                {
                    return Err("invalid_pin");
                }
                for digest in &pin.firmware_digests {
                    protocol::decode::<32>(digest).map_err(|_| "invalid_pin")?;
                }
            }
        }
        Ok(())
    }
}
/// Where the MCPBytes installers write the configuration by default, for owner commands run
/// without --config. The MCP server itself always takes --config.
pub fn default_path() -> Option<PathBuf> {
    let var = |name| std::env::var_os(name).filter(|v| !v.is_empty()).map(PathBuf::from);
    #[cfg(windows)]
    let root = var("LOCALAPPDATA").map(|d| d.join("MCPBytes").join("Vault"));
    #[cfg(target_os = "macos")]
    let root = var("HOME").map(|h| h.join("Library/Application Support/MCPBytes/Vault"));
    #[cfg(all(unix, not(target_os = "macos")))]
    let root = var("XDG_DATA_HOME")
        .or_else(|| var("HOME").map(|h| h.join(".local/share")))
        .map(|d| d.join("mcpbytes-vault"));
    #[cfg(not(any(windows, unix)))]
    let root: Option<PathBuf> = None;
    root.map(|r| r.join("config.json"))
}
pub fn valid_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
}
pub fn validate_remote_url(value: &str) -> Result<(), &'static str> {
    // The agent cannot redirect its API credential to an arbitrary endpoint.
    if value != "https://api.mcpbytes.com/v1/sealed-random" {
        return Err("invalid_remote_url");
    }
    Ok(())
}
