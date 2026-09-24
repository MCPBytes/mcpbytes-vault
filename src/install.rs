//! `mcpbytes-vault install`: the executable installs itself for the current user. It copies itself
//! to the standard folder (the one `config::default_path` points into), creates a private local-only
//! configuration the first time and keeps it afterwards, and writes the MCP client settings.
use crate::{config::Config, storage};
use serde_json::json;
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

#[derive(Debug)]
pub struct Installed {
    pub binary: PathBuf,
    pub config: PathBuf,
    pub settings: PathBuf,
    /// False when an existing configuration was kept.
    pub created_config: bool,
    /// The configuration's store backend, for the summary.
    pub backend: &'static str,
}

const EXE: &str = if cfg!(windows) { "mcpbytes-vault.exe" } else { "mcpbytes-vault" };

/// The store `install` configures unless asked for private files.
pub fn native_backend() -> &'static str {
    if cfg!(windows) {
        "windows_credential_manager"
    } else if cfg!(target_os = "macos") {
        "macos_keychain"
    } else {
        "linux_secret_service"
    }
}

/// Installs the running executable into `root`. `file_store` only applies when no configuration exists yet.
pub fn install(root: &Path, file_store: bool) -> Result<Installed, String> {
    if !root.is_absolute() {
        return Err("the install folder must be an absolute path".into());
    }
    // A folder set up by the mcpbytes.com installer holds the MCPBytes release (its own layout, and a config this
    // local-only build may not run): never take it over. Say how to update it, or how to install beside it.
    if root.join(".mcpbytes-vault-managed").exists() {
        return Err(managed_folder(root));
    }
    let state = root.join("state");
    private_dir(root)?;
    private_dir(&state)?;
    let config = root.join("config.json");
    let created_config = !config.exists();
    if created_config {
        let store = if file_store {
            let keys = root.join("keys");
            private_dir(&keys)?;
            json!({ "backend": "private_file", "directory": keys })
        } else {
            json!({ "backend": native_backend() })
        };
        let text = serde_json::to_string_pretty(&json!({
            "state_dir": state, "store": store, "label_prefix": "agent-", "mode": "local_only",
        }))
        .map_err(|_| "cannot write the configuration")?;
        // Owner-only from creation (0600, or a protected owner DACL on Windows), never replacing a file.
        let mut file = storage::create_private(&config).map_err(|_| format!("cannot create {}", config.display()))?;
        file.write_all(format!("{text}\n").as_bytes())
            .and_then(|_| file.sync_all())
            .map_err(|_| format!("cannot write {}", config.display()))?;
    }
    // Check the configuration before replacing anything, so a failed install changes nothing that runs.
    let loaded = Config::load(&config).map_err(|code| match code {
        "remote_not_built" => format!("{} uses a remote mode, which this local-only build does not include", config.display()),
        other => format!("{other}: {}", config.display()),
    })?;
    let backend = match loaded.store {
        crate::config::Store::PrivateFile { .. } => "private_file",
        _ => native_backend(),
    };

    let bin = root.join("bin");
    private_dir(&bin)?;
    let binary = bin.join(EXE);
    let current = std::env::current_exe().and_then(|p| p.canonicalize()).map_err(|_| "cannot locate this executable")?;
    if binary.canonicalize().ok().as_ref() != Some(&current) {
        // Copy beside the target, then rename over it: the installed binary is never half-written.
        let staged = bin.join(format!(".{EXE}.{}.new", std::process::id()));
        let copied = fs::copy(&current, &staged).and_then(|_| executable(&staged)).and_then(|_| fs::rename(&staged, &binary));
        if copied.is_err() {
            let _ = fs::remove_file(&staged);
            return Err(format!("cannot replace {}: if an MCP client is running the vault, close it and try again", binary.display()));
        }
    }
    let settings = root.join("mcp-server.json");
    let server = json!({ "mcpServers": { "mcpbytes-vault": { "command": binary, "args": ["--config", config] } } });
    fs::write(&settings, serde_json::to_string_pretty(&server).map_err(|_| "cannot write the settings")? + "\n")
        .map_err(|_| format!("cannot write {}", settings.display()))?;
    Ok(Installed { binary, config, settings, created_config, backend })
}

/// Why a folder of the mcpbytes.com installer is refused, and the two ways forward.
fn managed_folder(root: &Path) -> String {
    let name = root.file_name().map_or("mcpbytes-vault".into(), |n| n.to_string_lossy().into_owned());
    let beside = root.with_file_name(format!("{name}-local"));
    let one_line = if cfg!(windows) {
        format!("$env:MCPBYTES_VAULT_DIR = '{}' before the irm ... | iex line", beside.display())
    } else {
        format!("curl ... | sh -s -- --dir '{}'", beside.display())
    };
    format!(
        "{} holds the MCPBytes release, set up by the mcpbytes.com installer; nothing was changed.\n  \
         To keep that release: update it with its own installer (https://mcpbytes.com/docs/random-bytes).\n  \
         To install this local-only build beside it: mcpbytes-vault install --dir \"{}\"\n  \
         (with the one-line installer: {one_line})",
        root.display(),
        beside.display()
    )
}

/// Creates the folder if needed; never follows a symlink; owner-only on Unix (the journal requires it).
fn private_dir(path: &Path) -> Result<(), String> {
    if fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(format!("{} is a symlink; use a real folder", path.display()));
    }
    fs::create_dir_all(path).map_err(|_| format!("cannot create {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|_| format!("cannot make {} private", path.display()))?;
    }
    Ok(())
}

fn executable(_path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(_path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn installs_once_and_keeps_the_configuration() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("Vault folder");
        let first = install(&dir, true).unwrap();
        assert!(first.created_config && first.binary.is_file());
        assert_eq!(first.backend, "private_file");
        let config: serde_json::Value = serde_json::from_str(&fs::read_to_string(&first.config).unwrap()).unwrap();
        assert_eq!((config["mode"].as_str(), config["label_prefix"].as_str()), (Some("local_only"), Some("agent-")));
        let settings: serde_json::Value = serde_json::from_str(&fs::read_to_string(&first.settings).unwrap()).unwrap();
        assert_eq!(settings["mcpServers"]["mcpbytes-vault"]["args"][0], "--config");
        // A second run keeps the owner's configuration, whatever the options.
        let before = fs::read(&first.config).unwrap();
        let again = install(&dir, false).unwrap();
        assert!(!again.created_config);
        assert_eq!(fs::read(&first.config).unwrap(), before);
        assert_eq!(again.backend, "private_file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            for path in [&dir, &dir.join("state"), &dir.join("keys")] {
                assert_eq!(fs::metadata(path).unwrap().permissions().mode() & 0o777, 0o700);
            }
            assert_eq!(fs::metadata(&first.config).unwrap().mode() & 0o777, 0o600);
        }
    }
    #[test]
    fn refuses_what_it_should_not_touch() {
        assert!(install(Path::new("relative"), false).is_err());
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join(".mcpbytes-vault-managed"), "").unwrap();
        let refusal = install(root.path(), false).unwrap_err();
        assert!(refusal.contains("mcpbytes.com installer") && refusal.contains("nothing was changed"), "{refusal}");
        // It names a folder beside it, and installing there works.
        let beside = root.path().with_file_name(format!("{}-local", root.path().file_name().unwrap().to_string_lossy()));
        assert!(refusal.contains(&beside.display().to_string()), "{refusal}");
        let installed = install(&beside, true);
        let _ = fs::remove_dir_all(&beside);
        assert!(installed.is_ok());
        assert!(!root.path().join("bin").exists(), "the refused folder is untouched");
        #[cfg(not(feature = "remote"))]
        {
            let root = tempfile::tempdir().unwrap();
            let state = root.path().join("state");
            fs::create_dir(&state).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
                fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
            }
            let remote = json!({ "state_dir": state, "store": { "backend": "private_file", "directory": root.path() },
                "label_prefix": "agent-", "mode": "remote_required" });
            let mut file = storage::create_private(&root.path().join("config.json")).unwrap();
            file.write_all(remote.to_string().as_bytes()).unwrap();
            drop(file);
            assert!(install(root.path(), false).unwrap_err().contains("remote mode"));
            assert!(!root.path().join("bin").exists(), "nothing is installed when the configuration is refused");
        }
    }
}
