//! Only receipts are returned to agents. No default backend and no weaker-store fallback.
//! `read` and `delete` exist for the owner's terminal commands (main.rs), never for MCP tools.
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::Write,
    path::PathBuf,
};
use zeroize::Zeroizing;

use crate::protocol::MAX_BYTES;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    InvalidDestination,
    UnsafeDirectory,
    UnsupportedPlatform,
    StoreUnavailable,
    EntropyUnavailable,
    AuthenticationFailed,
    NotFound,
}

pub enum Destination {
    PrivateFile(PathBuf),
    WindowsCredentialManager,
    LinuxSecretService,
    MacosKeychain,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Receipt {
    pub reference: String,
    pub bytes: usize,
    pub backend: String,
    /// The native store's own lookup name when it differs from the reference (Windows target name).
    pub store_name: Option<String>,
}
/// Native stores keep every item under this service; the account is `label#version`.
const SERVICE: &str = "mcpbytes-vault";
pub fn entry_name(label: &str, version: u64) -> String {
    format!("{label}#{version}")
}
fn check_name(name: &str) -> Result<(), Error> {
    if name.is_empty()
        || name.len() > 100
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-#".contains(&b))
    {
        return Err(Error::InvalidDestination);
    }
    Ok(())
}
fn private_path(directory: &std::path::Path, name: &str) -> Result<PathBuf, Error> {
    if !directory.is_absolute() {
        return Err(Error::InvalidDestination);
    }
    let metadata = fs::symlink_metadata(directory).map_err(|_| Error::UnsafeDirectory)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(Error::UnsafeDirectory);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.mode() & 0o077 != 0 || metadata.uid() != unsafe { libc::geteuid() } {
            return Err(Error::UnsafeDirectory);
        }
    }
    Ok(directory.join(format!("{name}.key")))
}
fn native_backend(destination: &Destination) -> Result<&'static str, Error> {
    let (backend, supported) = match destination {
        Destination::PrivateFile(_) => return Err(Error::InvalidDestination),
        Destination::WindowsCredentialManager => ("windows_credential_manager", cfg!(target_os = "windows")),
        Destination::LinuxSecretService => ("linux_secret_service", cfg!(target_os = "linux")),
        Destination::MacosKeychain => ("macos_keychain", cfg!(target_os = "macos")),
    };
    if !supported {
        return Err(Error::UnsupportedPlatform);
    }
    Ok(backend)
}
pub fn save(destination: &Destination, name: &str, bytes: &[u8]) -> Result<Receipt, Error> {
    if bytes.is_empty() || bytes.len() > MAX_BYTES {
        return Err(Error::InvalidDestination);
    }
    check_name(name)?;
    match destination {
        Destination::PrivateFile(directory) => {
            let path = private_path(directory, name)?;
            let mut file = create_private(&path)?;
            if file.write_all(bytes).and_then(|_| file.sync_all()).is_err() {
                drop(file);
                let _ = fs::remove_file(&path);
                return Err(Error::StoreUnavailable);
            }
            #[cfg(unix)]
            File::open(directory)
                .and_then(|dir| dir.sync_all())
                .map_err(|_| Error::StoreUnavailable)?;
            Ok(Receipt {
                reference: path.to_string_lossy().into_owned(),
                bytes: bytes.len(),
                backend: "private_file".into(),
                store_name: None,
            })
        }
        native => save_vault(name, bytes, native_backend(native)?),
    }
}
/// The stored secret, for the owner's `reveal` command only.
pub fn read(destination: &Destination, name: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
    check_name(name)?;
    match destination {
        Destination::PrivateFile(directory) => {
            use std::io::Read;
            let path = private_path(directory, name)?;
            let metadata = fs::symlink_metadata(&path).map_err(|error| match error.kind() {
                std::io::ErrorKind::NotFound => Error::NotFound,
                _ => Error::StoreUnavailable,
            })?;
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(Error::UnsafeDirectory);
            }
            let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_BYTES + 1));
            File::open(&path)
                .and_then(|file| file.take(MAX_BYTES as u64 + 1).read_to_end(&mut bytes))
                .map_err(|_| Error::StoreUnavailable)?;
            if bytes.is_empty() || bytes.len() > MAX_BYTES {
                return Err(Error::StoreUnavailable);
            }
            Ok(bytes)
        }
        native => {
            native_backend(native)?;
            read_vault(name)
        }
    }
}
/// Removes a stored secret; `Ok(false)` when it was already gone (e.g. deleted with `cmdkey`).
pub fn delete(destination: &Destination, name: &str) -> Result<bool, Error> {
    check_name(name)?;
    match destination {
        Destination::PrivateFile(directory) => match fs::remove_file(private_path(directory, name)?) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(_) => Err(Error::StoreUnavailable),
        },
        native => {
            native_backend(native)?;
            delete_vault(name)
        }
    }
}

#[cfg(unix)]
pub(crate) fn create_private(path: &std::path::Path) -> Result<File, Error> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| Error::StoreUnavailable)
}

#[cfg(windows)]
pub(crate) fn create_private(path: &std::path::Path) -> Result<File, Error> {
    use std::{
        os::windows::{ffi::OsStrExt, io::FromRawHandle},
        ptr,
    };
    use windows_sys::Win32::{
        Foundation::{LocalFree, GENERIC_WRITE, INVALID_HANDLE_VALUE},
        Security::{
            Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW,
            SECURITY_ATTRIBUTES,
        },
        Storage::FileSystem::{
            CreateFileW, GetVolumeInformationW, GetVolumePathNameW, CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OPEN_REPARSE_POINT,
        },
        System::SystemServices::FILE_PERSISTENT_ACLS,
    };
    // Protected DACL gives the object's owner full access, without inherited ACEs.
    // Admin/kernel compromise and other programs under the same owner remain outside this boundary.
    let sddl: Vec<u16> = "D:P(A;;FA;;;OW)\0".encode_utf16().collect();
    let path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut volume = [0u16; 32768];
    let mut flags = 0u32;
    if unsafe { GetVolumePathNameW(path.as_ptr(), volume.as_mut_ptr(), volume.len() as u32) } == 0
        || unsafe {
            GetVolumeInformationW(
                volume.as_ptr(),
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut flags,
                ptr::null_mut(),
                0,
            )
        } == 0
        || flags & FILE_PERSISTENT_ACLS == 0
    {
        return Err(Error::UnsafeDirectory);
    }
    let mut descriptor = ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut descriptor,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(Error::StoreUnavailable);
    }
    let security = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_WRITE,
            0,
            &security,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    unsafe {
        LocalFree(descriptor);
    }
    if handle == INVALID_HANDLE_VALUE {
        return Err(Error::StoreUnavailable);
    }
    Ok(unsafe { File::from_raw_handle(handle) })
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn create_private(_: &std::path::Path) -> Result<File, Error> {
    Err(Error::UnsupportedPlatform)
}

#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
fn save_vault(id: &str, bytes: &[u8], backend: &'static str) -> Result<Receipt, Error> {
    let entry = keyring::Entry::new(SERVICE, id).map_err(|_| Error::StoreUnavailable)?;
    match entry.get_secret() {
        Err(keyring::Error::NoEntry) => (),
        Ok(existing) => {
            let _existing = Zeroizing::new(existing);
            return Err(Error::StoreUnavailable);
        }
        _ => return Err(Error::StoreUnavailable), // Never replace an existing item.
    }
    entry
        .set_secret(bytes)
        .map_err(|_| Error::StoreUnavailable)?;
    let readback = Zeroizing::new(entry.get_secret().map_err(|_| Error::StoreUnavailable)?);
    if readback.as_slice() != bytes {
        return Err(Error::StoreUnavailable);
    }
    Ok(Receipt {
        reference: format!("vault:{SERVICE}/{id}"),
        bytes: bytes.len(),
        backend: backend.into(),
        // keyring's default Windows target is `{user}.{service}`; the other stores use service/account.
        store_name: cfg!(target_os = "windows").then(|| format!("{id}.{SERVICE}")),
    })
}
#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
fn read_vault(id: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
    let entry = keyring::Entry::new(SERVICE, id).map_err(|_| Error::StoreUnavailable)?;
    match entry.get_secret() {
        Ok(bytes) => Ok(Zeroizing::new(bytes)),
        Err(keyring::Error::NoEntry) => Err(Error::NotFound),
        Err(_) => Err(Error::StoreUnavailable),
    }
}
#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
fn delete_vault(id: &str) -> Result<bool, Error> {
    let entry = keyring::Entry::new(SERVICE, id).map_err(|_| Error::StoreUnavailable)?;
    match entry.delete_credential() {
        Ok(()) => Ok(true),
        Err(keyring::Error::NoEntry) => Ok(false),
        Err(_) => Err(Error::StoreUnavailable),
    }
}

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
fn save_vault(_: &str, _: &[u8], _: &'static str) -> Result<Receipt, Error> {
    Err(Error::UnsupportedPlatform)
}
#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
fn read_vault(_: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
    Err(Error::UnsupportedPlatform)
}
#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
fn delete_vault(_: &str) -> Result<bool, Error> {
    Err(Error::UnsupportedPlatform)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn file_receipt_never_contains_the_secret() {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let secret = b"TEST-ONLY-SECRET-DO-NOT-PRINT-0001";
        let receipt = save(
            &Destination::PrivateFile(directory.path().to_path_buf()),
            "test#1",
            secret,
        )
        .unwrap();
        assert_eq!(fs::read(&receipt.reference).unwrap(), secret);
        assert!(!serde_json::to_string(&receipt)
            .unwrap()
            .contains("TEST-ONLY"));
        let destination = Destination::PrivateFile(directory.path().to_path_buf());
        assert_eq!(read(&destination, "test#1").unwrap().as_slice(), secret);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&receipt.reference)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        assert!(delete(&destination, "test#1").unwrap());
        assert!(!delete(&destination, "test#1").unwrap());
        assert_eq!(read(&destination, "test#1").unwrap_err(), Error::NotFound);
    }
    #[cfg(unix)]
    #[test]
    fn broad_directory_and_symlink_are_rejected() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            save(
                &Destination::PrivateFile(directory.path().to_path_buf()),
                "test#1",
                &[1; 32]
            )
            .unwrap_err(),
            Error::UnsafeDirectory
        );
        let link = directory.path().join("link");
        symlink(directory.path(), &link).unwrap();
        assert_eq!(
            save(&Destination::PrivateFile(link), "test#1", &[1; 32]).unwrap_err(),
            Error::UnsafeDirectory
        );
    }
    #[test]
    fn invalid_destinations_never_fall_back() {
        assert_eq!(
            save(
                &Destination::PrivateFile(PathBuf::from("relative")),
                "test#1",
                &[1; 32]
            )
            .unwrap_err(),
            Error::InvalidDestination
        );
        #[cfg(target_os = "linux")]
        assert_eq!(
            save(&Destination::WindowsCredentialManager, "test#1", &[1; 32]).unwrap_err(),
            Error::UnsupportedPlatform
        );
        #[cfg(target_os = "windows")]
        assert_eq!(
            save(&Destination::LinuxSecretService, "test#1", &[1; 32]).unwrap_err(),
            Error::UnsupportedPlatform
        );
    }
    #[test]
    #[ignore = "Writes and deletes only a unique synthetic test entry in the native credential store"]
    fn native_vault_round_trip() {
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce).unwrap();
        let suffix: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
        let name = format!("selftest-{suffix}#1");
        #[cfg(target_os = "windows")]
        let destination = Destination::WindowsCredentialManager;
        #[cfg(target_os = "linux")]
        let destination = Destination::LinuxSecretService;
        #[cfg(target_os = "macos")]
        let destination = Destination::MacosKeychain;
        let entry = keyring::Entry::new("mcpbytes-vault", &name).unwrap();
        assert!(matches!(entry.get_secret(), Err(keyring::Error::NoEntry)));
        let mut synthetic = [0u8; 64];
        for (i, byte) in synthetic.iter_mut().enumerate() { *byte = if i % 2 == 0 { i as u8 } else { 255 - i as u8 }; }
        let result = save(&destination, &name, &synthetic);
        if result.is_err() {
            // This is an explicitly selected synthetic test, never a production error path.
            if let Err(error) = entry.set_secret(&synthetic) { eprintln!("Native synthetic-test write status: {error}"); }
        }
        let stored = read(&destination, &name).map(|bytes| bytes.to_vec());
        let cleanup = delete(&destination, &name);
        assert!(result.is_ok(), "native vault write failed");
        #[cfg(target_os = "windows")]
        assert_eq!(result.as_ref().unwrap().store_name.as_deref(), Some(format!("{name}.mcpbytes-vault").as_str()));
        assert_eq!(stored.unwrap(), synthetic);
        assert_eq!(cleanup, Ok(true), "synthetic credential cleanup failed");
        assert_eq!(delete(&destination, &name), Ok(false));
        assert!(matches!(entry.get_secret(), Err(keyring::Error::NoEntry)));
    }
}
