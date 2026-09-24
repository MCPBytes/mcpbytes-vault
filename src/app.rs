use crate::{
    config::{self, Config, Mode, Store},
    journal::{Journal, Record},
    protocol, storage,
};
#[cfg(feature = "remote")]
use crate::{protocol::Pending, remote};
use rmcp::schemars;
use serde::{Deserialize, Serialize};
#[cfg(feature = "remote")]
use std::sync::Arc;
use zeroize::Zeroizing;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Input {
    /// Secret label within the configured allowed prefix. Use a new operation ID to rotate it.
    pub label: String,
    /// Bytes to save, from 1 to 64. Bytes are never returned to the agent.
    #[schemars(range(min = 1, max = 64))]
    pub n: u8,
    /// Stable caller-chosen ID. Reuse for retries of this operation; change only for a new secret.
    pub operation_id: String,
}
#[derive(Clone, Debug, Deserialize, Serialize, schemars::JsonSchema)]
pub struct Saved {
    pub reference: String,
    pub label: String,
    pub version: u64,
    pub bytes: usize,
    pub backend: String,
    pub entropy_mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback_reason: Option<String>,
    /// The native store's lookup name when it differs from the reference (the Windows target name).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store_name: Option<String>,
    /// How the bytes are stored: `raw` (unencoded). Absent in receipts written before 0.2.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
}
/// One journal entry as `list` shows it: metadata only, never the secret.
#[derive(Clone, Debug, Serialize, schemars::JsonSchema)]
pub struct Listed {
    pub label: String,
    pub version: u64,
    pub bytes: u8,
    /// `saved`, `deleted` or `incomplete` (interrupted or failed; the owner should inspect it).
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entropy_mode: Option<String>,
    /// Unix seconds; absent for secrets created before 0.2.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
}
#[derive(Clone, Debug, Serialize, schemars::JsonSchema)]
pub struct Listing {
    pub label_prefix: String,
    pub secrets: Vec<Listed>,
}
/// Errors caused by the tool arguments (MCP invalid params); every other code is an internal error.
pub const ARGUMENT_ERRORS: [&str; 4] = ["invalid_label", "label_prefix_mismatch", "invalid_size", "invalid_operation_id"];

pub struct Vault {
    config: Config,
    #[cfg(feature = "remote")]
    remote: Option<Arc<dyn remote::Client>>,
}
impl Vault {
    pub fn label_prefix(&self) -> &str {
        &self.config.label_prefix
    }
    fn backend_name(&self) -> &'static str {
        match self.config.store {
            Store::PrivateFile { .. } => "a private file",
            Store::WindowsCredentialManager => "Windows Credential Manager",
            Store::MacosKeychain => "the macOS Keychain",
            Store::LinuxSecretService => "the Linux Secret Service",
        }
    }
    fn key_env(&self) -> &str {
        self.config.remote.as_ref().map_or("MCPBYTES_API_KEY", |r| r.api_key_env.as_str())
    }
    /// The get_random_bytes description, written from the owner's configuration so an agent
    /// knows the prefix, the cost and the failure behaviour before its first call.
    pub fn tool_description(&self) -> String {
        let mode = match self.config.mode {
            Mode::LocalOnly => "local_only: OS randomness only; no network call and no cost.".to_string(),
            Mode::RemoteRequired => format!(
                "remote_required: each new secret runs one paid MCPBytes job (price in the MCPBytes catalog) and needs the {} environment variable; the call fails when the service is unavailable.",
                self.key_env()
            ),
            Mode::RemotePreferred => format!(
                "remote_preferred: each new secret runs one paid MCPBytes job (price in the MCPBytes catalog) and needs the {} environment variable; on timeout or unavailability it saves OS-only randomness and reports fallback_reason.",
                self.key_env()
            ),
        };
        format!(
            "Generate 1–64 random bytes and save them in {}. Returns a reference, never the bytes. Labels must start with \"{}\" and use only letters, digits, _ or - (at most 64 characters). Reuse operation_id to retry safely (no new secret, no new charge); a new operation_id creates the next version of the label. Mode {mode}",
            self.backend_name(),
            self.config.label_prefix
        )
    }
    pub fn instructions(&self) -> String {
        format!(
            "Local vault: tools return references and metadata only. Never read, print or export a stored secret into the conversation; the owner reveals secrets with `mcpbytes-vault reveal` in their own terminal. Labels must start with \"{}\". Reuse operation_id after an uncertain reply. If entropy_mode is local_only, the secret has no remote contribution.",
            self.config.label_prefix
        )
    }
    /// What an error code means and what to do about it, for the MCP error message.
    pub fn hint(&self, code: &str) -> String {
        match code {
            "label_prefix_mismatch" => format!("label must start with \"{}\"", self.config.label_prefix),
            "invalid_label" => "label must be 1–64 letters, digits, _ or -".into(),
            "invalid_size" => "n must be from 1 to 64".into(),
            "invalid_operation_id" => "operation_id must be 1–128 letters, digits, _ or -".into(),
            "operation_conflict" => "this operation_id was already used with a different label or n; use a new operation_id".into(),
            "operation_interrupted_or_failed" => "an earlier attempt with this operation_id did not complete; the owner can inspect it with `mcpbytes-vault list`. Use a new operation_id for a new secret".into(),
            "operation_policy_conflict" => "this operation completed without a remote contribution, which the current policy requires; use a new operation_id".into(),
            "secret_deleted" => "the owner deleted the secret this operation_id created; use a new operation_id".into(),
            "vault_busy" => "another vault operation is running; retry with the same operation_id".into(),
            "remote_timeout" | "remote_unavailable" | "remote_transport_failed" => "the MCPBytes service could not be reached; retry later with the same operation_id".into(),
            "remote_configuration_error" => format!("the vault process has no valid API key in {}; the owner must set it in the MCP client's environment", self.key_env()),
            "remote_authentication_failed" => format!("the MCPBytes API rejected the key in {} or the response failed authentication; tell the owner", self.key_env()),
            "untrusted_device" | "unapproved_firmware_metadata" | "invalid_remote_response" => "the service response did not match the pinned device or firmware; do not retry, tell the owner".into(),
            "storage_failed" => format!("{} refused the write (locked or unavailable)", self.backend_name()),
            "entropy_unavailable" => "the OS random generator failed".into(),
            "secret_not_found" => "no saved secret with that label and version; run `mcpbytes-vault list`".into(),
            "remote_not_built" => "this build is local-only: set mode to local_only, or build the vault with --features remote".into(),
            "secret_missing_from_store" => format!("the vault's records list this secret but {} no longer holds it (deleted outside the vault?); run `mcpbytes-vault delete` to update the records", self.backend_name()),
            _ => "see the vault README".into(),
        }
    }
    pub fn new(config: Config) -> Result<Self, &'static str> {
        config.validate()?;
        #[cfg(feature = "remote")]
        let remote = if config.mode == Mode::LocalOnly {
            None
        } else {
            Some(Arc::new(
                remote::HttpsClient::new(config.remote.as_ref().ok_or("remote_not_configured")?)
                    .map_err(|_| "remote_configuration_error")?,
            ) as Arc<dyn remote::Client>)
        };
        Ok(Self {
            config,
            #[cfg(feature = "remote")]
            remote,
        })
    }
    pub async fn generate(&self, input: Input) -> Result<Saved, &'static str> {
        if !config::valid_label(&input.label) {
            return Err("invalid_label");
        }
        if !input.label.starts_with(&self.config.label_prefix) {
            return Err("label_prefix_mismatch");
        }
        if input.n == 0 || input.n as usize > protocol::MAX_BYTES {
            return Err("invalid_size");
        }
        if input.operation_id.is_empty()
            || input.operation_id.len() > 128
            || !input
                .operation_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        {
            return Err("invalid_operation_id");
        }
        // Kept across generation to serialize processes and prevent duplicate logical operations.
        let journal = Journal::open(&self.config.state_dir)?;
        if let Some(receipt) = journal.existing(&input)? {
            // Tightening owner policy must not make an earlier local-only result satisfy it.
            // Keep the original key immutable; a new operation is required under the new policy.
            if self.config.mode == Mode::RemoteRequired && receipt.entropy_mode != "mixed" {
                return Err("operation_policy_conflict");
            }
            return Ok(receipt);
        }
        let mut record = journal.begin(&input)?;
        let context = serde_json::to_vec(&(
            "mcpbytes-vault-v1",
            &input.label,
            record.version,
            &input.operation_id,
        ))
        .map_err(|_| "invalid_request")?;
        let result = self.generate_inner(&input, record.version, &context).await;
        match &result {
            Ok(receipt) => record.receipt = Some(receipt.clone()),
            Err(code) => record.error = Some((*code).into()),
        }
        journal.write(&record).map_err(|_| "completion_ambiguous")?;
        result
    }
    async fn generate_inner(
        &self,
        input: &Input,
        version: u64,
        context: &[u8],
    ) -> Result<Saved, &'static str> {
        let (bytes, entropy_mode, fallback_reason) =
            self.material(input.n as usize, context).await?;
        let destination = self.config.store.destination();
        let name = storage::entry_name(&input.label, version);
        let receipt =
            tokio::task::spawn_blocking(move || storage::save(&destination, &name, &bytes))
                .await
                .map_err(|_| "storage_failed")?
                .map_err(|_| "storage_failed")?;
        Ok(Saved {
            reference: receipt.reference,
            label: input.label.clone(),
            version,
            bytes: receipt.bytes,
            backend: receipt.backend,
            entropy_mode: entropy_mode.into(),
            fallback_reason,
            store_name: receipt.store_name,
            format: Some("raw".into()),
        })
    }
    /// Metadata of every secret the journal knows, including deleted and incomplete ones.
    pub fn list(&self) -> Result<Listing, &'static str> {
        let secrets = Journal::open(&self.config.state_dir)?
            .records()?
            .into_iter()
            .map(|record| Listed {
                label: record.input.label,
                version: record.version,
                bytes: record.input.n,
                status: match (record.deleted, &record.receipt) {
                    (true, _) => "deleted",
                    (false, Some(_)) => "saved",
                    (false, None) => "incomplete",
                },
                entropy_mode: record.receipt.as_ref().map(|r| r.entropy_mode.clone()),
                created_at: record.created_at,
                reference: record.receipt.map(|r| r.reference),
            })
            .collect();
        Ok(Listing {
            label_prefix: self.config.label_prefix.clone(),
            secrets,
        })
    }
    /// The record for `label`: the given version, or the newest saved one.
    fn find(journal: &Journal, label: &str, version: Option<u64>) -> Result<Record, &'static str> {
        let mut matching: Vec<Record> = journal
            .records()?
            .into_iter()
            .filter(|r| r.input.label == label && version.is_none_or(|v| r.version == v))
            .collect();
        if version.is_none() {
            matching.retain(|r| !r.deleted && r.receipt.is_some());
        }
        let record = matching.pop().ok_or("secret_not_found")?;
        if record.deleted {
            return Err("secret_deleted");
        }
        Ok(record)
    }
    /// The stored bytes, for the owner's terminal command only (never an MCP tool).
    pub fn reveal(&self, label: &str, version: Option<u64>) -> Result<(Record, Zeroizing<Vec<u8>>), &'static str> {
        let journal = Journal::open(&self.config.state_dir)?;
        let record = Self::find(&journal, label, version)?;
        if record.receipt.is_none() {
            return Err("operation_interrupted_or_failed");
        }
        let name = storage::entry_name(label, record.version);
        match storage::read(&self.config.store.destination(), &name) {
            Ok(bytes) => Ok((record, bytes)),
            Err(storage::Error::NotFound) => Err("secret_missing_from_store"),
            Err(_) => Err("storage_failed"),
        }
    }
    /// Deletes one version from the store and marks it deleted in the journal, so its
    /// operation_id is not answered with a receipt for a secret that is gone.
    /// Returns whether the store still held it (false after an out-of-band delete).
    pub fn delete(&self, label: &str, version: u64) -> Result<(Record, bool), &'static str> {
        let journal = Journal::open(&self.config.state_dir)?;
        let mut record = Self::find(&journal, label, Some(version))?;
        let name = storage::entry_name(label, version);
        let existed = storage::delete(&self.config.store.destination(), &name).map_err(|_| "storage_failed")?;
        record.deleted = true;
        journal.write(&record)?;
        Ok((record, existed))
    }
    async fn material(
        &self,
        n: usize,
        context: &[u8],
    ) -> Result<(Zeroizing<Vec<u8>>, &'static str, Option<String>), &'static str> {
        if self.config.mode == Mode::LocalOnly {
            return Ok((
                protocol::local_only(n, context).map_err(|_| "entropy_unavailable")?,
                "local_only",
                None,
            ));
        }
        #[cfg(feature = "remote")]
        return self.remote_material(n, context).await;
        // Unreachable in practice: config.validate() refuses remote modes in a build without the feature.
        #[cfg(not(feature = "remote"))]
        Err("remote_not_built")
    }
    /// The MCPBytes contribution: a sealed request, the pinned device's encrypted reply, mixed with OS randomness.
    #[cfg(feature = "remote")]
    async fn remote_material(
        &self,
        n: usize,
        context: &[u8],
    ) -> Result<(Zeroizing<Vec<u8>>, &'static str, Option<String>), &'static str> {
        let pending = Pending::new(n).map_err(|_| "entropy_unavailable")?;
        let request = pending.request();
        let client = self.remote.as_ref().ok_or("remote_not_configured")?;
        let result = match tokio::time::timeout(remote::DEADLINE, client.fetch(&request)).await {
            Ok(value) => value,
            Err(_) => Err(remote::Error::Timeout),
        };
        let envelope = match result {
            Ok(envelope) => envelope,
            Err(error) if self.config.mode == Mode::RemotePreferred && error.allows_fallback() => {
                return Ok((
                    protocol::local_only(n, context).map_err(|_| "entropy_unavailable")?,
                    "local_only",
                    Some(error.code().into()),
                ));
            }
            Err(error) => return Err(error.code()),
        };
        let config = self.config.remote.as_ref().ok_or("remote_not_configured")?;
        let mut accepted = None;
        for pin in &config.pins {
            let key = protocol::decode::<32>(&pin.public_key).map_err(|_| "invalid_pin")?;
            if protocol::encode(&mcpbytes_sealed_core::key_id(&key)) == envelope.device_pk_id {
                if !pin.firmware_digests.contains(&envelope.fw_digest) {
                    return Err("unapproved_firmware_metadata");
                }
                accepted = Some(key);
                break;
            }
        }
        let pin = accepted.ok_or("untrusted_device")?;
        let bytes = pending
            .open_and_mix(&envelope, &pin, context)
            .map_err(|_| "remote_authentication_failed")?;
        Ok((bytes, "mixed", None))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    pub(super) fn fixture(mode: Mode) -> (tempfile::TempDir, Config) {
        let root = tempfile::tempdir().unwrap();
        for name in ["state", "keys"] {
            let path = root.path().join(name);
            std::fs::create_dir(&path).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
        }
        let config = Config {
            state_dir: root.path().join("state"),
            store: config::Store::PrivateFile {
                directory: root.path().join("keys"),
            },
            label_prefix: "test-".into(),
            mode,
            remote: remote_config(),
        };
        (root, config)
    }
    #[cfg(feature = "remote")]
    fn remote_config() -> Option<config::Remote> {
        let (_, public) = mcpbytes_sealed_core::keypair(&[2; 32]);
        Some(config::Remote {
            url: "https://api.mcpbytes.com/v1/sealed-random".into(),
            api_key_env: "MCPBYTES_API_KEY".into(),
            pins: vec![config::Pin {
                public_key: protocol::encode(&public),
                firmware_digests: vec![protocol::encode(&[3; 32])],
            }],
        })
    }
    #[cfg(not(feature = "remote"))]
    fn remote_config() -> Option<config::Remote> {
        None
    }
    /// How a leaked secret would look in JSON: unpadded base64url, the encoding the vault uses elsewhere.
    fn b64(bytes: &[u8]) -> String {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }
    fn input() -> Input {
        Input {
            label: "test-key".into(),
            n: 32,
            operation_id: "same-logical-operation".into(),
        }
    }
    #[cfg(feature = "remote")]
    struct Failed(remote::Error);
    #[cfg(feature = "remote")]
    struct Sealed {
        tamper: bool,
    }
    #[cfg(feature = "remote")]
    impl remote::Client for Sealed {
        fn fetch<'a>(
            &'a self,
            request: &'a protocol::WireRequest,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<protocol::WireEnvelope, remote::Error>>
                    + Send
                    + 'a,
            >,
        > {
            Box::pin(async move {
                let (sender, _) = mcpbytes_sealed_core::keypair(&[2; 32]);
                let request = request.to_core().unwrap();
                let mut material = vec![0u8; request.n as usize];
                let mut envelope = mcpbytes_sealed_core::seal(
                    &request,
                    [3; 32],
                    &sender,
                    &mut material,
                    &mut mcpbytes_sealed_core::rand_core::UnwrapErr(getrandom::SysRng),
                )
                .unwrap();
                assert!(material.iter().all(|b| *b == 0));
                if self.tamper {
                    envelope.ciphertext[0] ^= 1;
                }
                Ok(protocol::WireEnvelope::from(&envelope))
            })
        }
    }
    #[cfg(feature = "remote")]
    impl remote::Client for Failed {
        fn fetch<'a>(
            &'a self,
            _: &'a protocol::WireRequest,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<protocol::WireEnvelope, remote::Error>>
                    + Send
                    + 'a,
            >,
        > {
            Box::pin(async move { Err(self.0) })
        }
    }
    #[tokio::test]
    async fn retries_return_the_same_reference_and_rotation_does_not_overwrite() {
        let (root, config) = fixture(Mode::LocalOnly);
        let vault = Vault::new(config).unwrap();
        let first = vault.generate(input()).await.unwrap();
        let repeat = vault.generate(input()).await.unwrap();
        assert_eq!(first.reference, repeat.reference);
        let mut next = input();
        next.operation_id = "rotate".into();
        let second = vault.generate(next).await.unwrap();
        assert_eq!(second.version, first.version + 1);
        assert_ne!(second.reference, first.reference);
        assert_eq!(
            std::fs::read_dir(root.path().join("keys")).unwrap().count(),
            2
        );
        let bytes = std::fs::read(&first.reference).unwrap();
        let response = serde_json::to_string(&first).unwrap();
        assert!(!response.contains(&b64(&bytes)));
        for item in std::fs::read_dir(root.path().join("state")).unwrap() {
            let data = std::fs::read(item.unwrap().path()).unwrap();
            assert!(!String::from_utf8_lossy(&data).contains(&b64(&bytes)));
        }
    }
    #[cfg(feature = "remote")]
    #[tokio::test]
    async fn fallback_is_explicit_and_never_masks_bad_authentication() {
        for (mode, error, success) in [
            (Mode::RemoteRequired, remote::Error::Timeout, false),
            (Mode::RemotePreferred, remote::Error::Timeout, true),
            (Mode::RemotePreferred, remote::Error::Authentication, false),
            (Mode::RemotePreferred, remote::Error::InvalidResponse, false),
        ] {
            let (_root, config) = fixture(mode);
            let vault = Vault {
                config,
                remote: Some(Arc::new(Failed(error))),
            };
            let result = vault.generate(input()).await;
            assert_eq!(result.is_ok(), success);
            if let Ok(saved) = result {
                assert_eq!(saved.entropy_mode, "local_only");
                assert_eq!(saved.fallback_reason.as_deref(), Some("remote_timeout"));
            }
        }
    }
    #[cfg(feature = "remote")]
    #[tokio::test]
    async fn requiring_remote_rejects_an_earlier_local_only_completion() {
        let (root, config) = fixture(Mode::LocalOnly);
        let local = Vault::new(config.clone()).unwrap();
        let saved = local.generate(input()).await.unwrap();
        let mut required = config;
        required.mode = Mode::RemoteRequired;
        let vault = Vault { config: required, remote: Some(Arc::new(Failed(remote::Error::Unavailable))) };
        assert_eq!(vault.generate(input()).await.unwrap_err(), "operation_policy_conflict");
        assert!(std::path::Path::new(&saved.reference).is_file());
        assert_eq!(std::fs::read_dir(root.path().join("keys")).unwrap().count(), 1);
    }
    #[tokio::test]
    async fn conflicting_ids_and_interrupted_operations_do_not_generate_again() {
        let (root, config) = fixture(Mode::LocalOnly);
        {
            let journal = Journal::open(&config.state_dir).unwrap();
            journal.begin(&input()).unwrap();
        }
        let vault = Vault::new(config).unwrap();
        assert_eq!(
            vault.generate(input()).await.unwrap_err(),
            "operation_interrupted_or_failed"
        );
        let mut changed = input();
        changed.n = 64;
        assert_eq!(
            vault.generate(changed).await.unwrap_err(),
            "operation_conflict"
        );
        assert_eq!(
            std::fs::read_dir(root.path().join("keys")).unwrap().count(),
            0
        );
    }
    #[tokio::test]
    async fn invalid_arguments_name_the_problem_and_the_prefix() {
        let (_root, config) = fixture(Mode::LocalOnly);
        let vault = Vault::new(config).unwrap();
        for (change, code) in [
            (Input { label: "agent-key".into(), ..input() }, "label_prefix_mismatch"),
            (Input { label: "test-bad label".into(), ..input() }, "invalid_label"),
            (Input { n: 65, ..input() }, "invalid_size"),
            (Input { operation_id: "has space".into(), ..input() }, "invalid_operation_id"),
        ] {
            assert_eq!(vault.generate(change).await.unwrap_err(), code);
            assert!(ARGUMENT_ERRORS.contains(&code));
        }
        assert_eq!(vault.hint("label_prefix_mismatch"), "label must start with \"test-\"");
        assert!(vault.tool_description().contains("start with \"test-\""));
        assert!(vault.tool_description().contains("no network call"));
        #[cfg(feature = "remote")]
        {
            let (_root, config) = fixture(Mode::RemoteRequired);
            let remote = Vault::new(config).unwrap();
            assert!(remote.tool_description().contains("paid MCPBytes job"));
            assert!(remote.tool_description().contains("MCPBYTES_API_KEY"));
        }
    }
    #[cfg(not(feature = "remote"))]
    #[test]
    fn a_local_only_build_refuses_remote_modes() {
        for mode in [Mode::RemoteRequired, Mode::RemotePreferred] {
            assert_eq!(Vault::new(fixture(mode).1).err(), Some("remote_not_built"));
        }
    }
    #[tokio::test]
    async fn list_reveal_and_delete_keep_the_journal_consistent() {
        let (_root, config) = fixture(Mode::LocalOnly);
        let vault = Vault::new(config).unwrap();
        let first = vault.generate(input()).await.unwrap();
        assert_eq!(first.format.as_deref(), Some("raw"));
        let second = vault
            .generate(Input { operation_id: "rotate".into(), ..input() })
            .await
            .unwrap();
        let listing = vault.list().unwrap();
        assert_eq!(listing.label_prefix, "test-");
        assert_eq!(listing.secrets.len(), 2);
        assert!(listing.secrets.iter().all(|s| s.status == "saved" && s.created_at.is_some()));
        // The listing is metadata only.
        let stored = std::fs::read(&first.reference).unwrap();
        let json = serde_json::to_string(&listing).unwrap();
        assert!(!json.contains(&b64(&stored)));

        // Without a version, reveal returns the newest saved one.
        let (record, bytes) = vault.reveal("test-key", None).unwrap();
        assert_eq!(record.version, second.version);
        assert_eq!(*bytes, std::fs::read(&second.reference).unwrap());
        assert_eq!(*vault.reveal("test-key", Some(1)).unwrap().1, stored);
        // Compared through .err(): unwrap_err() would need a printable Ok value, i.e. the secret.
        assert_eq!(vault.reveal("test-none", None).err(), Some("secret_not_found"));

        let (_, existed) = vault.delete("test-key", 1).unwrap();
        assert!(existed);
        assert!(!std::path::Path::new(&first.reference).exists());
        assert_eq!(vault.delete("test-key", 1).err(), Some("secret_deleted"));
        assert_eq!(vault.reveal("test-key", Some(1)).err(), Some("secret_deleted"));
        // A retry of the deleted operation must not return a receipt for a secret that is gone.
        assert_eq!(vault.generate(input()).await.unwrap_err(), "secret_deleted");
        // Versions are never reused after a delete.
        let third = vault
            .generate(Input { operation_id: "after-delete".into(), ..input() })
            .await
            .unwrap();
        assert_eq!(third.version, 3);
        let statuses: Vec<_> = vault.list().unwrap().secrets.iter().map(|s| s.status).collect();
        assert_eq!(statuses, ["deleted", "saved", "saved"]);

        // A secret removed outside the vault still deletes cleanly and reveals as missing.
        std::fs::remove_file(&second.reference).unwrap();
        assert_eq!(vault.reveal("test-key", Some(2)).err(), Some("secret_missing_from_store"));
        assert!(!vault.delete("test-key", 2).unwrap().1);
    }
    #[cfg(feature = "remote")]
    #[tokio::test]
    async fn authenticated_remote_mix_is_saved_but_tampering_never_falls_back() {
        for tamper in [false, true] {
            let (root, config) = fixture(Mode::RemotePreferred);
            let vault = Vault {
                config,
                remote: Some(Arc::new(Sealed { tamper })),
            };
            let result = vault.generate(input()).await;
            if tamper {
                assert_eq!(result.unwrap_err(), "remote_authentication_failed");
                assert_eq!(
                    std::fs::read_dir(root.path().join("keys")).unwrap().count(),
                    0
                );
            } else {
                let receipt = result.unwrap();
                assert_eq!(receipt.entropy_mode, "mixed");
                assert!(receipt.fallback_reason.is_none());
                assert_eq!(std::fs::read(receipt.reference).unwrap().len(), 32);
            }
        }
    }
}

