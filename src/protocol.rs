//! Key derivation. The local path (OS randomness through HKDF) is always built; the sealed remote
//! request (`Pending`) only with the `remote` feature.
use hkdf::Hkdf;
#[cfg(feature = "remote")]
use mcpbytes_sealed_core::{self as core, Request, SecretKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Most bytes per secret; the sealed protocol has the same limit.
pub const MAX_BYTES: usize = 64;
#[cfg(feature = "remote")]
const _: () = assert!(MAX_BYTES == core::MAX_BYTES);

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    InvalidRequest,
    #[cfg(feature = "remote")]
    InvalidEnvelope,
    #[cfg(feature = "remote")]
    AuthenticationFailed,
    EntropyUnavailable,
    DerivationFailed,
}

#[cfg(feature = "remote")]
pub use core::json::{decode, encode, WireEnvelope, WireRequest};
#[cfg(feature = "remote")]
impl From<core::Error> for Error {
    fn from(_: core::Error) -> Self {
        Self::InvalidEnvelope
    }
}

/// Non-cloneable, non-serializable request state: consumed even on authentication failure.
#[cfg(feature = "remote")]
pub struct Pending {
    request: Request,
    secret: SecretKey,
}
#[cfg(feature = "remote")]
impl Pending {
    pub fn new(n: usize) -> Result<Self, Error> {
        if !(1..=MAX_BYTES).contains(&n) {
            return Err(Error::InvalidRequest);
        }
        let mut seed = Zeroizing::new([0; 32]);
        getrandom::fill(seed.as_mut()).map_err(|_| Error::EntropyUnavailable)?;
        let (secret, public) = core::keypair(&seed);
        Ok(Self {
            request: Request::new(n, public).map_err(|_| Error::InvalidRequest)?,
            secret,
        })
    }
    pub fn request(&self) -> WireRequest {
        WireRequest::from(&self.request)
    }
    pub fn open_and_mix(
        self,
        envelope: &WireEnvelope,
        pinned_sender: &[u8; 32],
        key_context: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        let envelope = envelope.to_core()?;
        let remote = core::open(&self.request, &self.secret, pinned_sender, &envelope)
            .map_err(|_| Error::AuthenticationFailed)?;
        let mut context = key_context.to_vec();
        context.extend_from_slice(&self.request.id);
        derive(remote.as_slice(), &context, self.request.n as usize, true)
    }
}

pub fn local_only(n: usize, key_context: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    derive(&[], key_context, n, false)
}
fn derive(
    remote: &[u8],
    context: &[u8],
    n: usize,
    mixed: bool,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    if !(1..=MAX_BYTES).contains(&n) {
        return Err(Error::InvalidRequest);
    }
    let mut local = Zeroizing::new([0; 32]);
    getrandom::fill(local.as_mut()).map_err(|_| Error::EntropyUnavailable)?;
    mix_with_local(&local, remote, context, n, mixed)
}
fn mix_with_local(
    local: &[u8; 32],
    remote: &[u8],
    context: &[u8],
    n: usize,
    mixed: bool,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    if !(1..=MAX_BYTES).contains(&n)
        || (mixed && remote.len() != n)
        || (!mixed && !remote.is_empty())
    {
        return Err(Error::InvalidRequest);
    }
    let mut ikm = Zeroizing::new(Vec::with_capacity(32 + remote.len()));
    ikm.extend_from_slice(local);
    ikm.extend_from_slice(remote);
    let salt = Sha256::digest(b"mcpbytes-vault/extract/v1");
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut info = b"mcpbytes-vault/key/v1\0".to_vec();
    info.extend_from_slice(&[n as u8, u8::from(mixed)]);
    info.extend_from_slice(&(context.len() as u32).to_be_bytes());
    info.extend_from_slice(context);
    let mut output = Zeroizing::new(vec![0; n]);
    hkdf.expand(&info, &mut output)
        .map_err(|_| Error::DerivationFailed)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn local_generation_limits_and_context_separation() {
        assert!(local_only(0, b"label#1").is_err());
        assert!(local_only(65, b"label#1").is_err());
        assert_eq!(local_only(64, b"label#1").unwrap().len(), 64);
        let a = mix_with_local(&[1; 32], &[0; 32], b"a", 32, true).unwrap();
        assert_ne!(
            *a,
            *mix_with_local(&[2; 32], &[0; 32], b"a", 32, true).unwrap()
        );
        assert_ne!(
            *a,
            *mix_with_local(&[1; 32], &[0; 32], b"b", 32, true).unwrap()
        );
    }
    #[cfg(feature = "remote")]
    #[test]
    fn strict_wire_encodings_and_request_identity() {
        let request = Pending::new(32).unwrap().request();
        assert!(request.to_core().is_ok());
        let mut changed = request.clone();
        changed.n = 16;
        assert!(changed.to_core().is_err());
        assert!(decode::<32>(&(request.pk_c.clone() + "=")).is_err());
        let mut json = serde_json::to_value(&request).unwrap();
        json["plaintext"] = serde_json::json!("not accepted");
        assert!(serde_json::from_value::<WireRequest>(json).is_err());
    }
}
