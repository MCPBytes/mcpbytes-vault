//! Optional host-side JSON codec. Not enabled in the embedded build.
use crate::{Envelope, Error, Identity, Request, MAX_BYTES, TAG_BYTES};
use alloc::string::String;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};

pub fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}
pub fn decode<const N: usize>(text: &str) -> Result<[u8; N], Error> {
    if text.len() != (N * 8).div_ceil(6) {
        return Err(Error::InvalidEnvelope);
    }
    let data = URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|_| Error::InvalidEnvelope)?;
    if encode(&data) != text {
        return Err(Error::InvalidEnvelope);
    }
    data.try_into().map_err(|_| Error::InvalidEnvelope)
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireRequest {
    pub version: u8,
    pub n: u8,
    pub pk_c: String,
    pub request_id: String,
}
impl WireRequest {
    pub fn to_core(&self) -> Result<Request, Error> {
        if self.version != 1 {
            return Err(Error::InvalidRequest);
        }
        let request = Request::new(self.n as usize, decode(&self.pk_c)?)?;
        if request.id != decode(&self.request_id)? {
            return Err(Error::InvalidRequest);
        }
        Ok(request)
    }
}
impl From<&Request> for WireRequest {
    fn from(value: &Request) -> Self {
        Self {
            version: 1,
            n: value.n,
            pk_c: encode(&value.recipient),
            request_id: encode(&value.id),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireEnvelope {
    pub request: WireRequest,
    pub device_pk_id: String,
    pub fw_digest: String,
    pub enc: String,
    pub ct: String,
}
impl WireEnvelope {
    pub fn to_core(&self) -> Result<Envelope, Error> {
        let request = self.request.to_core()?;
        let n = request.n as usize + TAG_BYTES;
        if self.ct.len() != (n * 8).div_ceil(6) {
            return Err(Error::InvalidEnvelope);
        }
        let ct = URL_SAFE_NO_PAD
            .decode(&self.ct)
            .map_err(|_| Error::InvalidEnvelope)?;
        if ct.len() != n || encode(&ct) != self.ct {
            return Err(Error::InvalidEnvelope);
        }
        let mut ciphertext = [0; MAX_BYTES + TAG_BYTES];
        ciphertext[..n].copy_from_slice(&ct);
        Ok(Envelope {
            request,
            identity: Identity {
                key_id: decode(&self.device_pk_id)?,
                firmware: decode(&self.fw_digest)?,
            },
            enc: decode(&self.enc)?,
            ciphertext,
        })
    }
}
impl From<&Envelope> for WireEnvelope {
    fn from(value: &Envelope) -> Self {
        Self {
            request: WireRequest::from(&value.request),
            device_pk_id: encode(&value.identity.key_id),
            fw_digest: encode(&value.identity.firmware),
            enc: encode(&value.enc),
            ct: encode(&value.ciphertext[..value.request.n as usize + TAG_BYTES]),
        }
    }
}
