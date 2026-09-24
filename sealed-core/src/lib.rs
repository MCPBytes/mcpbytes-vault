#![no_std]
//! Shared, allocation-free sealed-output protocol. Hardware provisioning is separate.
#[cfg(feature = "json")]
extern crate alloc;
#[cfg(feature = "json")]
pub mod json;
#[cfg(feature = "kat")]
pub mod kat;
use hpke::{
    aead::{AeadTag, ChaCha20Poly1305},
    kdf::HkdfSha256,
    kem::X25519HkdfSha256,
    Deserializable, Kem, OpModeR, OpModeS, Serializable,
};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

pub type SuiteKem = X25519HkdfSha256;
pub use hpke::rand_core;
pub type SecretKey = <SuiteKem as Kem>::PrivateKey;
pub const MAX_BYTES: usize = 64;
pub const TAG_BYTES: usize = 16;
pub const INFO: &[u8] = b"mcpbytes-sealed-v1";
pub const AAD_LEN: usize = 2 + 32 * 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidRequest,
    InvalidEnvelope,
    AuthenticationFailed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    pub n: u8,
    pub recipient: [u8; 32],
    pub id: [u8; 32],
}

impl Request {
    pub fn new(n: usize, recipient: [u8; 32]) -> Result<Self, Error> {
        // A fixed non-secret scalar is used only to reject low-order public inputs.
        if !(1..=MAX_BYTES).contains(&n) || x25519_dalek::x25519([42; 32], recipient) == [0; 32] {
            return Err(Error::InvalidRequest);
        }
        let mut hash = Sha256::new();
        hash.update(b"mcpbytes-sealed-request-v1\0");
        hash.update([n as u8]);
        hash.update(recipient);
        Ok(Self {
            n: n as u8,
            recipient,
            id: hash.finalize().into(),
        })
    }
    pub fn validate(&self) -> Result<(), Error> {
        if *self != Self::new(self.n as usize, self.recipient)? {
            return Err(Error::InvalidRequest);
        }
        Ok(())
    }
    pub fn aad(&self, identity: &Identity) -> Result<[u8; AAD_LEN], Error> {
        self.validate()?;
        let mut aad = [0u8; AAD_LEN];
        aad[0] = 1;
        aad[1] = self.n;
        aad[2..34].copy_from_slice(&self.recipient);
        aad[34..66].copy_from_slice(&self.id);
        aad[66..98].copy_from_slice(&identity.key_id);
        aad[98..130].copy_from_slice(&identity.firmware);
        Ok(aad)
    }
}

/// Firmware digest is authenticated sender metadata, NOT measured-boot attestation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    pub key_id: [u8; 32],
    pub firmware: [u8; 32],
}
pub fn key_id(public: &[u8; 32]) -> [u8; 32] {
    Sha256::digest(public).into()
}

#[derive(Clone, Debug)]
pub struct Envelope {
    pub request: Request,
    pub identity: Identity,
    pub enc: [u8; 32],
    pub ciphertext: [u8; MAX_BYTES + TAG_BYTES],
}

pub struct SecretBytes {
    bytes: Zeroizing<[u8; MAX_BYTES]>,
    len: usize,
}
impl SecretBytes {
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

pub fn keypair(seed: &[u8; 32]) -> (SecretKey, [u8; 32]) {
    let (secret, public) = SuiteKem::derive_keypair(seed);
    (secret, public.to_bytes().into())
}

/// The caller supplies fresh checked randomness for HPKE; no fallback exists here.
/// The caller's plaintext is wiped whether sealing succeeds or fails.
pub fn seal(
    request: &Request,
    firmware: [u8; 32],
    sender: &SecretKey,
    plaintext: &mut [u8],
    rng: &mut impl hpke::rand_core::CryptoRng,
) -> Result<Envelope, Error> {
    let result = seal_inner(request, firmware, sender, plaintext, rng);
    plaintext.zeroize();
    result
}
fn seal_inner(
    request: &Request,
    firmware: [u8; 32],
    sender: &SecretKey,
    plaintext: &[u8],
    rng: &mut impl hpke::rand_core::CryptoRng,
) -> Result<Envelope, Error> {
    request.validate()?;
    if plaintext.len() != request.n as usize {
        return Err(Error::InvalidRequest);
    }
    let public = SuiteKem::sk_to_pk(sender);
    let public_bytes: [u8; 32] = public.to_bytes().into();
    let identity = Identity {
        key_id: key_id(&public_bytes),
        firmware,
    };
    let aad = request.aad(&identity)?;
    let recipient = <SuiteKem as Kem>::PublicKey::from_bytes(&request.recipient)
        .map_err(|_| Error::InvalidRequest)?;
    let mut encrypted = Zeroizing::new([0u8; MAX_BYTES + TAG_BYTES]);
    encrypted[..plaintext.len()].copy_from_slice(plaintext);
    let (enc, tag) =
        hpke::single_shot_seal_inout_detached_with_rng::<ChaCha20Poly1305, HkdfSha256, SuiteKem>(
            &OpModeS::Auth((sender.clone(), public)),
            &recipient,
            INFO,
            (&mut encrypted[..plaintext.len()]).into(),
            &aad,
            rng,
        )
        .map_err(|_| Error::InvalidRequest)?;
    encrypted[plaintext.len()..plaintext.len() + TAG_BYTES].copy_from_slice(&tag.to_bytes());
    Ok(Envelope {
        request: *request,
        identity,
        enc: enc.to_bytes().into(),
        ciphertext: *encrypted,
    })
}

pub fn open(
    expected: &Request,
    receiver: &SecretKey,
    pinned_sender: &[u8; 32],
    envelope: &Envelope,
) -> Result<SecretBytes, Error> {
    expected.validate()?;
    if envelope.request != *expected
        || envelope.identity.key_id != key_id(pinned_sender)
        || SuiteKem::sk_to_pk(receiver).to_bytes().as_slice() != expected.recipient
    {
        return Err(Error::InvalidEnvelope);
    }
    if envelope.ciphertext[expected.n as usize + TAG_BYTES..]
        .iter()
        .any(|b| *b != 0)
    {
        return Err(Error::InvalidEnvelope);
    }
    let aad = expected.aad(&envelope.identity)?;
    let sender = <SuiteKem as Kem>::PublicKey::from_bytes(pinned_sender)
        .map_err(|_| Error::InvalidEnvelope)?;
    let enc = <SuiteKem as Kem>::EncappedKey::from_bytes(&envelope.enc)
        .map_err(|_| Error::InvalidEnvelope)?;
    let n = expected.n as usize;
    let tag = AeadTag::<ChaCha20Poly1305>::from_bytes(&envelope.ciphertext[n..n + TAG_BYTES])
        .map_err(|_| Error::InvalidEnvelope)?;
    let mut bytes = Zeroizing::new([0u8; MAX_BYTES]);
    bytes[..n].copy_from_slice(&envelope.ciphertext[..n]);
    hpke::single_shot_open_inout_detached::<ChaCha20Poly1305, HkdfSha256, SuiteKem>(
        &OpModeR::Auth(sender),
        receiver,
        &enc,
        INFO,
        (&mut bytes[..n]).into(),
        &aad,
        &tag,
    )
    .map_err(|_| Error::AuthenticationFailed)?;
    Ok(SecretBytes { bytes, len: n })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hpke::rand_core::UnwrapErr;
    #[test]
    fn boundaries_and_sealing_wipes_plaintext() {
        for n in [1, 32, 64] {
            let (receiver, pk) = keypair(&[1; 32]);
            let (sender, pinned) = keypair(&[2; 32]);
            let request = Request::new(n, pk).unwrap();
            let mut data = [42; 64];
            let envelope = seal(
                &request,
                [3; 32],
                &sender,
                &mut data[..n],
                &mut UnwrapErr(getrandom::SysRng),
            )
            .unwrap();
            assert!(data[..n].iter().all(|b| *b == 0));
            assert_eq!(
                open(&request, &receiver, &pinned, &envelope)
                    .unwrap()
                    .as_slice(),
                &[42; 64][..n]
            );
        }
        assert!(Request::new(0, [1; 32]).is_err());
        assert!(Request::new(65, [1; 32]).is_err());
    }
    #[test]
    fn low_order_recipients_are_rejected_and_failed_seals_wipe_input() {
        let (sender, _) = keypair(&[2; 32]);
        for first in [0, 1] {
            let mut recipient = [0; 32];
            recipient[0] = first;
            assert_eq!(Request::new(32, recipient), Err(Error::InvalidRequest));
            let forged = Request {
                n: 32,
                recipient,
                id: [0; 32],
            };
            let mut plaintext = [42; 32];
            assert!(seal(
                &forged,
                [3; 32],
                &sender,
                &mut plaintext,
                &mut UnwrapErr(getrandom::SysRng)
            )
            .is_err());
            assert_eq!(plaintext, [0; 32]);
        }
    }
    #[test]
    fn tampering_and_request_rebinding_fail() {
        let (receiver, pk) = keypair(&[1; 32]);
        let (sender, pinned) = keypair(&[2; 32]);
        let request = Request::new(32, pk).unwrap();
        let envelope = seal(
            &request,
            [3; 32],
            &sender,
            &mut [42; 32],
            &mut UnwrapErr(getrandom::SysRng),
        )
        .unwrap();
        for field in 0..6 {
            let mut changed = envelope.clone();
            match field {
                0 => changed.enc[0] ^= 1,
                1 => changed.ciphertext[0] ^= 1,
                2 => changed.identity.firmware[0] ^= 1,
                3 => changed.request.id[0] ^= 1,
                4 => changed.identity.key_id[0] ^= 1,
                _ => changed.ciphertext[79] ^= 1,
            }
            assert!(open(&request, &receiver, &pinned, &changed).is_err());
        }
        let (_, wrong) = keypair(&[4; 32]);
        assert!(open(&request, &receiver, &wrong, &envelope).is_err());
    }
}
