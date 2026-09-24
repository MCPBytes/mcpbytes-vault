//! Explicit known-answer-test feature. Every key/value here is a public RFC fixture.
use hpke::{
    aead::{AeadTag, ChaCha20Poly1305},
    kdf::HkdfSha256,
    kem::X25519HkdfSha256,
    rand_core::{TryCryptoRng, TryRng},
    Deserializable, Kem, OpModeR, OpModeS, Serializable,
};
#[path = "kat_vectors.rs"]
mod vector;
type K = X25519HkdfSha256;
struct FixtureRng {
    offset: usize,
}
impl TryRng for FixtureRng {
    type Error = core::convert::Infallible;
    fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), Self::Error> {
        out.copy_from_slice(&vector::IKME[self.offset..self.offset + out.len()]);
        self.offset += out.len();
        Ok(())
    }
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut b = [0; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }
}
impl TryCryptoRng for FixtureRng {}
pub fn run() -> bool {
    run_inner().is_ok()
}
fn run_inner() -> Result<(), ()> {
    let sender = <K as Kem>::PrivateKey::from_bytes(vector::SKSM).map_err(|_| ())?;
    let sender_pk = <K as Kem>::PublicKey::from_bytes(vector::PKSM).map_err(|_| ())?;
    let receiver = <K as Kem>::PrivateKey::from_bytes(vector::SKRM).map_err(|_| ())?;
    let receiver_pk = <K as Kem>::PublicKey::from_bytes(vector::PKRM).map_err(|_| ())?;
    let mut rng = FixtureRng { offset: 0 };
    let (enc, mut seal) = hpke::setup_sender_with_rng::<ChaCha20Poly1305, HkdfSha256, K>(
        &OpModeS::Auth((sender, sender_pk.clone())),
        &receiver_pk,
        vector::INFO,
        &mut rng,
    )
    .map_err(|_| ())?;
    if enc.to_bytes().as_slice() != vector::ENC || rng.offset != 32 {
        return Err(());
    }
    let mut open = hpke::setup_receiver::<ChaCha20Poly1305, HkdfSha256, K>(
        &OpModeR::Auth(sender_pk),
        &receiver,
        &enc,
        vector::INFO,
    )
    .map_err(|_| ())?;
    for &(plaintext, aad, expected) in vector::CASES {
        if plaintext.len() > 64 || expected.len() != plaintext.len() + 16 {
            return Err(());
        }
        let mut data = [0u8; 64];
        let n = plaintext.len();
        data[..n].copy_from_slice(plaintext);
        let tag = seal
            .seal_inout_detached((&mut data[..n]).into(), aad)
            .map_err(|_| ())?;
        if data[..n] != expected[..n] || tag.to_bytes().as_slice() != &expected[n..] {
            return Err(());
        }
        let tag = AeadTag::<ChaCha20Poly1305>::from_bytes(&expected[n..]).map_err(|_| ())?;
        open.open_inout_detached((&mut data[..n]).into(), aad, &tag)
            .map_err(|_| ())?;
        if &data[..n] != plaintext {
            return Err(());
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    #[test]
    fn embedded_vectors_pass() {
        assert!(super::run());
    }
}
