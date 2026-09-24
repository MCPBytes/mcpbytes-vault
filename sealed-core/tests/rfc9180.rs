use hpke::{
    aead::{AeadTag, ChaCha20Poly1305},
    kdf::HkdfSha256,
    kem::X25519HkdfSha256,
    rand_core::{TryCryptoRng, TryRng},
    Deserializable, Kem, OpModeR, OpModeS, Serializable,
};
use serde_json::Value;
type K = X25519HkdfSha256;

// Deterministic public RFC fixture, never used by application/firmware code.
struct VectorRng {
    bytes: Vec<u8>,
    offset: usize,
}
impl TryRng for VectorRng {
    type Error = std::convert::Infallible;
    fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), Self::Error> {
        out.copy_from_slice(&self.bytes[self.offset..self.offset + out.len()]);
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
impl TryCryptoRng for VectorRng {}
fn bytes(value: &Value, name: &str) -> Vec<u8> {
    hex::decode(value[name].as_str().unwrap()).unwrap()
}

#[test]
fn official_auth_x25519_hkdf_sha256_chacha_vectors() {
    let vector: Value =
        serde_json::from_str(include_str!("rfc9180-auth-x25519-chacha.json")).unwrap();
    let sender = <K as Kem>::PrivateKey::from_bytes(&bytes(&vector, "skSm")).unwrap();
    let sender_pk = <K as Kem>::PublicKey::from_bytes(&bytes(&vector, "pkSm")).unwrap();
    let receiver = <K as Kem>::PrivateKey::from_bytes(&bytes(&vector, "skRm")).unwrap();
    let receiver_pk = <K as Kem>::PublicKey::from_bytes(&bytes(&vector, "pkRm")).unwrap();
    let info = bytes(&vector, "info");
    let mut rng = VectorRng {
        bytes: bytes(&vector, "ikmE"),
        offset: 0,
    };
    let (enc, mut seal) = hpke::setup_sender_with_rng::<ChaCha20Poly1305, HkdfSha256, K>(
        &OpModeS::Auth((sender, sender_pk.clone())),
        &receiver_pk,
        &info,
        &mut rng,
    )
    .unwrap();
    assert_eq!(enc.to_bytes().as_slice(), bytes(&vector, "enc"));
    assert_eq!(rng.offset, 32);
    let mut open = hpke::setup_receiver::<ChaCha20Poly1305, HkdfSha256, K>(
        &OpModeR::Auth(sender_pk),
        &receiver,
        &enc,
        &info,
    )
    .unwrap();
    for case in vector["encryptions"].as_array().unwrap() {
        let original = bytes(case, "pt");
        let mut encrypted = original.clone();
        let aad = bytes(case, "aad");
        let tag = seal
            .seal_inout_detached(encrypted.as_mut_slice().into(), &aad)
            .unwrap();
        let mut expected = bytes(case, "ct");
        let tag_bytes = expected.split_off(expected.len() - 16);
        assert_eq!(encrypted, expected);
        assert_eq!(tag.to_bytes().as_slice(), tag_bytes);
        let tag = AeadTag::<ChaCha20Poly1305>::from_bytes(&tag_bytes).unwrap();
        open.open_inout_detached(encrypted.as_mut_slice().into(), &aad, &tag)
            .unwrap();
        assert_eq!(encrypted, original);
    }
}
