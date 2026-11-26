//! Shared synthetic inputs. The indirect blob and envelope were generated
//! independently with Python hashlib/hmac and PyCryptodome, using invented
//! credentials and the native partition fixture's known password and key data.

pub(crate) const FIXTURE: &[u8] = include_bytes!("fixtures/synthetic.keychain-db");
pub(crate) const PASSWORD: &[u8] = b"exhume synthetic fixture password";
pub(crate) const LOGIN_PASSWORD: &[u8] = b"SYNTHETIC-LOGIN-PASSWORD\n";
pub(crate) const PROTECTED_ENTROPY: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];
pub(crate) const SIGNAL_KEY_ENVELOPE: &str = "76313021ba560892f7ae52bd08a6bd238040a435a94b9fe95b8a787be17e5486be929185edd976b91aa7d9878b6941b5b7dd32e6af22bc6644e1416c79b47e6a4e4d724d2509d9b2886ac79e6b9a6058caeb22";

pub(crate) fn indirect_fixture() -> Vec<u8> {
    let mut bytes = include_bytes!("fixtures/synthetic-partition.keychain-db").to_vec();
    let start = super::LegacyKeychain::parse(&bytes)
        .unwrap()
        .metadata()
        .database_blob_offset
        .unwrap();
    let blob = hex::decode(include_str!("fixtures/indirect-blob.hex")).unwrap();
    bytes[start..start + blob.len()].copy_from_slice(&blob);
    bytes
}
