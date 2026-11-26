//! Storage-format support shared by artefact parsers.
//!
//! These modules depend on core contracts and evidence inputs, never on a
//! concrete parser or its platform registration.

pub mod dpapi;
pub mod gnome_keyring;
pub mod keychain;
pub mod kwallet;
pub mod os_crypt;
pub mod sqlite;
pub(crate) mod timestamps;
