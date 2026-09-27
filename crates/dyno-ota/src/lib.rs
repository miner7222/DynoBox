//! OTA signing and packaging for DynoBox: RSA signing keys, X.509
//! certificates, the `otacerts.zip` bundle Android's OTA verifiers trust,
//! signed update_engine payloads, and signed A/B OTA packages.

pub mod cert;
pub mod cms;
mod der;
pub mod full;
pub mod key;
pub mod metadata;
pub mod otacerts;
pub mod package;
pub mod payload;
mod pem;
pub mod verify;
mod zipsig;
mod zipwriter;

pub use cert::Certificate;
pub use key::OtaSigningKey;

#[cfg(test)]
mod e2e_tests;
