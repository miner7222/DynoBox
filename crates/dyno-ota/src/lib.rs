//! OTA signing for DynoBox: RSA signing keys, X.509 certificates, and the
//! `otacerts.zip` bundle Android's OTA verifiers trust.

pub mod cert;
mod der;
pub mod key;
pub mod otacerts;
mod pem;

pub use cert::Certificate;
pub use key::OtaSigningKey;
