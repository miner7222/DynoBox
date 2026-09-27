//! X.509 certificates for OTA signing.
//!
//! Android's OTA verifiers (update_engine, recovery and the framework's
//! `RecoverySystem`) use the certificate only to carry the RSA public key, so
//! a certificate may be stripped down to fit a fixed-size `otacerts.zip`.

use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use rand_core::{OsRng, RngCore};
use rsa::RsaPublicKey;
use rsa::pkcs1::DecodeRsaPublicKey;

use crate::der::{self, Tlv};
use crate::key::{self, OtaSigningKey};
use crate::pem;

const OID_RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
const OID_SHA256_WITH_RSA: &str = "1.2.840.113549.1.1.11";
const OID_COMMON_NAME: &str = "2.5.4.3";

const TAG_VERSION: u8 = 0xA0;
const TAG_ISSUER_UID: u8 = 0x81;
const TAG_SUBJECT_UID: u8 = 0x82;
const TAG_EXTENSIONS: u8 = 0xA3;

/// Fields that can be removed without affecting Android's OTA verification,
/// in the order they are given up to meet a size budget.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Strip {
    pub signature: bool,
    pub extensions: bool,
    pub issuer: bool,
    pub subject: bool,
}

/// A DER-encoded X.509 certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    der: Vec<u8>,
}

/// Borrowed view of the fields DynoBox reads or rewrites.
struct Parts<'a> {
    signature_algorithm: Tlv<'a>,
    signature: Tlv<'a>,
    version: Option<Tlv<'a>>,
    serial: Tlv<'a>,
    tbs_signature: Tlv<'a>,
    issuer: Tlv<'a>,
    validity: Tlv<'a>,
    subject: Tlv<'a>,
    spki: Tlv<'a>,
    issuer_uid: Option<Tlv<'a>>,
    subject_uid: Option<Tlv<'a>>,
    extensions: Option<Tlv<'a>>,
}

fn parse(der_bytes: &[u8]) -> Result<Parts<'_>> {
    let outer = der::read_single(der_bytes, der::TAG_SEQUENCE)?;
    let top = der::read_children(outer.content)?;
    let [tbs, signature_algorithm, signature] = top[..] else {
        bail!(
            "certificate must have 3 top-level fields, found {}",
            top.len()
        );
    };
    der::expect_tag(&tbs, der::TAG_SEQUENCE)?;
    der::expect_tag(&signature_algorithm, der::TAG_SEQUENCE)?;
    der::expect_tag(&signature, der::TAG_BIT_STRING)?;

    let fields = der::read_children(tbs.content)?;
    let mut rest = &fields[..];
    let version = match rest.first() {
        Some(first) if first.tag == TAG_VERSION => {
            rest = &rest[1..];
            Some(*first)
        }
        _ => None,
    };
    let [
        serial,
        tbs_signature,
        issuer,
        validity,
        subject,
        spki,
        ref optional @ ..,
    ] = *rest
    else {
        bail!("certificate TBS is missing required fields");
    };
    der::expect_tag(&serial, der::TAG_INTEGER)?;
    for field in [&tbs_signature, &issuer, &validity, &subject, &spki] {
        der::expect_tag(field, der::TAG_SEQUENCE)?;
    }
    let (mut issuer_uid, mut subject_uid, mut extensions) = (None, None, None);
    let mut last_tag = 0u8;
    for field in optional {
        if field.tag <= last_tag {
            bail!("certificate TBS optional fields are out of order");
        }
        last_tag = field.tag;
        match field.tag {
            TAG_ISSUER_UID => issuer_uid = Some(*field),
            TAG_SUBJECT_UID => subject_uid = Some(*field),
            TAG_EXTENSIONS => extensions = Some(*field),
            other => bail!("unexpected certificate TBS field tag {other:#04x}"),
        }
    }
    Ok(Parts {
        signature_algorithm,
        signature,
        version,
        serial,
        tbs_signature,
        issuer,
        validity,
        subject,
        spki,
        issuer_uid,
        subject_uid,
        extensions,
    })
}

fn rsa_algorithm_identifier(oid: &str) -> Vec<u8> {
    der::sequence(&[&der::oid(oid), &der::null()])
}

fn common_name(name: &str) -> Vec<u8> {
    let attribute = der::sequence(&[
        &der::oid(OID_COMMON_NAME),
        &der::encode(der::TAG_UTF8_STRING, name.as_bytes()),
    ]);
    der::sequence(&[&der::constructed(der::TAG_SET, &[&attribute])])
}

/// RFC 5280 time: UTCTime through 2049, GeneralizedTime afterwards.
fn x509_time(unix_secs: i64) -> Vec<u8> {
    let days = unix_secs.div_euclid(86_400);
    let secs = unix_secs.rem_euclid(86_400);
    let (year, month, day) = dynobox_core::time_format::civil_from_days(days);
    let clock = format!(
        "{month:02}{day:02}{:02}{:02}{:02}Z",
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    );
    if (1950..2050).contains(&year) {
        der::encode(
            der::TAG_UTC_TIME,
            format!("{:02}{clock}", year % 100).as_bytes(),
        )
    } else {
        der::encode(
            der::TAG_GENERALIZED_TIME,
            format!("{year:04}{clock}").as_bytes(),
        )
    }
}

impl Certificate {
    /// Parse DER bytes, validating the certificate structure.
    pub fn from_der(der_bytes: Vec<u8>) -> Result<Self> {
        parse(&der_bytes)?;
        Ok(Self { der: der_bytes })
    }

    /// Parse a PEM `CERTIFICATE` block or raw DER.
    pub fn from_pem_or_der(bytes: &[u8]) -> Result<Self> {
        match std::str::from_utf8(bytes) {
            Ok(text) if text.contains("-----BEGIN") => {
                Self::from_der(pem::decode(text, "CERTIFICATE")?)
            }
            _ => Self::from_der(bytes.to_vec()),
        }
    }

    pub fn load(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path)
            .with_context(|| format!("reading certificate {}", path.display()))?;
        Self::from_pem_or_der(&bytes)
            .with_context(|| format!("parsing certificate {}", path.display()))
    }

    /// Self-signed certificate for `key` with a common-name subject, valid
    /// from `not_before_unix` with no practical expiry.
    pub fn self_signed(
        key: &OtaSigningKey,
        subject_common_name: &str,
        not_before_unix: i64,
    ) -> Result<Self> {
        let mut serial = [0u8; 16];
        OsRng.fill_bytes(&mut serial);
        serial[0] &= 0x7F;
        serial[0] |= 0x40;

        let (modulus, exponent) = key::public_parts(&key.public_key());
        let rsa_public_key = der::sequence(&[
            &der::unsigned_integer(&modulus),
            &der::unsigned_integer(&exponent),
        ]);
        let spki = der::sequence(&[
            &rsa_algorithm_identifier(OID_RSA_ENCRYPTION),
            &der::bit_string(&rsa_public_key),
        ]);
        let name = common_name(subject_common_name);
        let validity = der::sequence(&[
            &x509_time(not_before_unix),
            &der::encode(der::TAG_GENERALIZED_TIME, b"99991231235959Z"),
        ]);
        let algorithm = rsa_algorithm_identifier(OID_SHA256_WITH_RSA);
        let tbs = der::sequence(&[
            &der::constructed(TAG_VERSION, &[&der::unsigned_integer(&[2])]),
            &der::unsigned_integer(&serial),
            &algorithm,
            &name,
            &validity,
            &name,
            &spki,
        ]);
        let signature = key.sign_sha256(&tbs)?;
        Self::from_der(der::sequence(&[
            &tbs,
            &algorithm,
            &der::bit_string(&signature),
        ]))
    }

    pub fn der(&self) -> &[u8] {
        &self.der
    }

    pub fn to_pem(&self) -> String {
        pem::encode("CERTIFICATE", &self.der)
    }

    /// The RSA public key the certificate carries.
    pub fn public_key(&self) -> Result<RsaPublicKey> {
        let parts = parse(&self.der)?;
        let spki = der::read_children(parts.spki.content)?;
        let [algorithm, key_bits] = spki[..] else {
            bail!("malformed SubjectPublicKeyInfo");
        };
        let algorithm_fields = der::read_children(algorithm.content)?;
        if algorithm_fields.first().map(|f| f.raw) != Some(&der::oid(OID_RSA_ENCRYPTION)[..]) {
            bail!("certificate key is not RSA");
        }
        der::expect_tag(&key_bits, der::TAG_BIT_STRING)?;
        let (&unused_bits, rsa_der) = key_bits
            .content
            .split_first()
            .ok_or_else(|| anyhow!("empty public key BIT STRING"))?;
        if unused_bits != 0 {
            bail!("public key BIT STRING has unused bits");
        }
        RsaPublicKey::from_pkcs1_der(rsa_der).map_err(|_| anyhow!("malformed RSA public key"))
    }

    /// Whether this certificate carries `key`'s public key.
    pub fn matches_key(&self, key: &OtaSigningKey) -> bool {
        self.public_key()
            .is_ok_and(|public| public == key.public_key())
    }

    /// A copy with the selected fields emptied. The result is no longer a
    /// validly signed certificate, which Android's OTA verifiers never check.
    pub(crate) fn stripped(&self, strip: Strip) -> Result<Self> {
        let parts = parse(&self.der)?;
        let empty_name = der::sequence(&[]);
        let issuer = if strip.issuer {
            &empty_name[..]
        } else {
            parts.issuer.raw
        };
        let subject = if strip.subject {
            &empty_name[..]
        } else {
            parts.subject.raw
        };
        let mut fields: Vec<&[u8]> = Vec::new();
        if let Some(version) = &parts.version {
            fields.push(version.raw);
        }
        fields.extend([
            parts.serial.raw,
            parts.tbs_signature.raw,
            issuer,
            parts.validity.raw,
            subject,
            parts.spki.raw,
        ]);
        if let Some(uid) = parts.issuer_uid.filter(|_| !strip.issuer) {
            fields.push(uid.raw);
        }
        if let Some(uid) = parts.subject_uid.filter(|_| !strip.subject) {
            fields.push(uid.raw);
        }
        if let Some(extensions) = parts.extensions.filter(|_| !strip.extensions) {
            fields.push(extensions.raw);
        }
        let tbs = der::sequence(&fields);
        let signature = if strip.signature {
            der::bit_string(&[])
        } else {
            parts.signature.raw.to_vec()
        };
        Self::from_der(der::sequence(&[
            &tbs,
            parts.signature_algorithm.raw,
            &signature,
        ]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::tests::test_key;

    /// 2026-09-27 00:00:00 UTC.
    const NOW: i64 = 1_790_467_200;

    #[test]
    fn self_signed_certificate_carries_key_and_verifies() {
        let key = test_key(2048);
        let cert = Certificate::self_signed(&key, "DynoBox OTA", NOW).unwrap();
        assert!(cert.matches_key(&key));
        assert!(!cert.matches_key(&test_key(4096)));

        // The self-signature covers the TBS bytes.
        let outer = der::read_single(cert.der(), der::TAG_SEQUENCE).unwrap();
        let top = der::read_children(outer.content).unwrap();
        let signature = &top[2].content[1..];
        let digest: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(top[0].raw).into();
        key::verify_digest(&key.public_key(), &digest, signature).unwrap();

        let reparsed = Certificate::from_pem_or_der(cert.to_pem().as_bytes()).unwrap();
        assert_eq!(reparsed, cert);
    }

    #[test]
    fn x509_time_switches_to_generalized_after_2049() {
        assert_eq!(x509_time(NOW), der::encode(0x17, b"260927000000Z"));
        assert_eq!(
            x509_time(2_556_144_000),
            der::encode(0x18, b"20510101000000Z")
        );
    }

    #[test]
    fn stripping_keeps_the_public_key() {
        let key = test_key(4096);
        let cert = Certificate::self_signed(&key, "DynoBox OTA", NOW).unwrap();
        let all = Strip {
            signature: true,
            extensions: true,
            issuer: true,
            subject: true,
        };
        let stripped = cert.stripped(all).unwrap();
        assert!(stripped.der().len() < cert.der().len() - 500);
        assert!(stripped.matches_key(&key));
        assert_eq!(cert.stripped(Strip::default()).unwrap(), cert);
    }

    #[test]
    fn parser_survives_mutated_input() {
        let cert = Certificate::self_signed(&test_key(2048), "DynoBox OTA", NOW).unwrap();
        dynobox_core::testutil::for_each_mutation(cert.der(), 0xCE27, 3000, |bytes| {
            if let Ok(cert) = Certificate::from_der(bytes.to_vec()) {
                let _ = cert.public_key();
                let _ = cert.stripped(Strip {
                    issuer: true,
                    ..Strip::default()
                });
            }
        });
    }
}
