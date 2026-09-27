//! Detached CMS `SignedData` in the exact shape AOSP `signapk -w` emits.
//!
//! Recovery and the framework's `RecoverySystem` use the structure purely as
//! a transport for one certificate and one raw RSA signature: there are no
//! signed attributes, and the signature is PKCS#1 v1.5 over the SHA-256 of
//! the signed bytes.

use crate::cert::Certificate;
use crate::der::{self, Tlv};
use crate::key::{self, OtaSigningKey};
use anyhow::{Result, anyhow, bail};

const OID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";
const OID_DATA: &str = "1.2.840.113549.1.7.1";
const OID_SHA256: &str = "2.16.840.1.101.3.4.2.1";
const OID_RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";
const OID_SHA256_WITH_RSA: &str = "1.2.840.113549.1.1.11";

/// Signature and certificate extracted from a `SignedData`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedDigest {
    pub certificate: Certificate,
    pub signature: Vec<u8>,
}

impl SignedDigest {
    /// Verify the signature over `digest` with the embedded certificate's key.
    pub fn verify(&self, digest: &[u8; 32]) -> Result<()> {
        key::verify_digest(&self.certificate.public_key()?, digest, &self.signature)
    }
}

/// Sign `digest` and wrap it as a detached `ContentInfo(SignedData)`.
pub fn sign_detached(
    key: &OtaSigningKey,
    certificate: &Certificate,
    digest: &[u8; 32],
) -> Result<Vec<u8>> {
    if !certificate.matches_key(key) {
        bail!("the OTA certificate does not belong to the signing key");
    }
    let (issuer, serial) = certificate.issuer_and_serial()?;
    let sha256 = der::sequence(&[&der::oid(OID_SHA256)]);
    let signer_info = der::sequence(&[
        &der::unsigned_integer(&[1]),
        &der::sequence(&[&issuer, &serial]),
        &sha256,
        &der::sequence(&[&der::oid(OID_RSA_ENCRYPTION), &der::null()]),
        &der::encode(der::TAG_OCTET_STRING, &key.sign_digest(digest)?),
    ]);
    let signed_data = der::sequence(&[
        &der::unsigned_integer(&[1]),
        &der::constructed(der::TAG_SET, &[&sha256]),
        &der::sequence(&[&der::oid(OID_DATA)]),
        &der::constructed(0xA0, &[certificate.der()]),
        &der::constructed(der::TAG_SET, &[&signer_info]),
    ]);
    Ok(der::sequence(&[
        &der::oid(OID_SIGNED_DATA),
        &der::constructed(0xA0, &[&signed_data]),
    ]))
}

fn expect_oid(tlv: &Tlv<'_>, dotted: &str, what: &str) -> Result<()> {
    if tlv.raw != der::oid(dotted) {
        bail!("CMS {what} is not {dotted}");
    }
    Ok(())
}

/// First element of an `AlgorithmIdentifier`.
fn algorithm_oid<'a>(identifier: &Tlv<'a>) -> Result<Tlv<'a>> {
    der::expect_tag(identifier, der::TAG_SEQUENCE)?;
    der::read_children(identifier.content)?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("empty CMS AlgorithmIdentifier"))
}

/// Parse a detached `SignedData` with one certificate and one SHA-256 RSA
/// signer, as `signapk -w` produces.
pub fn parse_detached(content_info: &[u8]) -> Result<SignedDigest> {
    let outer = der::read_single(content_info, der::TAG_SEQUENCE)?;
    let top = der::read_children(outer.content)?;
    let [content_type, explicit] = top[..] else {
        bail!("CMS ContentInfo must have 2 fields");
    };
    expect_oid(&content_type, OID_SIGNED_DATA, "content type")?;
    der::expect_tag(&explicit, 0xA0)?;
    let signed_data = der::read_single(explicit.content, der::TAG_SEQUENCE)?;
    let fields = der::read_children(signed_data.content)?;
    let [_version, _digests, encap, certificates, signer_infos] = fields[..] else {
        bail!("CMS SignedData must have version, digests, content, certificates, signers");
    };
    let encap_fields = der::read_children(encap.content)?;
    if encap_fields.len() != 1 {
        bail!("CMS content must be detached");
    }
    expect_oid(&encap_fields[0], OID_DATA, "encapsulated content type")?;
    der::expect_tag(&certificates, 0xA0)?;
    let certs = der::read_children(certificates.content)?;
    let [certificate] = certs[..] else {
        bail!(
            "CMS must carry exactly one certificate, found {}",
            certs.len()
        );
    };
    der::expect_tag(&signer_infos, der::TAG_SET)?;
    let signers = der::read_children(signer_infos.content)?;
    let [signer] = signers[..] else {
        bail!("CMS must have exactly one signer, found {}", signers.len());
    };
    let signer_fields = der::read_children(signer.content)?;
    let [
        _version,
        _sid,
        digest_algorithm,
        signature_algorithm,
        signature,
    ] = signer_fields[..]
    else {
        bail!("CMS SignerInfo has signed attributes or an unexpected shape");
    };
    expect_oid(
        &algorithm_oid(&digest_algorithm)?,
        OID_SHA256,
        "digest algorithm",
    )?;
    let signature_oid = algorithm_oid(&signature_algorithm)?;
    if signature_oid.raw != der::oid(OID_RSA_ENCRYPTION)
        && signature_oid.raw != der::oid(OID_SHA256_WITH_RSA)
    {
        bail!("CMS signature algorithm is not RSA");
    }
    der::expect_tag(&signature, der::TAG_OCTET_STRING)?;
    Ok(SignedDigest {
        certificate: Certificate::from_der(certificate.raw.to_vec())?,
        signature: signature.content.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::tests::test_key;

    const NOW: i64 = 1_790_467_200;

    fn sha256(data: &[u8]) -> [u8; 32] {
        <sha2::Sha256 as sha2::Digest>::digest(data).into()
    }

    #[test]
    fn sign_then_parse_round_trips_and_verifies() {
        let key = test_key(2048);
        let cert = Certificate::self_signed(&key, "DynoBox OTA", NOW).unwrap();
        let digest = sha256(b"signed zip bytes");
        let cms = sign_detached(&key, &cert, &digest).unwrap();
        let parsed = parse_detached(&cms).unwrap();
        assert_eq!(parsed.certificate, cert);
        parsed.verify(&digest).unwrap();
        assert!(parsed.verify(&sha256(b"other bytes")).is_err());
    }

    #[test]
    fn refuses_a_certificate_from_another_key() {
        let cert = Certificate::self_signed(&test_key(2048), "DynoBox OTA", NOW).unwrap();
        assert!(sign_detached(&test_key(4096), &cert, &[0; 32]).is_err());
    }

    #[test]
    fn parser_survives_mutated_input() {
        let key = test_key(2048);
        let cert = Certificate::self_signed(&key, "DynoBox OTA", NOW).unwrap();
        let cms = sign_detached(&key, &cert, &[7; 32]).unwrap();
        dynobox_core::testutil::for_each_mutation(&cms, 0xC5C5, 3000, |bytes| {
            if let Ok(parsed) = parse_detached(bytes) {
                let _ = parsed.verify(&[7; 32]);
            }
        });
    }
}
