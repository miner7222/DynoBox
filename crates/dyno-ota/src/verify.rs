//! End-to-end OTA package verification, mirroring what recovery,
//! `RecoverySystem` and update_engine check before installing.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use dynobox_payload::payload::proto::DeltaArchiveManifest;

use crate::cert::Certificate;
use crate::metadata::{OtaMetadata, PATH_METADATA, PATH_METADATA_PB};
use crate::package::{PATH_OTACERT, PATH_PAYLOAD, PATH_PROPERTIES, PF_NAME, PF_STREAMING_NAME};
use crate::payload;
use crate::zipsig;

/// What a verified package contains.
#[derive(Debug, Clone)]
pub struct VerifiedPackage {
    /// Certificate that signed the package and its payload.
    pub signer: Certificate,
    pub metadata: OtaMetadata,
    pub manifest: DeltaArchiveManifest,
}

fn read_entry(zip: &mut zip::ZipArchive<File>, name: &str) -> Result<Vec<u8>> {
    let mut entry = zip
        .by_name(name)
        .with_context(|| format!("OTA package has no {name}"))?;
    let mut out = Vec::new();
    entry.read_to_end(&mut out)?;
    Ok(out)
}

/// Verify `path`. With `trusted`, the signer must carry that certificate's
/// public key (as the device's `otacerts.zip` would require).
pub fn verify_package(path: &Path, trusted: Option<&Certificate>) -> Result<VerifiedPackage> {
    let mut file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let signer = zipsig::verify_zip(&mut file)?.certificate;
    let signer_key = signer.public_key()?;
    if let Some(trusted) = trusted {
        if trusted.public_key()? != signer_key {
            bail!("the package is signed by a key the given certificate does not trust");
        }
    }

    let mut zip = zip::ZipArchive::new(File::open(path)?).context("reading the OTA zip")?;
    let otacert = Certificate::from_pem_or_der(&read_entry(&mut zip, PATH_OTACERT)?)?;
    if otacert.public_key()? != signer_key {
        bail!("{PATH_OTACERT} is not the package signer's certificate");
    }

    let metadata = OtaMetadata::decode_pb(&read_entry(&mut zip, PATH_METADATA_PB)?)?;
    let legacy = String::from_utf8(read_entry(&mut zip, PATH_METADATA)?)
        .context("legacy metadata is not UTF-8")?;
    if legacy != metadata.to_legacy_text() {
        bail!("{PATH_METADATA} and {PATH_METADATA_PB} disagree");
    }

    let (payload_start, payload_len) = {
        let entry = zip
            .by_name(PATH_PAYLOAD)
            .context("OTA package has no payload.bin")?;
        if entry.compression() != zip::CompressionMethod::Stored {
            bail!("payload.bin must be stored uncompressed");
        }
        let start = entry
            .data_start()
            .ok_or_else(|| anyhow!("payload.bin data offset unknown"))?;
        (start, entry.size())
    };
    let properties = String::from_utf8(read_entry(&mut zip, PATH_PROPERTIES)?)
        .context("payload_properties.txt is not UTF-8")?;
    let verified = payload::verify_payload(
        &mut file,
        payload_start,
        payload_len,
        &signer_key,
        Some(&properties),
    )?;

    for key in [PF_NAME, PF_STREAMING_NAME] {
        let value = metadata
            .property_files
            .get(key)
            .ok_or_else(|| anyhow!("metadata has no {key}"))?;
        for item in value.trim_end().split(',') {
            let mut fields = item.split(':');
            let (Some(name), Some(offset), Some(size), None) =
                (fields.next(), fields.next(), fields.next(), fields.next())
            else {
                bail!("malformed {key} entry {item:?}");
            };
            let (offset, size): (u64, u64) = (
                offset.parse().context("property-files offset")?,
                size.parse().context("property-files size")?,
            );
            let expected = if name == "payload_metadata.bin" {
                (payload_start, verified.blob_offset)
            } else {
                let path = if name.starts_with("metadata") {
                    format!("META-INF/com/android/{name}")
                } else {
                    name.to_string()
                };
                let entry = zip
                    .by_name(&path)
                    .with_context(|| format!("{key} lists missing entry {name}"))?;
                (
                    entry
                        .data_start()
                        .ok_or_else(|| anyhow!("{name} offset unknown"))?,
                    entry.compressed_size(),
                )
            };
            if (offset, size) != expected {
                bail!(
                    "{key} says {name} is at {offset}+{size}, the zip has {}+{}",
                    expected.0,
                    expected.1
                );
            }
        }
    }

    Ok(VerifiedPackage {
        signer,
        metadata,
        manifest: verified.manifest,
    })
}
