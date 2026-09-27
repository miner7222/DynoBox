//! Assemble and sign an A/B OTA package.
//!
//! Entry order: `payload.bin`, `payload_properties.txt`, optional extras
//! (`apex_info.pb`, `care_map.pb`), `META-INF/com/android/otacert`, then the
//! metadata pair. The metadata lists every entry's offset and size
//! (`ota-property-files`) so update_engine can stream the payload; since it
//! also lists itself, it is written once with space-padded placeholders to
//! fix its length, then filled in.

use std::collections::BTreeMap;
use std::fs::File;
use std::path::Path;

use anyhow::{Context, Result, bail};
use prost::Message;

use crate::cert::Certificate;
use crate::key::OtaSigningKey;
use crate::metadata::{OtaMetadata, PATH_METADATA, PATH_METADATA_PB};
use crate::payload::PayloadSummary;
use crate::zipsig;
use crate::zipwriter::ZipWriter;

pub const PATH_PAYLOAD: &str = "payload.bin";
pub const PATH_PROPERTIES: &str = "payload_properties.txt";
pub const PATH_OTACERT: &str = "META-INF/com/android/otacert";
pub const PF_NAME: &str = "ota-property-files";
pub const PF_STREAMING_NAME: &str = "ota-streaming-property-files";
const NAME_PAYLOAD_METADATA: &str = "payload_metadata.bin";

/// Optional entries listed in property files, in AOSP order.
const OPTIONAL_LISTED: [&str; 2] = ["apex_info.pb", "care_map.pb"];
/// Room for `<offset>:<size>` of each self-referencing metadata entry.
const RESERVATION: usize = 16;

/// A small entry copied into the package verbatim.
#[derive(Debug, Clone)]
pub struct ExtraEntry {
    pub name: String,
    pub data: Vec<u8>,
}

/// Everything needed to write an OTA package around a signed payload.
pub struct PackageSpec<'a> {
    pub payload: &'a Path,
    pub payload_summary: &'a PayloadSummary,
    pub extras: Vec<ExtraEntry>,
    /// Package metadata; `property_files` is replaced.
    pub metadata: OtaMetadata,
}

fn basename(path: &str) -> &str {
    path.rsplit_once('/').map_or(path, |(_, name)| name)
}

/// `name:offset:size` list in AOSP order. `metadata_entries` is `None` for
/// the placeholder pass.
fn property_files(
    key: &str,
    listed: &BTreeMap<&str, (u64, u64)>,
    metadata_entries: Option<[(u64, u64); 2]>,
) -> String {
    let mut parts = Vec::new();
    let mut push = |name: &str| {
        if let Some((offset, size)) = listed.get(name) {
            parts.push(format!("{name}:{offset}:{size}"));
        }
    };
    if key == PF_NAME {
        push(NAME_PAYLOAD_METADATA);
    }
    push(PATH_PAYLOAD);
    push(PATH_PROPERTIES);
    for name in OPTIONAL_LISTED {
        push(name);
    }
    let meta_names = [basename(PATH_METADATA), basename(PATH_METADATA_PB)];
    match metadata_entries {
        None => {
            for name in meta_names {
                parts.push(format!("{name}:{}", " ".repeat(RESERVATION)));
            }
        }
        Some(entries) => {
            for (name, (offset, size)) in meta_names.into_iter().zip(entries) {
                parts.push(format!("{name}:{offset}:{size}"));
            }
        }
    }
    parts.join(",")
}

/// Write `spec` to `out` (which must not exist) and sign it. Returns the
/// final metadata, property files included.
pub fn write_package(
    out: &Path,
    spec: PackageSpec<'_>,
    key: &OtaSigningKey,
    certificate: &Certificate,
) -> Result<OtaMetadata> {
    if !certificate.matches_key(key) {
        bail!("the OTA certificate does not belong to the signing key");
    }
    let file = File::options()
        .read(true)
        .write(true)
        .create_new(true)
        .open(out)
        .with_context(|| format!("creating {}", out.display()))?;
    let mut writer = ZipWriter::new(file);
    let mut listed: BTreeMap<&str, (u64, u64)> = BTreeMap::new();

    let payload_size = std::fs::metadata(spec.payload)?.len();
    if payload_size != spec.payload_summary.file_size {
        bail!("payload.bin size does not match its summary");
    }
    let mut payload = File::open(spec.payload)?;
    let payload_offset = writer.add_reader(PATH_PAYLOAD, &mut payload, payload_size)?;
    listed.insert(PATH_PAYLOAD, (payload_offset, payload_size));
    listed.insert(
        NAME_PAYLOAD_METADATA,
        (payload_offset, spec.payload_summary.blob_offset),
    );
    let properties = spec.payload_summary.properties.as_bytes();
    let offset = writer.add_bytes(PATH_PROPERTIES, properties)?;
    listed.insert(PATH_PROPERTIES, (offset, properties.len() as u64));

    let mut extras = spec.extras;
    extras.sort_by_key(|e| {
        OPTIONAL_LISTED
            .iter()
            .position(|n| *n == e.name)
            .unwrap_or(usize::MAX)
    });
    for extra in &extras {
        if [
            PATH_PAYLOAD,
            PATH_PROPERTIES,
            PATH_OTACERT,
            PATH_METADATA,
            PATH_METADATA_PB,
        ]
        .contains(&extra.name.as_str())
        {
            bail!("extra entry {} collides with a generated entry", extra.name);
        }
        let offset = writer.add_bytes(&extra.name, &extra.data)?;
        if let Some(name) = OPTIONAL_LISTED.iter().find(|n| **n == extra.name) {
            listed.insert(name, (offset, extra.data.len() as u64));
        }
    }
    writer.add_bytes(PATH_OTACERT, certificate.to_pem().as_bytes())?;

    // Pass 1: placeholders fix the metadata sizes and therefore offsets.
    let mut metadata = spec.metadata;
    metadata.property_files = [PF_NAME, PF_STREAMING_NAME]
        .into_iter()
        .map(|k| (k.to_string(), property_files(k, &listed, None)))
        .collect();
    let legacy_len = metadata.to_legacy_text().len() as u64;
    let pb_len = metadata.encoded_len() as u64;
    let legacy_offset = writer.position() + ZipWriter::local_header_len(PATH_METADATA, legacy_len);
    let pb_offset =
        legacy_offset + legacy_len + ZipWriter::local_header_len(PATH_METADATA_PB, pb_len);

    // Pass 2: real offsets, padded to the placeholder length.
    for (key, value) in &mut metadata.property_files {
        let actual = property_files(
            key,
            &listed,
            Some([(legacy_offset, legacy_len), (pb_offset, pb_len)]),
        );
        if actual.len() > value.len() {
            bail!("property files outgrew their reservation: {actual}");
        }
        *value = format!("{actual:<width$}", width = value.len());
    }
    let legacy = metadata.to_legacy_text();
    let pb = metadata.encode_to_vec();
    assert_eq!((legacy.len() as u64, pb.len() as u64), (legacy_len, pb_len));
    assert_eq!(
        writer.add_bytes(PATH_METADATA, legacy.as_bytes())?,
        legacy_offset
    );
    assert_eq!(writer.add_bytes(PATH_METADATA_PB, &pb)?, pb_offset);

    let mut file = writer.finish()?;
    zipsig::sign_zip(&mut file, key, certificate)?;
    Ok(metadata)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn property_files_follow_the_aosp_order() {
        let listed = BTreeMap::from([
            (NAME_PAYLOAD_METADATA, (100, 50)),
            (PATH_PAYLOAD, (100, 900)),
            (PATH_PROPERTIES, (1100, 155)),
            ("care_map.pb", (1300, 40)),
            ("apex_info.pb", (1260, 30)),
        ]);
        assert_eq!(
            property_files(PF_NAME, &listed, Some([(1400, 9), (1500, 8)])),
            "payload_metadata.bin:100:50,payload.bin:100:900,payload_properties.txt:1100:155,\
             apex_info.pb:1260:30,care_map.pb:1300:40,metadata:1400:9,metadata.pb:1500:8"
        );
        assert!(!property_files(PF_STREAMING_NAME, &listed, None).contains(NAME_PAYLOAD_METADATA));
    }
}
