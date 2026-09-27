//! OTA package metadata: `META-INF/com/android/metadata.pb` (the
//! `build.tools.releasetools.OtaMetadata` protobuf from AOSP's
//! `ota_metadata.proto`) and its legacy `key=value` text twin.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use anyhow::{Context, Result};
use prost::Message;

pub const PATH_METADATA: &str = "META-INF/com/android/metadata";
pub const PATH_METADATA_PB: &str = "META-INF/com/android/metadata.pb";

/// `OtaMetadata.OtaType`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum OtaType {
    Unknown = 0,
    Ab = 1,
    Block = 2,
    Brick = 3,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct PartitionState {
    #[prost(string, tag = "1")]
    pub partition_name: String,
    #[prost(string, repeated, tag = "2")]
    pub device: Vec<String>,
    #[prost(string, repeated, tag = "3")]
    pub build: Vec<String>,
    #[prost(string, tag = "4")]
    pub version: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct DeviceState {
    #[prost(string, repeated, tag = "1")]
    pub device: Vec<String>,
    #[prost(string, repeated, tag = "2")]
    pub build: Vec<String>,
    #[prost(string, tag = "3")]
    pub build_incremental: String,
    #[prost(int64, tag = "4")]
    pub timestamp: i64,
    #[prost(string, tag = "5")]
    pub sdk_level: String,
    #[prost(string, tag = "6")]
    pub security_patch_level: String,
    #[prost(message, repeated, tag = "7")]
    pub partition_state: Vec<PartitionState>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct OtaMetadata {
    #[prost(enumeration = "OtaType", tag = "1")]
    pub r#type: i32,
    #[prost(bool, tag = "2")]
    pub wipe: bool,
    #[prost(bool, tag = "3")]
    pub downgrade: bool,
    #[prost(btree_map = "string, string", tag = "4")]
    pub property_files: BTreeMap<String, String>,
    #[prost(message, optional, tag = "5")]
    pub precondition: Option<DeviceState>,
    #[prost(message, optional, tag = "6")]
    pub postcondition: Option<DeviceState>,
    #[prost(int64, tag = "8")]
    pub required_cache: i64,
    #[prost(bool, tag = "9")]
    pub spl_downgrade: bool,
}

impl OtaMetadata {
    pub fn decode_pb(bytes: &[u8]) -> Result<Self> {
        Self::decode(bytes).context("decoding OTA metadata.pb")
    }

    /// The legacy `META-INF/com/android/metadata` text, one sorted
    /// `key=value` per line as AOSP's `ota_utils.py` writes it.
    pub fn to_legacy_text(&self) -> String {
        let mut pairs = BTreeMap::<String, String>::new();
        match OtaType::try_from(self.r#type) {
            Ok(OtaType::Ab) => {
                pairs.insert("ota-type".into(), "AB".into());
            }
            Ok(OtaType::Block) => {
                pairs.insert("ota-type".into(), "BLOCK".into());
            }
            _ => {}
        }
        if self.wipe {
            pairs.insert("ota-wipe".into(), "yes".into());
        }
        if self.downgrade {
            pairs.insert("ota-downgrade".into(), "yes".into());
        }
        pairs.insert("ota-required-cache".into(), self.required_cache.to_string());
        if let Some(post) = &self.postcondition {
            pairs.insert("post-build".into(), post.build.join("|"));
            pairs.insert(
                "post-build-incremental".into(),
                post.build_incremental.clone(),
            );
            pairs.insert("post-sdk-level".into(), post.sdk_level.clone());
            pairs.insert(
                "post-security-patch-level".into(),
                post.security_patch_level.clone(),
            );
            pairs.insert("post-timestamp".into(), post.timestamp.to_string());
        }
        if let Some(pre) = &self.precondition {
            pairs.insert("pre-device".into(), pre.device.join("|"));
            if !pre.build.is_empty() {
                pairs.insert("pre-build".into(), pre.build.join("|"));
                pairs.insert(
                    "pre-build-incremental".into(),
                    pre.build_incremental.clone(),
                );
            }
        }
        if self.spl_downgrade {
            pairs.insert("spl-downgrade".into(), "yes".into());
        }
        pairs.extend(self.property_files.clone());
        pairs
            .into_iter()
            .fold(String::new(), |mut out, (key, value)| {
                let _ = writeln!(out, "{key}={value}");
                out
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> OtaMetadata {
        OtaMetadata {
            r#type: OtaType::Ab as i32,
            property_files: BTreeMap::from([(
                "ota-streaming-property-files".to_string(),
                "payload.bin:10:20".to_string(),
            )]),
            precondition: Some(DeviceState {
                device: vec!["TB324ZC".into()],
                build: vec!["Lenovo/TB324ZC/TB324ZC:16/A/1:user/release-keys".into()],
                build_incremental: "1".into(),
                ..Default::default()
            }),
            postcondition: Some(DeviceState {
                build: vec!["Lenovo/TB324ZC/TB324ZC:16/A/2:user/release-keys".into()],
                build_incremental: "2".into(),
                timestamp: 1_788_553_589,
                sdk_level: "36".into(),
                security_patch_level: "2026-08-05".into(),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn protobuf_round_trips() {
        let metadata = sample();
        let decoded = OtaMetadata::decode_pb(&metadata.encode_to_vec()).unwrap();
        assert_eq!(decoded, metadata);
    }

    #[test]
    fn legacy_text_matches_the_aosp_layout() {
        assert_eq!(
            sample().to_legacy_text(),
            "ota-required-cache=0\n\
             ota-streaming-property-files=payload.bin:10:20\n\
             ota-type=AB\n\
             post-build=Lenovo/TB324ZC/TB324ZC:16/A/2:user/release-keys\n\
             post-build-incremental=2\n\
             post-sdk-level=36\n\
             post-security-patch-level=2026-08-05\n\
             post-timestamp=1788553589\n\
             pre-build=Lenovo/TB324ZC/TB324ZC:16/A/1:user/release-keys\n\
             pre-build-incremental=1\n\
             pre-device=TB324ZC\n"
        );
    }

    /// The official Lenovo metadata.pb must decode, and re-serializing its
    /// legacy text must reproduce the shipped `metadata` file.
    #[test]
    #[ignore = "fixture: set DYNOBOX_OTA_ZIP"]
    fn reproduces_an_official_legacy_metadata() {
        use std::io::Read;
        let path = std::env::var("DYNOBOX_OTA_ZIP").expect("set DYNOBOX_OTA_ZIP");
        let mut zip = zip::ZipArchive::new(std::fs::File::open(path).unwrap()).unwrap();
        let mut read = |name: &str| {
            let mut out = Vec::new();
            zip.by_name(name).unwrap().read_to_end(&mut out).unwrap();
            out
        };
        let (pb, legacy) = (read(PATH_METADATA_PB), read(PATH_METADATA));
        let metadata = OtaMetadata::decode_pb(&pb).unwrap();
        assert_eq!(
            metadata.to_legacy_text(),
            String::from_utf8(legacy).unwrap()
        );
    }
}
