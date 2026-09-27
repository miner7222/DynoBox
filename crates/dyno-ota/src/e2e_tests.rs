//! Full OTA round trip: encode partitions, sign payload and package, verify,
//! then apply the payload with DynoBox's update_engine-compatible patcher.

use std::fs::File;
use std::io::BufWriter;

use dynobox_payload::payload::proto::{
    DeltaArchiveManifest, DynamicPartitionGroup, DynamicPartitionMetadata, PartitionInfo,
    PartitionUpdate,
};

use crate::key::tests::test_key;
use crate::metadata::{DeviceState, OtaMetadata, OtaType};
use crate::package::{ExtraEntry, PackageSpec, write_package};
use crate::payload::write_signed_payload;
use crate::verify::verify_package;
use crate::{Certificate, full};

fn image(len: usize, seed: u32) -> Vec<u8> {
    let mut state = seed;
    (0..len)
        .map(|i| {
            if i % 8192 < 4096 {
                return (i / 4096) as u8;
            }
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect()
}

#[test]
fn full_ota_round_trips_through_sign_verify_and_apply() {
    let dir = tempfile::tempdir().unwrap();
    let key = test_key(2048);
    let cert = Certificate::self_signed(&key, "DynoBox OTA", 1_790_467_200).unwrap();
    let images = [("boot", image(3 << 20, 7)), ("system", image(5 << 20, 9))];

    let blob_path = dir.path().join("blobs.bin");
    let mut blobs = BufWriter::new(File::create(&blob_path).unwrap());
    let mut partitions = Vec::new();
    for (name, data) in &images {
        let encoded =
            full::encode_partition(&mut &data[..], data.len() as u64, 4096, &mut blobs, |_| {})
                .unwrap();
        partitions.push(PartitionUpdate {
            partition_name: name.to_string(),
            new_partition_info: Some(PartitionInfo {
                size: Some(data.len() as u64),
                hash: Some(encoded.hash.to_vec()),
            }),
            operations: encoded.operations,
            ..Default::default()
        });
    }
    drop(blobs);
    let manifest = DeltaArchiveManifest {
        block_size: Some(4096),
        minor_version: Some(0),
        partitions,
        max_timestamp: Some(1_788_553_589),
        dynamic_partition_metadata: Some(DynamicPartitionMetadata {
            groups: vec![DynamicPartitionGroup {
                name: "qti_dynamic_partitions".into(),
                size: Some(64 << 20),
                partition_names: vec!["system".into()],
            }],
            snapshot_enabled: Some(true),
            ..Default::default()
        }),
        ..Default::default()
    };

    let payload_path = dir.path().join("payload.bin");
    let summary = write_signed_payload(
        &mut BufWriter::new(File::create(&payload_path).unwrap()),
        manifest,
        &mut File::open(&blob_path).unwrap(),
        &key,
    )
    .unwrap();

    let ota_path = dir.path().join("ota.zip");
    let metadata = OtaMetadata {
        r#type: OtaType::Ab as i32,
        precondition: Some(DeviceState {
            device: vec!["TB324ZC".into()],
            ..Default::default()
        }),
        postcondition: Some(DeviceState {
            build: vec!["Lenovo/TB324ZC/TB324ZC:16/B/1:user/release-keys".into()],
            timestamp: 1_788_553_589,
            ..Default::default()
        }),
        ..Default::default()
    };
    let written = write_package(
        &ota_path,
        PackageSpec {
            payload: &payload_path,
            payload_summary: &summary,
            extras: vec![ExtraEntry {
                name: "care_map.pb".into(),
                data: vec![1, 2, 3],
            }],
            metadata,
        },
        &key,
        &cert,
    )
    .unwrap();
    assert!(written.property_files["ota-property-files"].contains("care_map.pb:"));

    // Trusted by the right certificate only.
    let verified = verify_package(&ota_path, Some(&cert)).unwrap();
    assert_eq!(verified.manifest.partitions.len(), 2);
    let stranger = Certificate::self_signed(&test_key(4096), "x", 0).unwrap();
    assert!(verify_package(&ota_path, Some(&stranger)).is_err());

    // The payload reproduces every partition byte for byte.
    let empty = dir.path().join("empty.img");
    File::create(&empty).unwrap();
    for (name, data) in &images {
        let out = dir.path().join(format!("{name}.img"));
        dynobox_payload::apply_partition_payload(&payload_path, name, &empty, &out, 4096).unwrap();
        assert_eq!(&std::fs::read(&out).unwrap(), data, "{name}");
    }

    // Any byte flip in the package breaks verification.
    let mut bytes = std::fs::read(&ota_path).unwrap();
    let middle = bytes.len() / 2;
    bytes[middle] ^= 1;
    let tampered = dir.path().join("tampered.zip");
    std::fs::write(&tampered, bytes).unwrap();
    assert!(verify_package(&tampered, None).is_err());
}
