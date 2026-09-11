#[cfg(test)]
mod tests {
    use crate::{extract_partition_images, parse_super_layout};
    use dynobox_xml::XmlCatalog;
    use std::path::Path;

    #[test]
    fn test_real_super_parsing_and_unpack() -> dynobox_core::error::Result<()> {
        let test_dir = Path::new(r"D:\Git\Project-LTBOX\TB322_ZUXOS_1.5.10.183_resigned");

        if !test_dir.exists() {
            println!("Skipping real super parsing test because test directory does not exist.");
            return Ok(());
        }

        // 1. Discover and parse XML catalog
        let catalog = XmlCatalog::from_dir(test_dir)?;
        let super_group = catalog.group_by_base_label(true).remove("super");

        assert!(
            super_group.is_some(),
            "Should find super partition group with files"
        );
        let super_group = super_group.unwrap();

        // 2. Parse super layout
        let records: Vec<_> = super_group.records().into_iter().cloned().collect();
        let layout = parse_super_layout(&records, test_dir)?;

        println!("Found Super Layout: {:?}", layout.geometry);
        println!("Dynamic partitions: {:?}", layout.dynamic_partition_names());

        assert!(!layout.chunks.is_empty(), "Should have found super chunks");
        assert!(
            !layout.partitions.is_empty(),
            "Should have found partitions in metadata"
        );

        // 3. Extract specific dynamic partitions to a temp directory
        let temp_out = tempfile::tempdir()?;
        let targets = vec!["vendor".to_string()]; // Just extract one small one to save time

        let extracted = extract_partition_images(&layout, temp_out.path(), Some(&targets))?;

        assert!(
            extracted.contains_key("vendor"),
            "Vendor should be extracted"
        );
        let vendor_img = extracted.get("vendor").unwrap();
        assert!(
            vendor_img.exists(),
            "Extracted vendor.img should exist on disk"
        );

        println!("Successfully extracted vendor to: {}", vendor_img.display());

        Ok(())
    }

    /// OEM layouts may name the split chunks after the logical partitions they
    /// carry (e.g. ALLDOCUBE U880: `system.img` is a `label="super"` chunk).
    /// After an OTA resizes a partition, the patched standalone image replaces
    /// the chunk and no longer matches the XML size. Repack only needs the
    /// metadata chunk, so its parser must accept the resized record while the
    /// strict parser keeps refusing it.
    #[test]
    fn repack_layout_accepts_chunks_replaced_by_resized_partitions()
    -> dynobox_core::error::Result<()> {
        use crate::metadata::{
            LP_TARGET_TYPE_LINEAR, SuperBlockDevice, SuperExtent, SuperGeometry, SuperGroup,
            SuperLayout, SuperPartition,
        };
        use crate::{parse_super_layout_for_repack, serialize_metadata};
        use dynobox_xml::PartitionRecord;

        fn record(filename: &str, start_sector: u64, num_sectors: u64) -> PartitionRecord {
            PartitionRecord {
                label: "super".to_string(),
                filename: filename.to_string(),
                lun: None,
                start_sector: Some(start_sector.to_string()),
                num_sectors: Some(num_sectors.to_string()),
                source_xml: "rawprogram_all.xml".to_string(),
                size_in_kb: None,
                sector_size_bytes: Some("4096".to_string()),
            }
        }

        let temp = tempfile::tempdir()?;
        let metadata_prefix = serialize_metadata(&SuperLayout {
            geometry: SuperGeometry {
                metadata_max_size: 4096,
                metadata_slot_count: 2,
                logical_block_size: 4096,
            },
            header_flags: 0,
            block_devices: vec![SuperBlockDevice {
                name: "super".to_string(),
                size: 4096 * 1024,
            }],
            groups: vec![SuperGroup {
                name: "default".to_string(),
                maximum_size: 4096 * 1024,
            }],
            partitions: vec![SuperPartition {
                name: "system_a".to_string(),
                attributes: 1,
                group_name: "default".to_string(),
                extents: vec![SuperExtent {
                    num_sectors: 16,
                    target_type: LP_TARGET_TYPE_LINEAR,
                    target_data: 2048,
                    target_source: 0,
                }],
            }],
            chunks: Vec::new(),
        })?;
        std::fs::write(temp.path().join("super_empty.img"), &metadata_prefix)?;
        // The OTA-updated standalone image is twice the declared chunk size.
        std::fs::write(temp.path().join("system.img"), vec![0u8; 32 * 4096])?;

        let records = vec![
            record("super_empty.img", 0, (metadata_prefix.len() / 4096) as u64),
            record("system.img", 2048, 16),
        ];

        assert!(
            parse_super_layout(&records, temp.path()).is_err(),
            "strict parser must reject the resized chunk record"
        );

        let layout = parse_super_layout_for_repack(&records, temp.path())?;
        assert_eq!(layout.chunks.len(), 1, "only the metadata chunk is needed");
        assert_eq!(layout.chunks[0].filename, "super_empty.img");
        assert_eq!(layout.dynamic_partition_names(), vec!["system".to_string()]);

        Ok(())
    }
}
