#[cfg(test)]
mod tests {
    use crate::catalog::{PartitionRecord, XmlCatalog};
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_partition_record_slots() {
        let record_a = PartitionRecord {
            label: "system_a".to_string(),
            filename: "system.img".to_string(),
            lun: None,
            start_sector: None,
            num_sectors: None,
            source_xml: "test.xml".to_string(),
            size_in_kb: None,
            sector_size_bytes: None,
        };

        assert_eq!(record_a.slot_suffix(), Some("a"));
        assert!(record_a.is_ab());
        assert_eq!(record_a.base_label(), "system");

        let record_b = PartitionRecord {
            label: "vendor_B".to_string(),
            filename: "vendor.img".to_string(),
            lun: None,
            start_sector: None,
            num_sectors: None,
            source_xml: "test.xml".to_string(),
            size_in_kb: None,
            sector_size_bytes: None,
        };

        assert_eq!(record_b.slot_suffix(), Some("b"));
        assert!(record_b.is_ab());
        assert_eq!(record_b.base_label(), "vendor");

        let record_none = PartitionRecord {
            label: "recovery".to_string(),
            filename: "recovery.img".to_string(),
            lun: None,
            start_sector: None,
            num_sectors: None,
            source_xml: "test.xml".to_string(),
            size_in_kb: None,
            sector_size_bytes: None,
        };

        assert_eq!(record_none.slot_suffix(), None);
        assert!(!record_none.is_ab());
        assert_eq!(record_none.base_label(), "recovery");
    }

    #[test]
    fn test_xml_catalog_parsing() -> dynobox_core::error::Result<()> {
        let xml_content = r#"<?xml version="1.0" ?>
        <data>
            <program label="system_a" filename="system.img" start_sector="10" num_partition_sectors="100" />
            <program label="vendor_b" filename="vendor.img" />
            <program label="empty" filename="" />
        </data>"#;

        let mut temp_file = NamedTempFile::new()?;
        temp_file.write_all(xml_content.as_bytes())?;

        let catalog = XmlCatalog::from_paths(&[temp_file.path()])?;

        assert_eq!(catalog.records().len(), 3);

        let sys = catalog.find_partition("system_a").unwrap();
        assert_eq!(sys.filename, "system.img");
        assert_eq!(sys.start_sector, Some("10".to_string()));
        assert_eq!(sys.num_sectors, Some("100".to_string()));

        let groups = catalog.group_by_base_label(true);
        assert!(groups.contains_key("system"));
        assert!(groups.contains_key("vendor"));
        assert!(!groups.contains_key("empty")); // because with_files_only is true

        Ok(())
    }

    #[test]
    fn test_real_xml_discovery() -> dynobox_core::error::Result<()> {
        let test_dir =
            std::path::Path::new(r"D:\Git\Project-LTBOX\TB322_ZUXOS_1.5.10.183_resigned");

        // Skip test if the directory doesn't exist (e.g. in CI environments)
        if !test_dir.exists() {
            println!("Skipping real XML discovery test because test directory does not exist.");
            return Ok(());
        }

        let catalog = XmlCatalog::from_dir(test_dir)?;

        // Make sure we found some records
        assert!(!catalog.records().is_empty());

        // Find some known partitions from typical real-world XMLs
        let boot_a = catalog.find_partition("boot_a");
        assert!(boot_a.is_some(), "Should find boot_a partition");
        if let Some(record) = boot_a {
            assert_eq!(record.filename, "boot.img");
        }

        let super_group = catalog.group_by_base_label(true).remove("super");
        assert!(
            super_group.is_some(),
            "Should find super partition group with files"
        );
        if let Some(group) = super_group {
            assert!(group.has_files());
            // super is usually a single 'none' slot or A/B slot depending on the structure
            assert!(!group.records().is_empty());
        }

        Ok(())
    }
}
