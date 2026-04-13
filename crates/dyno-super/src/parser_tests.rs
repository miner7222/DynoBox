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
}
