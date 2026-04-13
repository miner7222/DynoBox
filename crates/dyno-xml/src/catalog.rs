use dynobox_core::error::{DynoError, Result};
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PartitionRecord {
    pub label: String,
    pub filename: String,
    pub lun: Option<String>,
    pub start_sector: Option<String>,
    pub num_sectors: Option<String>,
    pub source_xml: String,
    pub size_in_kb: Option<String>,
    pub sector_size_bytes: Option<String>,
}

impl PartitionRecord {
    pub fn slot_suffix(&self) -> Option<&'static str> {
        let lowered = self.label.to_lowercase();
        if lowered.ends_with("_a") {
            Some("a")
        } else if lowered.ends_with("_b") {
            Some("b")
        } else {
            None
        }
    }

    pub fn is_ab(&self) -> bool {
        self.slot_suffix().is_some()
    }

    pub fn base_label(&self) -> String {
        if self.is_ab() {
            self.label[..self.label.len() - 2].to_string()
        } else {
            self.label.clone()
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct PartitionGroup {
    pub base_label: String,
    pub a: Vec<PartitionRecord>,
    pub b: Vec<PartitionRecord>,
    pub none: Vec<PartitionRecord>,
}

impl PartitionGroup {
    pub fn new(base_label: String) -> Self {
        Self {
            base_label,
            ..Default::default()
        }
    }

    pub fn is_ab(&self) -> bool {
        !self.a.is_empty() || !self.b.is_empty()
    }

    pub fn has_files(&self) -> bool {
        self.records().iter().any(|r| !r.filename.trim().is_empty())
    }

    pub fn records(&self) -> Vec<&PartitionRecord> {
        self.a
            .iter()
            .chain(self.b.iter())
            .chain(self.none.iter())
            .collect()
    }

    pub fn add(&mut self, record: PartitionRecord) {
        match record.slot_suffix() {
            Some("a") => self.a.push(record),
            Some("b") => self.b.push(record),
            _ => self.none.push(record),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct XmlCatalog {
    records: Vec<PartitionRecord>,
}

impl XmlCatalog {
    pub fn new(records: Vec<PartitionRecord>) -> Self {
        Self { records }
    }

    pub fn records(&self) -> &[PartitionRecord] {
        &self.records
    }

    pub fn from_paths<I, P>(xml_paths: I) -> Result<Self>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        let mut records = Vec::new();

        for path in xml_paths {
            let path = path.as_ref();
            let parsed_records = Self::parse_xml_records(path)?;
            records.extend(parsed_records);
        }

        Ok(Self { records })
    }

    /// Discovers and parses all `rawprogram*.xml` files in the given directory.
    pub fn from_dir(dir: impl AsRef<Path>) -> Result<Self> {
        let dir = dir.as_ref();
        if !dir.is_dir() {
            return Err(DynoError::Validation(format!(
                "Path is not a directory: {}",
                dir.display()
            )));
        }

        let mut xml_paths = Vec::new();
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    let lower = name.to_lowercase();
                    if lower.starts_with("rawprogram") && lower.ends_with(".xml") {
                        xml_paths.push(path);
                    }
                }
            }
        }

        if xml_paths.is_empty() {
            return Err(DynoError::MissingFile(format!(
                "No rawprogram XMLs found in directory: {}",
                dir.display()
            )));
        }

        // Sort paths to ensure deterministic parsing order
        xml_paths.sort();
        Self::from_paths(&xml_paths)
    }

    fn parse_xml_records(path: &Path) -> Result<Vec<PartitionRecord>> {
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string();

        let mut reader = Reader::from_file(path).map_err(|e| {
            DynoError::XmlParse(format!("Failed to open XML file {}: {}", file_name, e))
        })?;
        reader.config_mut().trim_text(true);

        let mut buf = Vec::new();
        let mut records = Vec::new();

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Empty(e)) | Ok(Event::Start(e)) => {
                    if e.name().as_ref() == b"program" {
                        let mut label = String::new();
                        let mut filename = String::new();
                        let mut lun = None;
                        let mut start_sector = None;
                        let mut num_sectors = None;
                        let mut size_in_kb = None;
                        let mut sector_size_bytes = None;

                        for attr in e.attributes().flatten() {
                            let key = attr.key.as_ref();
                            let value = String::from_utf8_lossy(&attr.value).to_string();

                            match key {
                                b"label" => label = value.trim().to_string(),
                                b"filename" => filename = value.trim().to_string(),
                                b"physical_partition_number" => lun = Some(value),
                                b"start_sector" => start_sector = Some(value),
                                b"num_partition_sectors" => num_sectors = Some(value),
                                b"size_in_KB" => size_in_kb = Some(value),
                                b"SECTOR_SIZE_IN_BYTES" => sector_size_bytes = Some(value),
                                _ => {}
                            }
                        }

                        if !label.is_empty() {
                            records.push(PartitionRecord {
                                label,
                                filename,
                                lun,
                                start_sector,
                                num_sectors,
                                source_xml: file_name.clone(),
                                size_in_kb,
                                sector_size_bytes,
                            });
                        }
                    }
                }
                Ok(Event::Eof) => break,
                Err(e) => {
                    return Err(DynoError::XmlParse(format!(
                        "Error parsing XML at position {}: {:?}",
                        reader.buffer_position(),
                        e
                    )));
                }
                _ => (),
            }
            buf.clear();
        }

        Ok(records)
    }

    pub fn find_partition(&self, target_label: &str) -> Option<&PartitionRecord> {
        let normalized = target_label.to_lowercase();
        // 1. Exact match
        if let Some(r) = self
            .records
            .iter()
            .find(|r| r.label.to_lowercase() == normalized)
        {
            return Some(r);
        }

        // 2. Base label match (e.g. "xbl" matches "xbl_a")
        // Prefer slot 'a' if multiple matches exist
        let matches: Vec<_> = self
            .records
            .iter()
            .filter(|r| r.base_label().to_lowercase() == normalized)
            .collect();

        if let Some(r) = matches.iter().find(|r| r.slot_suffix() == Some("a")) {
            return Some(r);
        }

        matches.first().copied()
    }

    pub fn require_partition(
        &self,
        label: &str,
        fallback_labels: Option<&[String]>,
    ) -> Result<&PartitionRecord> {
        if let Some(record) = self.find_partition(label) {
            return Ok(record);
        }

        if let Some(fallbacks) = fallback_labels {
            for candidate in fallbacks {
                if let Some(record) = self.find_partition(candidate) {
                    return Ok(record);
                }
            }
        }

        Err(DynoError::MissingFile(format!(
            "Partition '{}' not found in catalog",
            label
        )))
    }

    pub fn group_by_base_label(&self, with_files_only: bool) -> HashMap<String, PartitionGroup> {
        let mut groups: HashMap<String, PartitionGroup> = HashMap::new();

        for record in &self.records {
            let base_label = record.base_label();
            let group = groups
                .entry(base_label.clone())
                .or_insert_with(|| PartitionGroup::new(base_label));
            group.add(record.clone());
        }

        if with_files_only {
            groups.retain(|_, group| group.has_files());
        }

        groups
    }
}
