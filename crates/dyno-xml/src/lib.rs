pub mod catalog;

#[cfg(test)]
mod catalog_tests;

pub use catalog::{PartitionGroup, PartitionRecord, XmlCatalog};

pub fn component_scope() -> &'static str {
    "rawprogram XML discovery, parsing, and rewrite helpers"
}

#[cfg(test)]
mod tests {
    use super::component_scope;

    #[test]
    fn scope_mentions_xml() {
        assert!(component_scope().contains("XML"));
    }
}
