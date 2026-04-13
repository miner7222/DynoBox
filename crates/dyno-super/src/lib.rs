pub mod builder;
pub mod extractor;
pub mod metadata;
pub mod parser;
pub mod repack;

pub use builder::serialize_metadata;
pub use extractor::extract_partition_images;
pub use metadata::*;
pub use parser::parse_super_layout;
pub use repack::repack_super_image;

pub fn component_scope() -> &'static str {
    "super image parsing, unpack, and repack planning"
}

#[cfg(test)]
mod parser_tests;

#[cfg(test)]
mod tests {
    use super::component_scope;

    #[test]
    fn scope_mentions_super_images() {
        assert!(component_scope().contains("super image"));
    }
}
