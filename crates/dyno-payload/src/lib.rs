pub mod patcher;
pub mod payload;
pub mod puffin;

pub use patcher::{
    ApplyProgressCallback, OperationSupportInfo, apply_partition_payload,
    apply_partition_payload_from, apply_partition_payload_with_progress, inspect_operation_support,
};
pub use payload::{
    Payload, PayloadMetadata, PayloadPartitionInfo, PayloadPreflightReport, UnsupportedOperation,
    extract_payload, inspect_payload, inspect_payload_from, parse_payload_metadata,
    parse_payload_metadata_from, read_manifest,
};
pub use puffin::apply_puffpatch;

pub fn component_scope() -> &'static str {
    "payload metadata parsing and OTA patch planning"
}

#[cfg(test)]
mod tests {
    use super::component_scope;

    #[test]
    fn scope_mentions_payload() {
        assert!(component_scope().contains("payload"));
    }
}
