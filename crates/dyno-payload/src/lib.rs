pub mod patcher;
pub mod payload;
pub mod puffin;

pub use patcher::{OperationSupportInfo, apply_partition_payload, inspect_operation_support};
pub use payload::{
    PayloadMetadata, PayloadPartitionInfo, PayloadPreflightReport, UnsupportedOperation,
    extract_payload, inspect_payload, parse_payload_metadata,
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
