pub mod crypto;
pub mod info;
pub mod parser;
pub mod resign;

pub fn component_scope() -> &'static str {
    "avb signing, descriptor handling, and vbmeta rebuild support"
}

#[cfg(test)]
mod tests {
    use super::component_scope;

    #[test]
    fn scope_mentions_vbmeta() {
        assert!(component_scope().contains("vbmeta"));
    }
}
