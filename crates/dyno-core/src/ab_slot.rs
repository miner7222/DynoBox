//! Shared helpers for parsing the Android `_a` / `_b` slot suffix
//! out of partition names.
//!
//! Both `dyno-xml::PartitionRecord` (parses `<program label="...">`)
//! and `dyno-super::SuperPartition` (parses dynamic-partition names
//! from the super metadata blob) used to carry their own copies of
//! the same logic. Promoting them into `dyno-core` keeps the two
//! crates in lockstep and gives us one place to evolve when AOSP
//! eventually grows a third slot or moves to a different suffix
//! scheme.

/// Strip an `_a` / `_b` suffix from `name` and return the
/// remaining base. Case-insensitive on the suffix (`system_A` is
/// treated as slot `a`). Returns `Some(("system", "a"))` for
/// `"system_a"`, `Some(("system", "b"))` for `"system_b"`, and
/// `None` for any other input.
pub fn split_slot_suffix(name: &str) -> Option<(&str, &'static str)> {
    let bytes = name.as_bytes();
    if bytes.len() < 2 || bytes[bytes.len() - 2] != b'_' {
        return None;
    }
    match bytes[bytes.len() - 1] {
        b'a' | b'A' => Some((&name[..name.len() - 2], "a")),
        b'b' | b'B' => Some((&name[..name.len() - 2], "b")),
        _ => None,
    }
}

/// `Some("a")` / `Some("b")` / `None`. Convenience over
/// [`split_slot_suffix`] when the caller only needs the slot.
pub fn slot_suffix(name: &str) -> Option<&'static str> {
    split_slot_suffix(name).map(|(_, slot)| slot)
}

/// Strip an `_a` / `_b` suffix, returning the owned base name.
/// `system_a` -> `system`. Inputs without a suffix are echoed
/// unchanged.
pub fn base_name(name: &str) -> String {
    match split_slot_suffix(name) {
        Some((base, _)) => base.to_string(),
        None => name.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_slot() {
        assert_eq!(split_slot_suffix("system_a"), Some(("system", "a")));
        assert_eq!(slot_suffix("system_a"), Some("a"));
        assert_eq!(base_name("system_a"), "system");
    }

    #[test]
    fn parses_b_slot() {
        assert_eq!(split_slot_suffix("vendor_b"), Some(("vendor", "b")));
        assert_eq!(slot_suffix("vendor_b"), Some("b"));
        assert_eq!(base_name("vendor_b"), "vendor");
    }

    #[test]
    fn case_insensitive_suffix() {
        assert_eq!(slot_suffix("system_A"), Some("a"));
        assert_eq!(slot_suffix("system_B"), Some("b"));
        assert_eq!(base_name("vendor_A"), "vendor");
    }

    #[test]
    fn rejects_non_slot_names() {
        assert_eq!(slot_suffix("super"), None);
        assert_eq!(slot_suffix("system"), None);
        assert_eq!(slot_suffix("system_c"), None);
        assert_eq!(base_name("super"), "super");
        // Two-letter strings without `_` prefix:
        assert_eq!(slot_suffix("ab"), None);
        assert_eq!(slot_suffix("_a"), Some("a"));
    }
}
