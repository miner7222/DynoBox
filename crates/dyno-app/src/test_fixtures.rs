//! Helpers for tests that need real firmware artifacts.
//!
//! Such tests are marked `#[ignore = "fixture: set DYNOBOX_..."]` so a plain
//! `cargo test` reports them as ignored instead of silently passing. Run
//! them with `cargo test -- --ignored` after exporting the named variables;
//! a missing variable then fails loudly instead of skipping.

/// Read a required fixture environment variable, panicking with a clear
/// message when it is unset.
pub(crate) fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| {
        panic!("fixture test needs `{name}`; export it before `cargo test -- --ignored`")
    })
}
