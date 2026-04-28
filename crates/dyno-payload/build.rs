// `set_var` is `unsafe` since Rust 1.95; no other thread is running during a
// build script's `main`, so calling it here is sound. The workspace's
// `unsafe_code = "forbid"` lint applies to runtime code only, but build
// scripts inherit the same workspace lints, so opt this single block out.
#![allow(unsafe_code)]

fn main() {
    // Compile Protobuf for Rust
    unsafe {
        std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path().unwrap());
    }
    let mut config = prost_build::Config::new();
    config
        .compile_protos(
            &["proto/update_metadata.proto", "proto/puffin.proto"],
            &["proto/"],
        )
        .unwrap();
}
