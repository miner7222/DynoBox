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
