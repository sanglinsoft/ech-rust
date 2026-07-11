fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    std::env::set_var("PROTOC", protoc);

    tonic_build::configure()
        .build_server(false)
        .build_client(true)
        // Use Bytes for protobuf `bytes` fields so relay paths can avoid extra copies.
        .bytes(["."])
        .compile(&["../proto/tunnel/v1/tunnel.proto"], &["../proto"])?;
    println!("cargo:rerun-if-changed=../proto/tunnel/v1/tunnel.proto");
    Ok(())
}
