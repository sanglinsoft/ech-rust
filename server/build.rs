fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(true)
        .build_client(false)
        .compile(&["../proto/tunnel/v1/tunnel.proto"], &["../proto"])?;
    println!("cargo:rerun-if-changed=../proto/tunnel/v1/tunnel.proto");
    Ok(())
}
