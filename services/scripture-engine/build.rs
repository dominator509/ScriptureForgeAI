fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-env-changed=PROTOC");
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    std::env::set_var("PROTOC", protoc);
    let manifest_dir = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?);
    let proto_file = manifest_dir.join("../../proto/scripture.proto");
    let proto_dir = manifest_dir.join("../../proto");
    println!("cargo:rerun-if-changed={}", proto_file.display());
    tonic_build::configure().compile(&[proto_file], &[proto_dir])?;
    Ok(())
}
