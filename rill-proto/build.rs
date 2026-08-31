use pb_rs::{types::FileDescriptor, ConfigBuilder};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let in_dir = manifest.join("proto");
    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    println!("cargo:rerun-if-changed={}", in_dir.to_str().unwrap());

    let mut protos = Vec::new();
    for entry in WalkDir::new(&in_dir) {
        let path = entry.unwrap().into_path();
        if path.extension() == Some(Path::new("proto").as_os_str()) {
            println!("cargo:rerun-if-changed={}", path.to_str().unwrap());
            protos.push(path);
        }
    }

    for entry in std::fs::read_dir(&out_dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().map(|e| e == "rs").unwrap_or(false) {
            std::fs::remove_file(path).unwrap();
        }
    }
    let mut config = ConfigBuilder::new(&protos, None, Some(&out_dir), &[in_dir]).unwrap();
    config = config.owned(true);
    FileDescriptor::run(&config.build()).unwrap()
}
