use std::{env, fs, path::PathBuf, process::Command};

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    println!("cargo:rerun-if-changed=injector");
    println!("cargo:rerun-if-changed=payload");

    let injector_status = Command::new("cargo")
        .args(&["build", "--release", "--manifest-path"])
        .arg(manifest_dir.join("injector/Cargo.toml"))
        .env("CARGO_TARGET_DIR", &out_dir)
        .status()
        .expect("Failed to execute cargo build for injector");

    if !injector_status.success() {
        panic!("Failed to build injector application");
    }

    let payload_status = Command::new("cargo")
        .args(&["build", "--release", "--manifest-path"])
        .arg(manifest_dir.join("payload/Cargo.toml"))
        .env("CARGO_TARGET_DIR", &out_dir)
        .status()
        .expect("Failed to execute cargo build for payload");

    if !payload_status.success() {
        panic!("Failed to build payload module");
    }

    let injector_binary = out_dir.join("release/injector.exe");
    let payload_binary = out_dir.join("release/payload.dll");

    if !injector_binary.exists() {
        panic!("Injector binary not found at {:?}", injector_binary);
    }
    if !payload_binary.exists() {
        panic!("Payload binary not found at {:?}", payload_binary);
    }

    let injector_out = out_dir.join("injector_bin");
    let payload_out = out_dir.join("payload_bin");

    fs::copy(&injector_binary, &injector_out).expect("Failed to copy secondary binary");
    fs::copy(&payload_binary, &payload_out).expect("Failed to copy library binary");

    println!(
        "cargo:rustc-env=INJECTOR_BINARY_PATH={}",
        injector_out.display()
    );
    println!(
        "cargo:rustc-env=PAYLOAD_BINARY_PATH={}",
        payload_out.display()
    );
}
