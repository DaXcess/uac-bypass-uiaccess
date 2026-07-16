fn main() {
    // Embed manifest with "UIAccess" enabled
    let mut res = winres::WindowsResource::new();
    res.set_manifest_file("manifest.xml");
    res.compile().unwrap();

    println!("cargo:rustc-link-arg=/EXPORT:is_injector");
}
