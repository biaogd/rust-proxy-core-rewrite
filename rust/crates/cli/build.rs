fn main() {
    println!("cargo:rerun-if-env-changed=MIHOMO_VERSION");
    println!("cargo:rerun-if-env-changed=MIHOMO_BUILD_TIME");
    let compiler = rustc_version::version()
        .map_or_else(|_| "unknown".to_owned(), |version| version.to_string());
    println!("cargo:rustc-env=MIHOMO_RUSTC_VERSION={compiler}");
}
