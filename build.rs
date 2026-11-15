use std::env;

fn main() {
    println!("cargo:rerun-if-env-changed=RUSS_UPDATE_URL");
    println!("cargo:rerun-if-env-changed=RUSS_UPDATE_PUBLIC_KEY");
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=release/update-source.json");
    let built = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("build clock must be after the Unix epoch")
        .as_secs();
    println!("cargo:rustc-env=RUSS_BUILD_UNIX_SECONDS={built}");
    println!("cargo:rerun-if-changed=assets/russ-logo.png");
    println!("cargo:rerun-if-changed=assets/russ-logo.ico");

    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let mut resource = winresource::WindowsResource::new();
        resource.set_icon("assets/russ-logo.ico");
        resource
            .compile()
            .expect("failed to embed the RUSS Windows application icon");
    }
}
