fn main() {
    cc::Build::new()
        .cpp(true)
        .include("deps/")
        .file("src/wrapper.cpp")
        .flag_if_supported("-std=c++20")
        .compile("vmaware-bridge");

    println!("cargo:rerun-if-changed=src/wrapper.cpp");
    println!("cargo:rerun-if-changed=deps/vmaware.hpp");

    #[cfg(target_os = "windows")]
    {
        println!("cargo:rustc-link-lib=advapi32");
        println!("cargo:rustc-link-lib=gdi32");
        println!("cargo:rustc-link-lib=user32");
    }
}
