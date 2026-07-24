fn main() {
    cc::Build::new()
        .cpp(true)
        .include("deps")
        .file("src/wrapper.cpp")
        .flag_if_supported("-std=c++17")
        .compile("vmaware-bridge");

    let bindings = bindgen::Builder::default()
        .header("deps/vmaware.hpp")
        .clang_arg("-x")
        .clang_arg("c++")
        .clang_arg("-std=c++17")
        .allowlist_type("VM_enum_flags")
        .allowlist_type("VM_brand_enum")
        .allowlist_var("VM_technique_count")
        .rustified_enum("VM_enum_flags")
        .rustified_enum("VM_brand_enum")
        .generate()
        .expect("bindgen failed");

    let out_path = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    
    bindings
        .write_to_file(out_path.join("flags_bindgen.rs"))
        .expect("couldn't write flags_bindgen.rs");

    println!("cargo:rerun-if-changed=src/wrapper.cpp");
    println!("cargo:rerun-if-changed=src/wrapper.hpp");
    println!("cargo:rerun-if-changed=deps/vmaware.hpp");

    #[cfg(target_os = "windows")]
    {
        println!("cargo:rustc-link-lib=advapi32");
        println!("cargo:rustc-link-lib=gdi32");
        println!("cargo:rustc-link-lib=user32");
    }
}
