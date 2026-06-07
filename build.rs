fn main() {
    cc::Build::new()
        .cpp(true)
        .include("deps/vmaware/src")
        .file("src/wrapper.cpp")
        .flag_if_supported("-std=c++17")
        .compile("vmaware-bridge");

    println!("cargo:rerun-if-changed=src/wrapper.cpp");
    println!("cargo:rerun-if-changed=deps/vmaware/src/vmaware.hpp");
}
