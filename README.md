# vmaware-rs

Rust bindings for [VMAware](https://github.com/NotRequiem/VMAware), a cross-platform C++ framework for virtual machine detection.

The package is published as `vmaware-rs`, while the Rust library is imported as `vmaware`.

## Installation

```toml
[dependencies]
vmaware-rs = { git = "https://github.com/MarcelDev/vmaware-rs.git" }
```

This crate builds a small C++17 wrapper around the vendored VMAware header. A working C++ compiler is required.

## Usage

```rust
fn main() -> Result<(), vmaware::Error> {
    println!("is vm: {}", vmaware::detect()?);
    println!("brand: {}", vmaware::brand()?);
    println!("type: {}", vmaware::vm_type()?);
    println!("conclusion: {}", vmaware::conclusion()?);
    println!("percentage: {}%", vmaware::percentage()?);

    Ok(())
}
```

You can run a small example:

```sh
cargo run --example basic
```

## License

Licensed under the MIT License, matching upstream VMAware. The vendored VMAware source is included under `deps/vmaware` as a Git submodule.
