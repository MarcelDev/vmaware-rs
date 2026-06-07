fn main() -> Result<(), vmaware::Error> {
    println!("is_vm: {}", vmaware::detect()?);
    println!("brand: {}", vmaware::brand()?);
    println!("type: {}", vmaware::vm_type()?);
    println!("conclusion: {}", vmaware::conclusion()?);
    println!("percentage: {}%", vmaware::percentage()?);
    println!("detected_count: {}", vmaware::detected_count()?);
    println!("technique_count: {}", vmaware::technique_count());
    println!("is_hardened: {}", vmaware::is_hardened()?);

    let flag = vmaware::flags::HYPERVISOR_BIT;
    println!("flag {flag}: {}", vmaware::flag_to_string(flag)?);
    println!("check {flag}: {}", vmaware::check(flag)?);
    println!(
        "high_threshold: {}",
        vmaware::detect_with(&[vmaware::flags::HIGH_THRESHOLD])?
    );

    Ok(())
}
