use vmaware::{detect, brand, vm_type, conclusion, percentage, detected_count, is_hardened, check, flags};

fn main() -> Result<(), vmaware::VmawareError> {
    println!("is vm: {}", detect()?);
    println!("brand: {}", brand()?);
    println!("type: {}", vm_type()?);
    println!("conclusion: {}", conclusion()?);
    println!("percentage: {}%", percentage()?);
    println!("detected techniques: {}", detected_count()?);
    println!("hardened: {}", is_hardened()?);

    // check a single technique
    if check(flags::HYPERVISOR_BIT)? {
        println!("hypervisor bit is set");
    }

    Ok(())
}