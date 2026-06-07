//! Safe Rust bindings for VMAware.
//!
//! `vmaware-rs` builds a small C++17 wrapper around the VMAware header and
//! exposes Rust functions for detecting virtual machines.
//!
//! C++ exceptions from VMAware are caught at the FFI boundary and returned as
//! [`Error`].
//!
//! # Example
//!
//! ```no_run
//! # fn main() -> Result<(), vmaware::Error> {
//! println!("is vm: {}", vmaware::detect()?);
//! println!("brand: {}", vmaware::brand()?);
//! println!("type: {}", vmaware::vm_type()?);
//! println!("conclusion: {}", vmaware::conclusion()?);
//! println!("percentage: {}%", vmaware::percentage()?);
//! # Ok(())
//! # }
//! ```
//!
//! The package is named `vmaware-rs`, while the library is imported as
//! `vmaware`.

use std::ffi::CStr;
use std::os::raw::{c_char, c_uchar, c_ushort};
use std::ptr;

unsafe extern "C" {
    fn vmaware_try_check(flag: c_uchar, out: *mut bool, error: *mut *mut c_char) -> bool;
    fn vmaware_try_detect(out: *mut bool, error: *mut *mut c_char) -> bool;
    fn vmaware_try_detect_with(
        flags: *const c_uchar,
        len: usize,
        out: *mut bool,
        error: *mut *mut c_char,
    ) -> bool;
    fn vmaware_try_percentage(out: *mut c_uchar, error: *mut *mut c_char) -> bool;
    fn vmaware_try_percentage_with(
        flags: *const c_uchar,
        len: usize,
        out: *mut c_uchar,
        error: *mut *mut c_char,
    ) -> bool;
    fn vmaware_try_detected_count(out: *mut c_uchar, error: *mut *mut c_char) -> bool;
    fn vmaware_try_detected_count_with(
        flags: *const c_uchar,
        len: usize,
        out: *mut c_uchar,
        error: *mut *mut c_char,
    ) -> bool;
    fn vmaware_technique_count() -> c_ushort;
    fn vmaware_try_is_hardened(out: *mut bool, error: *mut *mut c_char) -> bool;
    fn vmaware_try_brand(out: *mut *mut c_char, error: *mut *mut c_char) -> bool;
    fn vmaware_try_brand_with(
        flags: *const c_uchar,
        len: usize,
        out: *mut *mut c_char,
        error: *mut *mut c_char,
    ) -> bool;
    fn vmaware_try_type(out: *mut *mut c_char, error: *mut *mut c_char) -> bool;
    fn vmaware_try_type_with(
        flags: *const c_uchar,
        len: usize,
        out: *mut *mut c_char,
        error: *mut *mut c_char,
    ) -> bool;
    fn vmaware_try_conclusion(out: *mut *mut c_char, error: *mut *mut c_char) -> bool;
    fn vmaware_try_conclusion_with(
        flags: *const c_uchar,
        len: usize,
        out: *mut *mut c_char,
        error: *mut *mut c_char,
    ) -> bool;
    fn vmaware_try_flag_to_string(
        flag: c_uchar,
        out: *mut *mut c_char,
        error: *mut *mut c_char,
    ) -> bool;
    fn vmaware_string_free(value: *mut c_char);
}

/// Error returned when VMAware throws a C++ exception.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Error {
    message: String,
}

impl Error {
    /// Returns the exception message reported by VMAware.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

/// Technique and setting flags matching VMAware's `VM::enum_flags`.
pub mod flags {
    pub const GPU_CAPABILITIES: u8 = 0;
    pub const ACPI_SIGNATURE: u8 = 1;
    pub const POWER_CAPABILITIES: u8 = 2;
    pub const IVSHMEM: u8 = 3;
    pub const DRIVERS: u8 = 4;
    pub const HANDLES: u8 = 5;
    pub const VIRTUAL_PROCESSORS: u8 = 6;
    pub const HYPERVISOR_QUERY: u8 = 7;
    pub const AUDIO: u8 = 8;
    pub const DISPLAY: u8 = 9;
    pub const DLL: u8 = 10;
    pub const VMWARE_BACKDOOR: u8 = 11;
    pub const WINE: u8 = 12;
    pub const VIRTUAL_REGISTRY: u8 = 13;
    pub const MUTEX: u8 = 14;
    pub const DEVICE_STRING: u8 = 15;
    pub const VPC_INVALID: u8 = 16;
    pub const VMWARE_STR: u8 = 17;
    pub const GAMARUE: u8 = 18;
    pub const CUCKOO_DIR: u8 = 19;
    pub const CUCKOO_PIPE: u8 = 20;
    pub const TRAP: u8 = 21;
    pub const UD: u8 = 22;
    pub const INTERRUPT_SHADOW: u8 = 23;
    pub const DBVM: u8 = 24;
    pub const KERNEL_OBJECTS: u8 = 25;
    pub const NVRAM: u8 = 26;
    pub const EDID: u8 = 27;
    pub const CPU_HEURISTIC: u8 = 28;
    pub const CLOCK: u8 = 29;
    pub const MSR: u8 = 30;
    pub const KVM_INTERCEPTION: u8 = 31;
    pub const HYPERVISOR_HOOK: u8 = 32;
    pub const SINGLE_STEP: u8 = 33;
    pub const EIP_OVERFLOW: u8 = 34;
    pub const SVM_EXCEPTIONS: u8 = 35;
    pub const SYSTEM_REGISTERS: u8 = 36;
    pub const FIRMWARE: u8 = 37;
    pub const DEVICES: u8 = 38;
    pub const AZURE: u8 = 39;
    pub const BOOT_LOGO: u8 = 40;
    pub const DISK_SERIAL: u8 = 41;
    pub const SMBIOS_VM_BIT: u8 = 42;
    pub const KMSG: u8 = 43;
    pub const CVENDOR: u8 = 44;
    pub const QEMU_FW_CFG: u8 = 45;
    pub const SYSTEMD: u8 = 46;
    pub const CTYPE: u8 = 47;
    pub const DOCKERENV: u8 = 48;
    pub const DMIDECODE: u8 = 49;
    pub const DMESG: u8 = 50;
    pub const HWMON: u8 = 51;
    pub const LINUX_USER_HOST: u8 = 52;
    pub const VMWARE_IOMEM: u8 = 53;
    pub const VMWARE_IOPORTS: u8 = 54;
    pub const VMWARE_SCSI: u8 = 55;
    pub const VMWARE_DMESG: u8 = 56;
    pub const QEMU_VIRTUAL_DMI: u8 = 57;
    pub const QEMU_USB: u8 = 58;
    pub const HYPERVISOR_DIR: u8 = 59;
    pub const UML_CPU: u8 = 60;
    pub const VBOX_MODULE: u8 = 61;
    pub const SYSINFO_PROC: u8 = 62;
    pub const DMI_SCAN: u8 = 63;
    pub const PODMAN_FILE: u8 = 64;
    pub const WSL_PROC: u8 = 65;
    pub const FILE_ACCESS_HISTORY: u8 = 66;
    pub const MAC: u8 = 67;
    pub const CONTAINER_PID: u8 = 68;
    pub const BLUESTACKS_FOLDERS: u8 = 69;
    pub const AMD_SEV_MSR: u8 = 70;
    pub const TEMPERATURE: u8 = 71;
    pub const CGROUP: u8 = 72;
    pub const PROCESSES: u8 = 73;
    pub const THREAD_COUNT: u8 = 74;
    pub const MAC_MEMSIZE: u8 = 75;
    pub const MAC_IOKIT: u8 = 76;
    pub const MAC_SIP: u8 = 77;
    pub const IOREG_GREP: u8 = 78;
    pub const HWMODEL: u8 = 79;
    pub const MAC_SYS: u8 = 80;
    pub const HYPERVISOR_BIT: u8 = 81;
    pub const VMID: u8 = 82;
    pub const THREAD_MISMATCH: u8 = 83;
    pub const TIMER: u8 = 84;
    pub const CPU_BRAND: u8 = 85;
    pub const HYPERVISOR_STR: u8 = 86;
    pub const CPUID_SIGNATURE: u8 = 87;
    pub const BOCHS_CPU: u8 = 88;
    pub const KGT_SIGNATURE: u8 = 89;
    pub const DEFAULT: u8 = 90;
    pub const ALL: u8 = 91;
    pub const NULL_ARG: u8 = 92;
    pub const HIGH_THRESHOLD: u8 = 93;
    pub const DYNAMIC: u8 = 94;
    pub const MULTIPLE: u8 = 95;
}

/// This takes a single technique argument and returns a `bool`. It essentially
/// returns a technique's effective output. Nothing more, nothing less.
///
/// ```no_run
/// # fn main() -> Result<(), vmaware::Error> {
/// if vmaware::check(vmaware::flags::VMID)? {
///     println!("VMID technique detected a VM!");
/// }
///
/// if vmaware::check(vmaware::flags::HYPERVISOR_BIT)? {
///     println!("Hypervisor bit is set, most definitely a VM!");
/// }
///
/// # Ok(())
/// # }
/// ```
pub fn check(flag: u8) -> Result<bool, Error> {
    let mut out = false;
    call_value(|error| unsafe { vmaware_try_check(flag, &mut out, error) })?;
    Ok(out)
}

/// This is basically the main function you're looking for, which returns a
/// bool. If no parameter is provided, all the recommended checks will be
/// performed. But you can optionally set which techniques are used.
///
/// ```no_run
/// # fn main() -> Result<(), vmaware::Error> {
/// /**
///  * The basic way to detect a VM where the default checks will
///  * be performed. This is the recommended usage of the lib.
///  */
/// let is_vm = vmaware::detect()?;
///
/// /**
///  * This does the exact same as above, but as an explicit alternative.
///  */
/// let is_vm2 = vmaware::detect_with(&[vmaware::flags::DEFAULT])?;
///
/// /**
///  * All checks are performed including techniques that are
///  * disabled by default for a viariety of reasons. If you
///  * want all techniques for the sake of completeness, then
///  * you can use this flag but remember that there may be potential
///  * performance bottlenecks and an increase in false positives.
///  */
/// let is_vm3 = vmaware::detect_with(&[vmaware::flags::ALL])?;
///
/// /**
///  * This will raise the detection threshold above the default level.
///  * Use this if you want to be extremely sure if it's a VM, but this
///  * increases the chance of a false negative. Use vmaware::percentage()
///  * for a more precise result if you want.
///  */
/// let is_vm4 = vmaware::detect_with(&[vmaware::flags::HIGH_THRESHOLD])?;
///
/// /**
///  * Essentially means only the CPU brand, MAC, and hypervisor bit techniques
///  * should be performed. Note that the less technique flags you provide, the more
///  * likely the result will not be accurate. If you just want to check for
///  * a single technique, use vmaware::check() instead. Also, read the flag table
///  * in the upstream docs for a full list of technique flags.
///  */
/// let is_vm5 = vmaware::detect_with(&[
///     vmaware::flags::CPU_BRAND,
///     vmaware::flags::MAC,
///     vmaware::flags::HYPERVISOR_BIT,
/// ])?;
///
/// /**
///  * This is just an example to show that you can use a combination of
///  * different flags and non-technique flags with the above examples.
///  */
/// let is_vm6 = vmaware::detect_with(&[
///     vmaware::flags::DEFAULT,
///     vmaware::flags::HIGH_THRESHOLD,
/// ])?;
/// # let _ = (is_vm, is_vm2, is_vm3, is_vm4, is_vm5, is_vm6);
/// # Ok(())
/// # }
/// ```
pub fn detect() -> Result<bool, Error> {
    let mut out = false;
    call_value(|error| unsafe { vmaware_try_detect(&mut out, error) })?;
    Ok(out)
}

/// Detects with a specific set of VMAware flags.
///
/// An empty slice has the same behavior as [`detect`].
pub fn detect_with(flags: &[u8]) -> Result<bool, Error> {
    let mut out = false;
    call_value(|error| unsafe {
        vmaware_try_detect_with(flags.as_ptr(), flags.len(), &mut out, error)
    })?;
    Ok(out)
}

/// This will return a `u8` between 0 and 100. It'll return the certainty of
/// whether it has detected a VM based on all the techniques available as a
/// percentage.
///
/// ```no_run
/// # fn main() -> Result<(), vmaware::Error> {
/// let percent = vmaware::percentage()?;
///
/// if percent == 100 {
///     println!("Definitely a VM!");
/// } else if percent == 0 {
///     println!("Definitely NOT a VM");
/// } else {
///     println!("Unsure if it's a VM");
/// }
///
/// println!("percentage: {percent}%");
/// # Ok(())
/// # }
/// ```
///
/// > [!NOTE]
/// > you can use the same flag system as shown with [`detect_with`] for this
/// > function.
pub fn percentage() -> Result<u8, Error> {
    let mut out = 0;
    call_value(|error| unsafe { vmaware_try_percentage(&mut out, error) })?;
    Ok(out)
}

/// Returns VMAware's confidence score using a specific set of flags.
///
/// An empty slice has the same behavior as [`percentage`].
pub fn percentage_with(flags: &[u8]) -> Result<u8, Error> {
    let mut out = 0;
    call_value(|error| unsafe {
        vmaware_try_percentage_with(flags.as_ptr(), flags.len(), &mut out, error)
    })?;
    Ok(out)
}

/// This will fetch the number of techniques that have been detected as a `u8`.
///
/// ```no_run
/// # fn main() -> Result<(), vmaware::Error> {
/// let count = vmaware::detected_count()?;
///
/// // output: 7 techniques were detected
/// println!("{count} techniques were detected");
///
/// // note that if it's baremetal, it should be 0.
/// // if it's a VM, it should have at least 4 to
/// // maybe around 15 max. The most I've seen was
/// // around 18 but that only occurs very rarely.
/// # Ok(())
/// # }
/// ```
pub fn detected_count() -> Result<u8, Error> {
    let mut out = 0;
    call_value(|error| unsafe { vmaware_try_detected_count(&mut out, error) })?;
    Ok(out)
}

/// Returns the detected technique count using a specific set of flags.
///
/// An empty slice has the same behavior as [`detected_count`].
pub fn detected_count_with(flags: &[u8]) -> Result<u8, Error> {
    let mut out = 0;
    call_value(|error| unsafe {
        vmaware_try_detected_count_with(flags.as_ptr(), flags.len(), &mut out, error)
    })?;
    Ok(out)
}

/// Returns the number of detection techniques available in VMAware.
///
/// This reads a static count and cannot throw a VMAware exception.
pub fn technique_count() -> u16 {
    unsafe { vmaware_technique_count() }
}

/// This will detect whether the environment has any hardening indications as a
/// `bool`.
///
/// Internally, this function works by analysing which combination of techniques
/// are expected to be detected together. If a certain combination rule is
/// mismatched, it indicates some kind of tampering of the system which assumes
/// some sort of VM hardening.
///
/// Similiary to [`brand`], do not rely on this function for critical
/// operations. This is meant to be a heuristic assumption rather than a concrete
/// guarantee.
///
/// ```no_run
/// # fn main() -> Result<(), vmaware::Error> {
/// if vmaware::is_hardened()? {
///     println!("Potential hardening detected");
/// } else {
///     println!("Unsure if hardened");
/// }
/// # Ok(())
/// # }
/// ```
pub fn is_hardened() -> Result<bool, Error> {
    let mut out = false;
    call_value(|error| unsafe { vmaware_try_is_hardened(&mut out, error) })?;
    Ok(out)
}

/// This will essentially return the VM brand as a `String`. All the brands
/// and brand alias variables are listed in VMAware's brand table.
///
/// If none were detected, it will return `Unknown`. It should be noted that this
/// could be a common scenario even if you're running inside a VM due to technical
/// difficulties with accomplishing this. This is especially true for VMware
/// sub-versions (ESX, GSX, Fusion, etc...). It's not recommended to rely on this
/// function for critical operations as if your whole program depends on it.
///
/// ```no_run
/// # fn main() -> Result<(), vmaware::Error> {
/// let result = vmaware::brand()?;
///
/// if result == "KVM" {
///     // do KVM specific stuff
/// } else if result == "VirtualBox" {
///     // you get the idea
/// }
/// # Ok(())
/// # }
/// ```
///
/// On rare occasions, there might be cases where there's multiple brands that
/// have been detected, which might cause a conflicting output with an inaccurate
/// result. To prevent this, you can use the [`flags::MULTIPLE`] flag that
/// returns a **message** rather than a **VM brand string**. For example, if it found 2
/// conflicting brands, it will return `VMware or VirtualBox`. For 3 conflicts,
/// it's `VMware or VirtualBox or QEMU` and so on.
///
/// ```no_run
/// # fn main() -> Result<(), vmaware::Error> {
/// // format: "vmbrand1 or vmbrand2 [or vmbrandx...]"
/// let result = vmaware::brand_with(&[vmaware::flags::MULTIPLE])?;
///
/// // example output: "VMware or Bochs"
/// println!("{result}");
///
/// // Keep in mind that there's no limit to how many conflicts there can be.
/// // And if there's no conflict, it'll revert back to giving the brand string
/// // normally as if the MULTIPLE flag wasn't there
/// # Ok(())
/// # }
/// ```
///
/// > [!NOTE]
/// > you can use the same flag system as shown with [`detect_with`] for
/// > [`brand_with`]
///
/// > [!IMPORTANT]
/// > [`flags::MULTIPLE`] has no effect for any other function other than
/// > [`brand_with`]
pub fn brand() -> Result<String, Error> {
    call_string(|out, error| unsafe { vmaware_try_brand(out, error) })
}

/// Returns the detected brand using a specific set of flags.
///
/// Pass [`flags::MULTIPLE`] to allow VMAware to report multiple possible brands.
/// An empty slice has the same behavior as [`brand`].
pub fn brand_with(flags: &[u8]) -> Result<String, Error> {
    call_string(|out, error| unsafe {
        vmaware_try_brand_with(flags.as_ptr(), flags.len(), out, error)
    })
}

/// This will return the VM type (or architecture) as a `String` based on
/// the brand found. The possible return values are listed in VMAware's brand
/// table in the `type` column.
///
/// ```no_run
/// # fn main() -> Result<(), vmaware::Error> {
/// // example output: VirtualBox is a Hypervisor (type 2) VM
/// println!("{} is a {} VM", vmaware::brand()?, vmaware::vm_type()?);
/// # Ok(())
/// # }
/// ```
pub fn vm_type() -> Result<String, Error> {
    call_string(|out, error| unsafe { vmaware_try_type(out, error) })
}

/// Returns the detected environment category using a specific set of flags.
///
/// An empty slice has the same behavior as [`vm_type`].
pub fn vm_type_with(flags: &[u8]) -> Result<String, Error> {
    call_string(|out, error| unsafe {
        vmaware_try_type_with(flags.as_ptr(), flags.len(), out, error)
    })
}

/// This will return the "conclusion" message of what the overall result is as a
/// `String`. By default, there are 2 possible outputs:
/// - `Running on baremetal`
/// - `Running inside a [brand] VM`
///
/// The `[brand]` part might contain a brand or may as well be empty, depending
/// on whether a brand has been found. Additionally, you can extend this by
/// adding the [`flags::DYNAMIC`] flag which will now allow much more variadic
/// potential outputs:
/// - `Running on baremetal`
/// - `Very unlikely a [brand] VM`
/// - `Unlikely a [brand] VM`
/// - `Potentially a [brand] VM`
/// - `Might be a [brand] VM`
/// - `Likely a [brand] VM`
/// - `Very likely a [brand] VM`
/// - `Running inside a [brand] VM`
pub fn conclusion() -> Result<String, Error> {
    call_string(|out, error| unsafe { vmaware_try_conclusion(out, error) })
}

/// Returns VMAware's conclusion using a specific set of flags.
///
/// Pass [`flags::DYNAMIC`] to enable VMAware's dynamic likelihood messages. An
/// empty slice has the same behavior as [`conclusion`].
pub fn conclusion_with(flags: &[u8]) -> Result<String, Error> {
    call_string(|out, error| unsafe {
        vmaware_try_conclusion_with(flags.as_ptr(), flags.len(), out, error)
    })
}

/// This will take a technique flag enum as an argument and return the string
/// version of it. For example:
///
/// ```no_run
/// # fn main() -> Result<(), vmaware::Error> {
/// let name = vmaware::flag_to_string(vmaware::flags::VMID)?;
///
/// // output: VM::VMID
/// println!("VM::{name}");
/// # Ok(())
/// # }
/// ```
///
/// The reason why this exists is because it can be useful for debugging and
/// infodumping purposes. It should be noted that the "VM::" part is not
/// included in the string output, so that's based on the programmer's choice if
/// it should remain in the string or not. The example given above is obviously
/// useless since the whole code can be manually handwritten, but the function is
/// especially convenient if it's being used with a list of technique flags. For
/// example:
///
/// ```no_run
/// # fn main() -> Result<(), vmaware::Error> {
/// // this will loop through technique enums,
/// // and then checks each of them and outputs the enum that was detected
/// for technique_enum in [vmaware::flags::VMID, vmaware::flags::HYPERVISOR_BIT] {
///     if vmaware::check(technique_enum)? {
///         let name = vmaware::flag_to_string(technique_enum)?;
///         println!("VM::{name} was detected");
///     }
/// }
/// # Ok(())
/// # }
/// ```
pub fn flag_to_string(flag: u8) -> Result<String, Error> {
    call_string(|out, error| unsafe { vmaware_try_flag_to_string(flag, out, error) })
}

fn call_value(call: impl FnOnce(*mut *mut c_char) -> bool) -> Result<(), Error> {
    let mut error = ptr::null_mut();

    if call(&mut error) {
        Ok(())
    } else {
        Err(take_error(error))
    }
}

fn call_string(
    call: impl FnOnce(*mut *mut c_char, *mut *mut c_char) -> bool,
) -> Result<String, Error> {
    let mut out = ptr::null_mut();
    let mut error = ptr::null_mut();

    if call(&mut out, &mut error) {
        Ok(take_string(out))
    } else {
        Err(take_error(error))
    }
}

fn take_error(value: *mut c_char) -> Error {
    let message = take_string(value);
    Error {
        message: if message.is_empty() {
            "unknown C++ exception".to_string()
        } else {
            message
        },
    }
}

fn take_string(value: *mut c_char) -> String {
    if value.is_null() {
        return String::new();
    }

    let result = unsafe { CStr::from_ptr(value) }
        .to_string_lossy()
        .into_owned();
    unsafe { vmaware_string_free(value) };
    result
}
