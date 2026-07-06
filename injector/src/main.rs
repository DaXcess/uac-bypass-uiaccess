use std::time::Duration;

use windows::{
    Win32::{
        Foundation::{HWND, LPARAM, WPARAM},
        UI::WindowsAndMessaging::{
            EnumThreadWindows, GetWindowThreadProcessId, PostThreadMessageA, SetWindowsHookExA,
            UnhookWindowsHookEx, WH_GETMESSAGE,
        },
    },
    core::BOOL,
};

use crate::{enum_thread::EnumThreads, loader::LoadedModule};

mod enum_thread;
mod loader;

struct InjectParams {
    module: LoadedModule,
}

fn main() {
    let mut args = std::env::args().skip(1);

    let target_pid: u32 = args.next().unwrap().parse().unwrap();
    let module_path = args.next().unwrap();

    let module = match loader::load_module(&module_path) {
        Ok(module) => module,
        Err(why) => {
            eprintln!("Failed to load module: {why}");
            return;
        }
    };

    let iter = match EnumThreads::new(target_pid) {
        Ok(iter) => iter,
        Err(why) => {
            eprintln!("Failed to enumerate target process threads: {why}");
            return;
        }
    };

    let params = Box::new(InjectParams { module });
    let params_raw = Box::into_raw(params);

    for thread in iter {
        if thread.th32OwnerProcessID != target_pid {
            continue;
        }

        unsafe {
            _ = EnumThreadWindows(
                thread.th32ThreadID,
                Some(try_inject_thread),
                LPARAM(params_raw as isize),
            );
        }
    }
}

unsafe extern "system" fn try_inject_thread(hwnd: HWND, params: LPARAM) -> BOOL {
    let thread_id = unsafe { GetWindowThreadProcessId(hwnd, None) };
    let params = unsafe { &*(params.0 as *const InjectParams) };

    let hook = match unsafe {
        SetWindowsHookExA(
            WH_GETMESSAGE,
            std::mem::transmute(params.module.get_proc_address()),
            Some(params.module.get_module_handle()),
            thread_id,
        )
    } {
        Ok(hook) => hook,
        Err(why) => {
            eprintln!("Failed to set hook: {why}");
            return true.into();
        }
    };

    let mut tries = 10;
    let mut success = false;

    loop {
        std::thread::sleep(Duration::from_millis(250));

        let post_success = unsafe {
            PostThreadMessageA(
                GetWindowThreadProcessId(hwnd, None),
                0x511,
                WPARAM::default(),
                LPARAM(hook.0 as _),
            )
            .is_ok()
        };

        success = success || post_success;
        tries -= 1;

        if tries == 0 || success {
            break;
        }
    }

    if !success {
        eprintln!("Failed to post message after 10 tries");

        unsafe {
            _ = UnhookWindowsHookEx(hook);
        }

        return true.into();
    }

    false.into()
}

#[unsafe(no_mangle)]
pub extern "system" fn is_injector() -> isize {
    1
}
