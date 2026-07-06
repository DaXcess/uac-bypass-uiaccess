use std::{
    io::{self, Error, ErrorKind},
    os::windows::ffi::OsStrExt,
    path::Path,
};

use windows::{
    Win32::{
        Foundation::{FreeLibrary, HINSTANCE, HMODULE},
        System::LibraryLoader::{GetProcAddress, LoadLibraryW},
    },
    core::{PCSTR, PCWSTR},
};

pub struct LoadedModule {
    module: HMODULE,
    proc: isize,
}

impl LoadedModule {
    #[must_use]
    pub fn get_module_handle(&self) -> HINSTANCE {
        HINSTANCE(self.module.0)
    }

    #[must_use]
    pub fn get_proc_address(&self) -> isize {
        self.proc
    }
}

impl Drop for LoadedModule {
    fn drop(&mut self) {
        if self.module.is_invalid() {
            return;
        }

        unsafe {
            _ = FreeLibrary(self.module);
        }

        self.module = HMODULE::default();
    }
}

pub fn load_module<P: AsRef<Path>>(path: P) -> io::Result<LoadedModule> {
    let path = path.as_ref();
    let path_w = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();

    let module = unsafe { LoadLibraryW(PCWSTR(path_w.as_ptr()))? };
    let proc = unsafe {
        GetProcAddress(module, PCSTR(b"windows_hook_proc\0".as_ptr())).ok_or_else(|| {
            Error::new(ErrorKind::NotFound, "procedure not found in loaded module")
        })?
    };

    Ok(LoadedModule {
        module,
        proc: proc as isize,
    })
}
