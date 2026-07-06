use std::io::{self, Error, ErrorKind};

use windows::Win32::{
    Foundation::HANDLE,
    Security::{
        GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, TOKEN_MANDATORY_LABEL,
        TOKEN_QUERY, TokenElevation, TokenIntegrityLevel, TokenUIAccess,
    },
    System::Threading::{
        GetCurrentProcessId, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    },
};

use crate::{enum_process::EnumProcesses, process::guards::HandleGuard};

pub fn find_target_process() -> io::Result<Vec<u32>> {
    let own_pid = unsafe { GetCurrentProcessId() };
    let iter = EnumProcesses::new()?;

    let mut candidates = vec![];

    for process in iter {
        if process.th32ProcessID == own_pid {
            continue;
        }

        if check_elevated_process(process.th32ProcessID).is_ok() {
            candidates.push(process.th32ProcessID);
        }
    }

    Ok(candidates)
}

fn check_elevated_process(pid: u32) -> io::Result<()> {
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)? };
    let _guard = HandleGuard(handle);

    let mut token = HANDLE::default();
    unsafe { OpenProcessToken(handle, TOKEN_QUERY, &mut token)? };
    let _guard = HandleGuard(token);

    if let Ok(true) = get_token_uiaccess(token) {
        return Err(Error::new(
            ErrorKind::Other,
            "cannot target UIAccess process",
        ));
    }

    let Ok(0x3000) = get_token_il(token) else {
        return Err(Error::new(
            ErrorKind::Other,
            "cannot target non-high IL process",
        ));
    };

    let Ok(true) = get_token_elevated(token) else {
        return Err(Error::new(
            ErrorKind::Other,
            "cannot target process with stripped privileges",
        ));
    };

    Ok(())
}

fn get_token_uiaccess(token: HANDLE) -> io::Result<bool> {
    let mut length = 0;
    let mut value = 0u32;

    unsafe {
        GetTokenInformation(
            token,
            TokenUIAccess,
            Some(&mut value as *mut _ as *mut _),
            4,
            &mut length,
        )?;
    }

    Ok(value != 0)
}

fn get_token_il(token: HANDLE) -> io::Result<u32> {
    let mut length = 0;

    let err = unsafe { GetTokenInformation(token, TokenIntegrityLevel, None, 0, &mut length) };
    if length == 0 {
        return Err(err.unwrap_err().into());
    }

    let mut buffer = vec![0u8; length as _];
    unsafe {
        GetTokenInformation(
            token,
            TokenIntegrityLevel,
            Some(buffer.as_mut_ptr() as _),
            length,
            &mut length,
        )?;
    }

    let label = unsafe { &*(buffer.as_ptr() as *const TOKEN_MANDATORY_LABEL) };
    let count = unsafe { *GetSidSubAuthorityCount(label.Label.Sid) };
    let level = unsafe { *GetSidSubAuthority(label.Label.Sid, count as u32 - 1) };

    Ok(level)
}

fn get_token_elevated(token: HANDLE) -> io::Result<bool> {
    let mut length = 0;
    let mut elevated = 0u32;

    unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevated as *mut _ as *mut _),
            4,
            &mut length,
        )?
    };

    Ok(elevated != 0)
}

mod guards {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};

    pub struct HandleGuard(pub HANDLE);

    impl Drop for HandleGuard {
        fn drop(&mut self) {
            if self.0.is_invalid() {
                return;
            }

            unsafe {
                _ = CloseHandle(self.0);
            }
        }
    }
}
