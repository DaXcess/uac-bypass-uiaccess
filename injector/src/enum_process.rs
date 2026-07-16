//! Helper module that allows lazily enumerating Windows processes
//!
//! # Example
//!
//! ```
//! // Prints each process ID to the screen
//! let processes = EnumProcesses::new().unwrap();
//!
//! for process_entry in processes {
//!     println!("Process ID: {}", process_entry.th32ProcessID);
//! }
//! ```

use std::io;

use windows::Win32::{
    Foundation::HANDLE,
    System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32, Process32First, Process32Next, TH32CS_SNAPPROCESS,
    },
};

pub struct EnumProcess {
    snapshot: HANDLE,
    current: Option<PROCESSENTRY32>,
}

impl EnumProcess {
    pub fn new() -> io::Result<Self> {
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)? };

        let mut entry = PROCESSENTRY32::default();
        entry.dwSize = size_of_val(&entry) as _;

        unsafe {
            Process32First(snapshot, &mut entry)?;
        }

        Ok(Self {
            snapshot,
            current: Some(entry),
        })
    }

    pub fn next_process(&mut self) -> Option<PROCESSENTRY32> {
        let result = self.current.take();
        let mut entry = PROCESSENTRY32::default();
        entry.dwSize = size_of_val(&entry) as _;

        unsafe {
            if Process32Next(self.snapshot, &mut entry).is_ok() {
                _ = self.current.insert(entry);
            }
        }

        return result;
    }
}

impl Iterator for EnumProcess {
    type Item = PROCESSENTRY32;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_process()
    }
}
