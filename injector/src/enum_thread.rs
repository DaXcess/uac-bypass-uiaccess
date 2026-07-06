use std::io;

use windows::Win32::{
    Foundation::HANDLE,
    System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
    },
};

pub struct EnumThreads {
    snapshot: HANDLE,
    current: Option<THREADENTRY32>,
}

impl EnumThreads {
    pub fn new(pid: u32) -> io::Result<Self> {
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid)? };

        let mut entry = THREADENTRY32::default();
        entry.dwSize = size_of_val(&entry) as _;

        unsafe {
            Thread32First(snapshot, &mut entry)?;
        }

        Ok(Self {
            snapshot,
            current: Some(entry),
        })
    }

    pub fn next_thread(&mut self) -> Option<THREADENTRY32> {
        let result = self.current.take();
        let mut entry = THREADENTRY32::default();
        entry.dwSize = size_of_val(&entry) as _;

        unsafe {
            if Thread32Next(self.snapshot, &mut entry).is_ok() {
                _ = self.current.insert(entry);
            }
        }

        return result;
    }
}

impl Iterator for EnumThreads {
    type Item = THREADENTRY32;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_thread()
    }
}
