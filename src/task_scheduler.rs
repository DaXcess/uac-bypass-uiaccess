//! Minimal wrapper around the Windows Task Scheduler that allows us to run existing tasks

use std::io;

use windows::{
    Win32::System::{
        Com::{CLSCTX_ALL, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx},
        TaskScheduler::{ITaskService, TaskScheduler},
        Variant::VARIANT,
    },
    core::BSTR,
};

pub struct TaskManager(ITaskService);

impl TaskManager {
    pub fn new() -> io::Result<Self> {
        unsafe {
            CoInitializeEx(None, COINIT_MULTITHREADED).ok()?;

            let task_service: ITaskService = CoCreateInstance(&TaskScheduler, None, CLSCTX_ALL)?;
            task_service.Connect(
                &VARIANT::default(),
                &VARIANT::default(),
                &VARIANT::default(),
                &VARIANT::default(),
            )?;

            Ok(Self(task_service))
        }
    }

    pub fn run_task(&self, path: &str, name: &str) -> io::Result<()> {
        unsafe {
            let folder = self.0.GetFolder(&BSTR::from(path))?;
            let task = folder.GetTask(&BSTR::from(name))?;

            task.Run(&VARIANT::default())?;
        }

        Ok(())
    }
}
