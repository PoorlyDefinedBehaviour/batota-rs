use std::time::Duration;

use anyhow::Result;
use tracing::info;
use windows::Win32::{
    Foundation::CloseHandle,
    System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
    },
};

use crate::string;

pub type ProcessId = u32;

/// Finds the id of a process using the process name.
///
/// # Example
///
/// ```norun
/// dbg!(get_proc_id("notepad.exe"));
/// ```
pub fn get_proc_id(process_name: &str) -> Result<Option<ProcessId>> {
    unsafe {
        let mut proc_entry_32 = PROCESSENTRY32::default();
        proc_entry_32.dwSize = std::mem::size_of_val(&proc_entry_32) as u32;

        let hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)?;

        while Process32Next(hsnap, &mut proc_entry_32 as *mut _).as_bool() {
            if process_name == string::chars_to_string(&proc_entry_32.szExeFile) {
                CloseHandle(hsnap);
                return Ok(Some(proc_entry_32.th32ProcessID));
            }
        }

        CloseHandle(hsnap);
        Ok(None)
    }
}

/// Waits for a process to start executing and then tries
/// to get its process id.
///
/// # Example
///
/// ```norun
/// let proc_id = wait_for_proc("notepad.exe");
/// ```
#[tracing::instrument(name = "wait_for_proc_id", skip_all, fields(
    proc_name = ?proc_name
))]
pub fn wait_for_proc_id(proc_name: &str) -> ProcessId {
    loop {
        if let Ok(maybe_proc_id) = get_proc_id(proc_name) {
            if let Some(proc_id) = maybe_proc_id {
                tracing::Span::current().record("proc_id", proc_id);
                return proc_id;
            }
        }

        info!("waiting for {} to start executing", proc_name);
        std::thread::sleep(Duration::from_secs(1));
    }
}
