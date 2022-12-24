use anyhow::Result;
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
