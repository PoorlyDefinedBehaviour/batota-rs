use std::process::Command;

use crate::{memory::Address, process::ProcessId};
use anyhow::{anyhow, Context, Result};
use tracing::{error, info};
use windows::Win32::System::{
    LibraryLoader::{GetProcAddress, LoadLibraryA},
    Threading::GetCurrentProcessId,
};

/// The code of instructions that can be sent to the kernerl.
#[derive(Debug)]
#[repr(u32)]
pub enum KernelInstruction {
    GetModBase = 1,
    Read,
    Write,
    VirtualQuery,
    GetMappedFilename,
    GetDrvInfo,
    ReadKernel,
    IsRunning,
}

/// Error generated when a kernel request fails.
#[derive(Debug, thiserror::Error)]
#[error("kernel request did not succeed")]
pub struct KernelRequestError;

/// A kernel request.
#[derive(Debug)]
#[repr(C)]
pub struct KernelRequest {
    check_code: u32,
    instruction_id: u32,
    source_proc_id: ProcessId,
    target_proc_id: ProcessId,
    target_address: usize,
    buffer: usize,
    size: u32,
    response: *const (),
    succeed: bool,
}

/// Responsible for sending requests to the kernel.
pub struct Driver {
    current_proc_id: u32,
    user_set_proc_window_station: unsafe extern "system" fn() -> isize,
}

impl std::fmt::Debug for Driver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Driver")
            .field("current_proc_id", &self.current_proc_id)
            .field(
                "user_set_proc_window_station",
                &format!("0x{:x?}", self.user_set_proc_window_station as usize),
            )
            .finish()
    }
}

impl Driver {
    #[tracing::instrument(name = "Driver::new", skip_all, fields(
        driver_path = ?driver_path
    ))]
    pub fn new(driver_path: &str) -> Result<Self> {
        unsafe {
            let _ = LoadLibraryA("user32.dll")?;
            let win32udll_hinstance = LoadLibraryA("win32u.dll")?;

            let user_set_proc_window_station =
                GetProcAddress(win32udll_hinstance, "NtUserSetProcessWindowStation")
                    .context("getting NtUserSetProcessWindowStation proc address")?;

            let current_proc_id = GetCurrentProcessId();

            let driver = Self {
                current_proc_id,
                user_set_proc_window_station,
            };

            info!(
                "driver spawned. stdout={}",
                String::from_utf8_lossy(&Driver::spawn_driver_program(driver_path)?.stdout)
            );

            if let Err(error) = driver.test_communicate() {
                error!(
                    ?error,
                    "[x]    Failed to communicate with driver. Make sure driver is loaded"
                );
                return Err(error.into());
            };

            Ok(driver)
        }
    }

    #[tracing::instrument(name = "Driver::spawn_driver_program", skip_all, fields(
        driver_path = ?driver_path
    ))]
    pub fn spawn_driver_program(driver_path: &str) -> Result<std::process::Output> {
        let output = Command::new("./kdu.exe")
            .arg("-scv")
            .arg("3")
            .arg("-drvn")
            .arg("nw-object")
            .arg("-drvr")
            .arg("nw")
            .arg("-map")
            .arg(driver_path)
            .output()
            .context("spawning driver program")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        if !output.status.success() || stdout.contains("Input file cannot be found") {
            Err(anyhow!(format!("stdout={}\n\nstderr={}", stdout, stderr)))
        } else {
            Ok(output)
        }
    }

    #[tracing::instrument(name = "Driver::get_module_base", skip_all, fields(
        target_proc_id = ?target_proc_id,
        mod_name = ?mod_name
    ))]
    pub fn get_module_base(
        &self,
        target_proc_id: ProcessId,
        mod_name: &str,
    ) -> Result<usize, KernelRequestError> {
        unsafe {
            let mut request = KernelRequest {
                check_code: 0x696969,
                instruction_id: KernelInstruction::GetModBase as u32,
                source_proc_id: self.current_proc_id,
                target_proc_id: target_proc_id,
                // TODO: fix
                target_address: 0,
                // TODO: may be wrong
                buffer: mod_name.as_ptr() as usize,
                size: 0,
                response: std::ptr::null(),
                succeed: false,
            };

            info!(?request, "request");

            let f: unsafe extern "system" fn(*mut KernelRequest) -> u64 =
                std::mem::transmute(self.user_set_proc_window_station);

            f(&mut request);

            if request.succeed {
                let address: usize = std::mem::transmute(request.response);
                Ok(address)
            } else {
                Err(KernelRequestError)
            }
        }
    }

    #[tracing::instrument(name = "Driver::read_process_memory", skip_all, fields(
        target_proc_id = ?target_proc_id,
        read_address = ?read_address,
        buffer_address = ?buffer_address,
        size = ?size,
    ))]
    pub fn read_process_memory(
        &self,
        target_proc_id: ProcessId,
        read_address: Address,
        buffer_address: Address,
        size: usize,
    ) -> Result<(), KernelRequestError> {
        unsafe {
            let mut request = KernelRequest {
                check_code: 0x696969,
                instruction_id: KernelInstruction::Read as u32,
                source_proc_id: self.current_proc_id,
                target_proc_id: target_proc_id,
                target_address: read_address,
                buffer: buffer_address,
                size: size as u32,
                response: std::ptr::null(),
                succeed: false,
            };

            info!(?request, "request");

            let f: unsafe extern "system" fn(*mut KernelRequest) -> u64 =
                std::mem::transmute(self.user_set_proc_window_station);

            f(&mut request);

            if request.succeed {
                Ok(())
            } else {
                Err(KernelRequestError)
            }
        }
    }

    #[tracing::instrument(name = "Driver::write_process_memory", skip_all, fields(
        target_proc_id = ?target_proc_id,
        write_address = ?write_address,
        buffer_address = ?buffer_address,
        size = ?size,
    ))]
    pub fn write_process_memory(
        &self,
        target_proc_id: ProcessId,
        write_address: Address,
        buffer_address: Address,
        size: usize,
    ) -> Result<(), KernelRequestError> {
        unsafe {
            let mut request = KernelRequest {
                check_code: 0x696969,
                instruction_id: KernelInstruction::Write as u32,
                source_proc_id: self.current_proc_id,
                target_proc_id: target_proc_id,
                target_address: write_address,
                buffer: buffer_address,
                size: size as u32,
                response: std::ptr::null(),
                succeed: false,
            };

            info!(?request, "request");

            let f: unsafe extern "system" fn(*mut KernelRequest) -> u64 =
                std::mem::transmute(self.user_set_proc_window_station);

            f(&mut request);

            if request.succeed {
                Ok(())
            } else {
                Err(KernelRequestError)
            }
        }
    }

    #[tracing::instrument(name = "Driver::virtual_query", skip_all, fields(
        target_proc_id = ?target_proc_id,
        address = ?address,
        buffer_address = ?buffer_address,
        size = ?size,
    ))]
    pub fn virtual_query(
        &self,
        target_proc_id: ProcessId,
        address: Address,
        buffer_address: Address,
        size: usize,
    ) -> Result<(), KernelRequestError> {
        unsafe {
            let mut request = KernelRequest {
                check_code: 0x696969,
                instruction_id: KernelInstruction::VirtualQuery as u32,
                source_proc_id: self.current_proc_id,
                target_proc_id: target_proc_id,
                target_address: address,
                buffer: buffer_address,
                size: size as u32,
                response: std::ptr::null(),
                succeed: false,
            };

            info!(?request, "request");

            let f: unsafe extern "system" fn(*mut KernelRequest) -> u64 =
                std::mem::transmute(self.user_set_proc_window_station);

            f(&mut request);

            if request.succeed {
                Ok(())
            } else {
                Err(KernelRequestError)
            }
        }
    }

    #[tracing::instrument(name = "Driver::get_mapped_file_name", skip_all, fields(
        target_proc_id = ?target_proc_id,
        address = ?address,
        buffer_address = ?buffer_address,
        size = ?size,
    ))]
    pub fn get_mapped_file_name(
        &self,
        target_proc_id: ProcessId,
        address: Address,
        buffer_address: Address,
        size: usize,
    ) -> Result<(), KernelRequestError> {
        unsafe {
            let mut request = KernelRequest {
                check_code: 0x696969,
                instruction_id: KernelInstruction::VirtualQuery as u32,
                source_proc_id: self.current_proc_id,
                target_proc_id: target_proc_id,
                target_address: address,
                buffer: buffer_address,
                size: size as u32,
                response: std::ptr::null(),
                succeed: false,
            };

            info!(?request, "request");

            let f: unsafe extern "system" fn(*mut KernelRequest) -> u64 =
                std::mem::transmute(self.user_set_proc_window_station);

            f(&mut request);

            if request.succeed {
                Ok(())
            } else {
                Err(KernelRequestError)
            }
        }
    }

    #[tracing::instrument(name = "Driver::test_communicate", skip_all)]
    pub fn test_communicate(&self) -> Result<(), KernelRequestError> {
        unsafe {
            let mut request = KernelRequest {
                check_code: 0x696969,
                instruction_id: KernelInstruction::IsRunning as u32,
                source_proc_id: self.current_proc_id,
                target_proc_id: 0,
                target_address: 0,
                buffer: 0,
                size: 0,
                response: std::ptr::null(),
                succeed: false,
            };

            info!(?request, "request");

            let f: unsafe extern "system" fn(*mut KernelRequest) -> u64 =
                std::mem::transmute(self.user_set_proc_window_station);

            f(&mut request);

            if request.succeed {
                Ok(())
            } else {
                Err(KernelRequestError)
            }
        }
    }

    #[tracing::instrument(name = "Driver::read_kernel_memory", skip_all, fields(
        read_address = ?read_address,
        buffer_address = ?buffer_address,
        size = ?size,
    ))]
    pub fn read_kernel_memory(
        &self,
        read_address: Address,
        buffer_address: Address,
        size: usize,
    ) -> Result<(), KernelRequestError> {
        unsafe {
            let mut request = KernelRequest {
                check_code: 0x696969,
                instruction_id: KernelInstruction::ReadKernel as u32,
                source_proc_id: self.current_proc_id,
                target_proc_id: 0,
                target_address: read_address,
                buffer: buffer_address,
                size: size as u32,
                response: std::ptr::null(),
                succeed: false,
            };

            info!(?request, "request");

            let f: unsafe extern "system" fn(*mut KernelRequest) -> u64 =
                std::mem::transmute(self.user_set_proc_window_station);

            f(&mut request);

            if request.succeed {
                Ok(())
            } else {
                Err(KernelRequestError)
            }
        }
    }

    #[tracing::instrument(name = "Driver::get_kernel_driver", skip_all, fields(
        buffer_address = ?buffer_address,
        size = ?size,
    ))]
    pub fn get_kernel_driver(
        &self,
        buffer_address: Address,
        size: usize,
    ) -> Result<(), KernelRequestError> {
        unsafe {
            let mut request = KernelRequest {
                check_code: 0x696969,
                instruction_id: KernelInstruction::GetDrvInfo as u32,
                source_proc_id: self.current_proc_id,
                target_proc_id: 0,
                target_address: 0,
                buffer: buffer_address,
                size: 0,
                response: std::ptr::null(),
                succeed: false,
            };

            info!(?request, "request");

            let f: unsafe extern "system" fn(*mut KernelRequest) -> u64 =
                std::mem::transmute(self.user_set_proc_window_station);

            f(&mut request);

            if request.succeed {
                Ok(())
            } else {
                Err(KernelRequestError)
            }
        }
    }
}
