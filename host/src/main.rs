use std::ffi::CString;

use host::{HostError, HostResult, UserProcess};
use nix::{
    libc::{MAP_ANONYMOUS, MAP_PRIVATE, PROT_READ, PROT_WRITE},
    unistd::Pid,
};
use syscalls::Sysno;
use sysinfo::{ProcessExt, System, SystemExt};

fn main() -> HostResult<()> {
    pretty_env_logger::formatted_builder()
        .filter_level(log::LevelFilter::Trace)
        .init();

    let process_name = "victim";
    log::info!("Host Process Pid: {}", std::process::id());

    // Create sysinfo object and refresh to collect current os state
    let mut sys = System::new_all();
    sys.refresh_all();

    // Find our target process or die
    let process = sys
        .processes_by_name(process_name)
        .take(1)
        .next()
        .ok_or_else(|| HostError::ProcessNotFound(process_name.to_string()))?;

    // Cast our sysinfo::Pid into a nix::unistd::Pid
    let pid = Pid::from_raw(process.pid().into());

    // Attach to the process
    let user_process = UserProcess::attach(pid)?;

    // Refactor out the expect later, but the input should never fail because we know the input does not contain an internal 0 byte.
    let output_message = CString::new("/home/chase").expect("CString::new failed");

    // We want the bytes of the Cstring.
    let output_message = output_message.as_bytes();

    // Allocate 8 bytes of data, i64 is 8 bytes
    let mut user_memory = user_process.allocate_memory(
        0,
        output_message.len() as u64,
        (PROT_READ | PROT_WRITE) as u64,
        (MAP_PRIVATE | MAP_ANONYMOUS) as u64,
        u64::MAX,
        0,
    )?;
    log::info!("UserMemory Result Address: {:#X}", user_memory.address());

    // Read the memory and demonstrate it is zero'd out
    let read = user_process.read_user_memory(&user_memory, user_memory.len() as usize)?;
    log::info!("Allocated Memory: {:?}", read);

    // Write to the memory out cstring
    user_process.write_user_memory(&mut user_memory, 0, output_message)?;

    // We can check if the call succeeded by the resultant rax value.
    let result = user_process
        .sys_call(Sysno::chdir, user_memory.address(), 0, 0, 0, 0, 0)?
        .rax;

    log::info!("Result {result:?}");

    Ok(())
}
