use std::{ffi::CStr, fs::File, os::fd::AsRawFd, process::Command};

use greenhook::{RemoteProcess, Supervisor, UNotifyEventRequest};
use libseccomp::ScmpSyscall;
use log::info;
use nix::{libc, unistd::Pid};

fn openat_handler(req: &UNotifyEventRequest) -> libseccomp::ScmpNotifResp {
    let path = req.get_request().data.args[1];
    let remote = RemoteProcess::new(Pid::from_raw(req.get_request().pid as i32)).unwrap();
    let mut buf = [0u8; 256];
    remote.read_mem(&mut buf, path as usize).unwrap();
    // debug!("open (read from remote): {:?}", buf);
    let path = CStr::from_bytes_until_nul(&buf).unwrap();
    if !req.is_valid() {
        return req.fail_syscall(libc::EACCES);
    }
    info!("open (path CStr): {:?}", path);
    if path.to_str().unwrap() == "/etc/passwd" {
        // open /etc/resolv.conf instead
        let file = File::open("/etc/resolv.conf").unwrap();
        let fd = file.as_raw_fd();
        let remote_fd = req.add_fd(fd).unwrap();
        req.return_syscall(remote_fd as i64)
    } else {
        unsafe { req.continue_syscall() }
    }
}

fn main() {
    env_logger::init();
    // Get argv[1..]
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() == 0 {
        panic!(
            "Usage: {} <program> [args...]",
            std::env::args().nth(0).unwrap()
        );
    }
    let mut supervisor = Supervisor::new(2).unwrap();
    supervisor.insert_handler(ScmpSyscall::new("openat"), openat_handler);
    let mut cmd = Command::new(args[0].clone());
    let cmd = cmd.args(&args[1..]);
    let (mut child, thread_handle, pool) = supervisor.exec(cmd).unwrap();
    let _ = Supervisor::wait(&mut child, thread_handle, pool).unwrap();
}
