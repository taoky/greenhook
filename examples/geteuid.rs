use std::process::Command;

use greenhook::{Supervisor, UNotifyEventRequest};
use libseccomp::ScmpSyscall;

fn geteuid_handler(req: &UNotifyEventRequest) -> libseccomp::ScmpNotifResp {
    req.return_syscall(0)
}

fn main() {
    env_logger::init();
    // Get argv[1]
    let program = std::env::args().nth(1).unwrap();
    let mut supervisor = Supervisor::new(2).unwrap();
    supervisor
        .handlers
        .insert(ScmpSyscall::new("geteuid"), geteuid_handler);
    let mut cmd = Command::new(program);
    let (mut child, thread_handle, pool) = supervisor.exec(&mut cmd).unwrap();
    let _ = Supervisor::wait(&mut child, thread_handle, pool).unwrap();
}
