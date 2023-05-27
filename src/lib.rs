use std::{
    collections::HashMap,
    io::{self, IoSliceMut},
    mem::{self, size_of},
    os::{fd::RawFd, unix::process::CommandExt},
    process::{Child, Command, ExitStatus},
    ptr,
    thread::JoinHandle,
};

use libseccomp::{ScmpAction, ScmpFilterContext, ScmpNotifReq, ScmpNotifRespFlags, ScmpSyscall};
use log::debug;
use nix::{
    cmsg_space,
    errno::Errno,
    libc::{self, c_uint, c_void, cmsghdr, msghdr, CMSG_DATA, CMSG_FIRSTHDR, CMSG_LEN, CMSG_SPACE},
    poll::{PollFd, PollFlags},
    sys::{
        socket::{
            recvmsg, socketpair, AddressFamily, ControlMessageOwned, MsgFlags, SockFlag, SockType,
        },
        uio::{process_vm_readv, RemoteIoVec},
    },
    unistd::{close, Pid},
};

// SocketPair is used to copy fd from child to parent
// with sendmsg/recvmsg and SCM_RIGHTS
#[derive(Debug)]
struct SocketPair {
    // child fd
    sender: RawFd,
    // parent fd
    receiver: RawFd,
}

struct Sender {
    fd: RawFd,
}

struct Receiver {
    fd: RawFd,
}

impl SocketPair {
    pub(crate) fn init() -> Result<Self, io::Error> {
        let pairs = socketpair(
            AddressFamily::Unix,
            SockType::Stream,
            None,
            SockFlag::SOCK_CLOEXEC,
        )?;
        Ok(SocketPair {
            sender: pairs.0,
            receiver: pairs.1,
        })
    }

    pub(crate) fn channel(self) -> (Sender, Receiver) {
        (Sender { fd: self.sender }, Receiver { fd: self.receiver })
    }
}

impl Sender {
    // nix::sys::socket::sendmsg allocates when cmsgs is not empty
    // which is not a good idea inside pre_exec
    // ref: nix's sendmsg implementation (MIT license)
    // (https://github.com/nix-rust/nix/blob/c6f9e2332efcf62c751d7a0174bb791e732b90a8/src/sys/socket/mod.rs#L1474)
    pub(crate) fn sendfd(&self, fd: RawFd) -> Result<(), io::Error> {
        const FD_SIZE: c_uint = size_of::<RawFd>() as c_uint;
        const CAPACITY: u32 = unsafe { CMSG_SPACE(FD_SIZE) };
        let buf = [0u8; CAPACITY as usize];
        let cmsg_ptr = buf.as_ptr() as *mut c_void;
        let mut _binding = [0; 1];
        let mut _iov_buffer = [IoSliceMut::new(&mut _binding); 1];

        let mhdr = unsafe {
            // Musl's msghdr has private fields, so this is the only way to
            // initialize it.
            let mut mhdr = mem::MaybeUninit::<msghdr>::zeroed();
            let p = mhdr.as_mut_ptr();
            (*p).msg_name = ptr::null::<()>() as *mut _;
            (*p).msg_namelen = 0;
            // transmute iov into a mutable pointer.  sendmsg doesn't really mutate
            // the buffer, but the standard says that it takes a mutable pointer
            (*p).msg_iov = _iov_buffer.as_ref().as_ptr() as *mut _;
            (*p).msg_iovlen = 1;
            (*p).msg_control = cmsg_ptr;
            (*p).msg_controllen = CAPACITY as _;
            (*p).msg_flags = 0;
            mhdr.assume_init()
        };

        let mut pmhdr: *mut cmsghdr = unsafe { CMSG_FIRSTHDR(&mhdr) };

        unsafe {
            (*pmhdr).cmsg_level = libc::SOL_SOCKET;
            (*pmhdr).cmsg_type = libc::SCM_RIGHTS;
            (*pmhdr).cmsg_len = CMSG_LEN(FD_SIZE) as usize;
            ptr::copy_nonoverlapping(
                &[fd] as *const _ as *const u8,
                CMSG_DATA(pmhdr),
                FD_SIZE as usize,
            )
        }
        let ret = unsafe { libc::sendmsg(self.fd, &mhdr, 0) };

        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

impl Drop for Sender {
    fn drop(&mut self) {
        let _ = close(self.fd);
    }
}

impl Receiver {
    pub(crate) fn recvfd(&self) -> Result<RawFd, io::Error> {
        let mut cmsg_buffer = cmsg_space!(RawFd);
        let mut _binding = [0; 1];
        let mut _iov_buffer = [IoSliceMut::new(&mut _binding); 1];
        let res = recvmsg::<()>(
            self.fd,
            &mut _iov_buffer,
            Some(&mut cmsg_buffer),
            MsgFlags::empty(),
        )
        .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
        for cmsg in res.cmsgs() {
            if let ControlMessageOwned::ScmRights(fds) = cmsg {
                return Ok(fds[0]);
            }
        }
        Err(io::Error::from_raw_os_error(libc::EINVAL))
    }
}

impl Drop for Receiver {
    fn drop(&mut self) {
        let _ = close(self.fd);
    }
}

#[derive(Debug)]
pub struct UNotifyEventRequest {
    request: libseccomp::ScmpNotifReq,
    notify_fd: RawFd,
}

impl UNotifyEventRequest {
    fn new(request: libseccomp::ScmpNotifReq, notify_fd: RawFd) -> Self {
        UNotifyEventRequest { request, notify_fd }
    }

    pub fn get_request(&self) -> &libseccomp::ScmpNotifReq {
        &self.request
    }

    /// CAUTION! This method is unsafe because it may suffer TOCTOU attack.
    ///
    /// # Safety
    /// Please read seccomp_unotify(2) "NOTES/Design goals; use of SECCOMP_USER_NOTIF_FLAG_CONTINUE"
    /// before using this method.
    pub unsafe fn continue_syscall(&self) -> libseccomp::ScmpNotifResp {
        libseccomp::ScmpNotifResp::new(self.request.id, 0, 0, ScmpNotifRespFlags::CONTINUE.bits())
    }

    pub fn fail_syscall(&self, err: i32) -> libseccomp::ScmpNotifResp {
        libseccomp::ScmpNotifResp::new(self.request.id, 0, err, 0)
    }

    pub fn return_syscall(&self, val: i64) -> libseccomp::ScmpNotifResp {
        libseccomp::ScmpNotifResp::new(self.request.id, val, 0, 0)
    }

    pub fn is_valid(&self) -> bool {
        libseccomp::notify_id_valid(self.notify_fd, self.request.id).is_ok()
    }
}

pub struct RemoteProcess {
    pid: Pid,
    fd: RawFd,
}

impl RemoteProcess {
    pub fn new(pid: Pid) -> Result<Self, io::Error> {
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid.as_raw(), 0) };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(RemoteProcess {
                pid,
                fd: fd as RawFd,
            })
        }
    }

    // pidfd_getfd(), Linux 5.6
    /// Get file descriptor from remote process. This function requires Linux 5.6+.
    pub fn get_fd(&self, remote_fd: RawFd) -> Result<RawFd, io::Error> {
        let local_fd = unsafe { libc::syscall(libc::SYS_pidfd_getfd, self.fd, remote_fd, 0) };
        if local_fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(local_fd as RawFd)
        }
    }

    // process_vm_readv
    /// Read data from remote process's memory.
    /// You should run is_valid() after this method to check if the remote process and corresponding syscall
    /// is still alive.
    pub fn read_mem(
        &self,
        local_buffer: &mut [u8],
        remote_addr: usize,
    ) -> Result<usize, io::Error> {
        let len = local_buffer.len();
        let mut local_iov = [IoSliceMut::new(local_buffer)];
        let remote_iov = [RemoteIoVec {
            base: remote_addr,
            len,
        }];
        process_vm_readv(self.pid, &mut local_iov, &remote_iov)
            .map_err(|e| io::Error::from_raw_os_error(e as i32))
    }
}

impl Drop for RemoteProcess {
    fn drop(&mut self) {
        let _ = close(self.fd);
    }
}

type UserHookFunc = Box<dyn Fn(&UNotifyEventRequest) -> libseccomp::ScmpNotifResp + Sync + Send>;

pub struct Supervisor {
    pub handlers: HashMap<ScmpSyscall, UserHookFunc>,
    socket_pair: SocketPair,
}

// pub unsafe fn cancel_thread(thread_handle: JoinHandle<()>) -> Result<(), io::Error> {
//     let res = unsafe { pthread_cancel(thread_handle.into_pthread_t()) };
//     if res != 0 {
//         return Err(io::Error::last_os_error());
//     }
//     Ok(())
// }

macro_rules! loop_while_eintr {
    ($poll_expr: expr) => {
        loop {
            match $poll_expr {
                Ok(nfds) => break Ok(nfds),
                Err(Errno::EINTR) => (),
                Err(e) => break Err(e),
            }
        }
    };
}

impl Supervisor {
    pub fn new() -> Result<Self, io::Error> {
        Ok(Supervisor {
            socket_pair: SocketPair::init()?,
            handlers: HashMap::new(),
        })
    }

    /// Run a command with seccomp filter.
    /// This method will fork a child process, do some preparations and run the command in it.
    /// It returns a Child and a JoinHandle. The Child is the child process, and the JoinHandle
    /// is the supervisor thread. You should use `Supervisor::wait()` to wait for the child process
    pub fn exec(self, cmd: &mut Command) -> Result<(Child, JoinHandle<()>), io::Error> {
        let (sender, receiver) = self.socket_pair.channel();
        let syscall_list: Vec<_> = self.handlers.keys().copied().collect();
        unsafe {
            cmd.pre_exec(move || {
                let mut ctx = ScmpFilterContext::new_filter(ScmpAction::Allow).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::Other,
                        format!("failed to create seccomp filter: {}", e),
                    )
                })?;
                for syscall in syscall_list.iter() {
                    ctx.add_rule_exact(ScmpAction::Notify, *syscall)
                        .map_err(|e| {
                            io::Error::new(
                                io::ErrorKind::Other,
                                format!("failed to add rule: {}", e),
                            )
                        })?;
                }
                ctx.load().map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::Other,
                        format!("failed to load seccomp filter: {}", e),
                    )
                })?;
                let ufd = ctx.get_notify_fd().map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::Other,
                        format!("failed to get notify fd: {}", e),
                    )
                })?;

                sender.sendfd(ufd)?;
                close(ufd)?;
                Ok(())
            });
        }
        let child = cmd.spawn()?;
        let fd = receiver.recvfd()?;

        debug!("receiver got fd: {}", fd);

        let thread_handle = std::thread::spawn(move || {
            loop {
                // Poll fd first: is it readable?
                let mut pollfd = [PollFd::new(fd, PollFlags::POLLIN)];
                let poll_res = loop_while_eintr!(nix::poll::poll(&mut pollfd, -1));
                if let Err(e) = poll_res {
                    eprintln!("failed to poll: {}", e);
                    break;
                }
                match pollfd[0].revents() {
                    None => {
                        eprintln!("unknown poll event");
                        break;
                    }
                    Some(revents) => {
                        if revents.contains(PollFlags::POLLHUP) {
                            break;
                        }
                    }
                }
                // eprintln!("{:?} {:?} {:?}", poll_res, pollfd[0].revents(), pollfd);

                let req = ScmpNotifReq::receive(fd);
                let req = match req {
                    Ok(req) => req,
                    Err(e) => {
                        eprintln!("failed to receive notification: {}", e);
                        break;
                    }
                };
                let event_req = UNotifyEventRequest::new(req, fd);
                let syscall_id = event_req.get_request().data.syscall;
                let response = match self.handlers.get(&syscall_id) {
                    Some(handler) => handler(&event_req),
                    None => {
                        eprintln!("no handler for syscall {}", syscall_id);
                        event_req.fail_syscall(libc::ENOSYS)
                    }
                };
                if !event_req.is_valid() {
                    eprintln!("no need to respond to the request as it is invalid");
                    continue;
                }
                match response.respond(fd) {
                    Ok(_) => {}
                    Err(e) => {
                        eprintln!("failed to send response: {}", e);
                        break;
                    }
                };
            }
        });

        Ok((child, thread_handle))
    }

    /// Wait for the child process to exit and cleanup the supervisor thread.
    pub fn wait(child: &mut Child, thread_handle: JoinHandle<()>) -> Result<ExitStatus, io::Error> {
        let status = child.wait()?;
        thread_handle.join().map_err(|_| {
            io::Error::new(io::ErrorKind::Other, "failed to join supervisor thread")
        })?;
        Ok(status)
    }
}

#[cfg(test)]
mod tests {
    use std::{ffi::CStr, io::Read, process::Stdio, time::Duration};

    use super::*;
    use log::info;
    use nix::sys::signal::{kill, Signal::SIGKILL};
    use test_log::test;

    #[test]
    fn smoke_test_sleep() {
        let mut supervisor = Supervisor::new().unwrap();
        supervisor.handlers.insert(
            ScmpSyscall::new("openat"),
            Box::new(|req| {
                let path = req.get_request().data.args[1];
                let remote = RemoteProcess::new(Pid::from_raw(req.request.pid as i32)).unwrap();
                let mut buf = [0u8; 256];
                remote.read_mem(&mut buf, path as usize).unwrap();
                debug!("open (read from remote): {:?}", buf);
                let path = CStr::from_bytes_until_nul(&buf).unwrap();
                if !req.is_valid() {
                    return req.fail_syscall(libc::EACCES);
                }
                debug!("open (path CStr): {:?}", path);
                unsafe { req.continue_syscall() }
            }),
        );
        let mut cmd = Command::new("/bin/sleep");
        let cmd = cmd.arg("1");
        let (mut child, thread_handle) = supervisor.exec(cmd).unwrap();
        let status = Supervisor::wait(&mut child, thread_handle).unwrap();
        assert!(status.success());
    }

    #[test]
    fn smoke_test_whoami() {
        let mut supervisor = Supervisor::new().unwrap();
        supervisor.handlers.insert(
            ScmpSyscall::new("geteuid"),
            Box::new(|req| req.return_syscall(0)),
        );
        let mut cmd = Command::new("/bin/whoami");
        let cmd = cmd.stdout(Stdio::piped());
        let (mut child, thread_handle) = supervisor.exec(cmd).unwrap();
        let status = Supervisor::wait(&mut child, thread_handle).unwrap();
        assert!(status.success());
        let whoami_stdout = child.stdout.as_mut().unwrap();
        let mut buf = String::new();
        whoami_stdout.read_to_string(&mut buf).unwrap();
        assert_eq!(buf.trim(), "root");
    }

    #[test]
    fn test_sleep_blocking_syscall() {
        let mut supervisor = Supervisor::new().unwrap();
        supervisor.handlers.insert(
            ScmpSyscall::new("clock_nanosleep"),
            Box::new(|req| {
                // sleep for extra 60s
                // Please note that it may bring A LOT OF PROBLEMS if you try using pthread_cancel
                // So here we just use the easy way: check valid in the loop
                let (tx, rx) = std::sync::mpsc::channel();
                let handler = std::thread::spawn(move || {
                    for _ in 0..60 {
                        if rx.try_recv().is_ok() {
                            break;
                        }
                        std::thread::sleep(Duration::from_secs(1));
                    }
                });
                // while handler is running, check valid in the loop
                loop {
                    if !req.is_valid() {
                        // cancel the thread
                        info!("canceling thread as req is invalid now");
                        tx.send(()).unwrap();
                        return req.fail_syscall(libc::EACCES);
                    }
                    if handler.is_finished() {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                unsafe { req.continue_syscall() }
            }),
        );
        let mut cmd = Command::new("/bin/sleep");
        let cmd = cmd.arg("120");
        let (mut child, thread_handle) = supervisor.exec(cmd).unwrap();
        let child_pid = child.id();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(1));
            // kill the child process
            kill(Pid::from_raw(child_pid as i32), SIGKILL).unwrap();
        });
        let _ = Supervisor::wait(&mut child, thread_handle).unwrap();
    }
}
