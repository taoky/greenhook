# greenhook

Greenhook is a seccomp-unotify-based syscall hook library. It is adapted from <https://github.com/pdlan/binder>.

You could have it a try if you want to find alternatives other than `LD_PRELOAD` and `ptrace`. However, please note that seccomp unotify **IS NOT** a full replacement of these techniques, and take some time reading [`seccomp_unotify(2)`](https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html) before you start.

To fully utilize this library, you need to have a kernel version >= 5.9.0. And also you need [a special seccomp policy file](./assets/seccomp.json) if you want to run this in Docker or other containers (to allow `process_vm_readv()` and `pidfd_getfd()` to run without capabilities), with this:

```console
# docker run --security-opt seccomp=assets/seccomp.json ...
```

Also, it is necessary to install libseccomp header and library:

```
$ sudo apt install libseccomp-dev
```

## Example

You can find some examples inside test code. Here is a simple one that makes programs like `whoami(1)` considering you are root (even if you are not), by hooking `geteuid(2)`:

```rust
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
```

Run this with:

```console
> cargo run --example geteuid -- whoami
root
> whoami
user
```

A more complicated one, that replaces `/etc/passwd` to `/etc/resolv.conf` by hooking `openat(2)`:

```rust
use std::{process::Command, ffi::CStr, fs::File, os::fd::AsRawFd};

use greenhook::{Supervisor, UNotifyEventRequest, RemoteProcess};
use libseccomp::ScmpSyscall;
use log::info;
use nix::{unistd::Pid, libc};

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
        panic!("Usage: {} <program> [args...]", std::env::args().nth(0).unwrap());
    }
    let mut supervisor = Supervisor::new(2).unwrap();
    supervisor
        .handlers
        .insert(ScmpSyscall::new("openat"), openat_handler);
    let mut cmd = Command::new(args[0].clone());
    let cmd = cmd.args(&args[1..]);
    let (mut child, thread_handle, pool) = supervisor.exec(cmd).unwrap();
    let _ = Supervisor::wait(&mut child, thread_handle, pool).unwrap();
}
```

Run this with:

```console
> RUST_LOG=info cargo run --example openat -- cat /etc/passwd
[2023-05-27T14:39:57Z INFO  openat] open (path CStr): "/home/taoky/Projects/greenhook/target/debug/deps/glibc-hwcaps/x86-64-v3/libc.so.6"
[2023-05-27T14:39:57Z INFO  openat] open (path CStr): "/home/taoky/Projects/greenhook/target/debug/deps/glibc-hwcaps/x86-64-v2/libc.so.6"
[2023-05-27T14:39:57Z INFO  openat] open (path CStr): "/home/taoky/Projects/greenhook/target/debug/deps/libc.so.6"
[2023-05-27T14:39:57Z INFO  openat] open (path CStr): "/home/taoky/Projects/greenhook/target/debug/glibc-hwcaps/x86-64-v3/libc.so.6"
[2023-05-27T14:39:57Z INFO  openat] open (path CStr): "/home/taoky/Projects/greenhook/target/debug/glibc-hwcaps/x86-64-v2/libc.so.6"
[2023-05-27T14:39:57Z INFO  openat] open (path CStr): "/home/taoky/Projects/greenhook/target/debug/libc.so.6"
[2023-05-27T14:39:57Z INFO  openat] open (path CStr): "/home/taoky/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-unknown-linux-gnu/lib/glibc-hwcaps/x86-64-v3/libc.so.6"
[2023-05-27T14:39:57Z INFO  openat] open (path CStr): "/home/taoky/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-unknown-linux-gnu/lib/glibc-hwcaps/x86-64-v2/libc.so.6"
[2023-05-27T14:39:57Z INFO  openat] open (path CStr): "/home/taoky/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-unknown-linux-gnu/lib/libc.so.6"
[2023-05-27T14:39:57Z INFO  openat] open (path CStr): "/home/taoky/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/lib/glibc-hwcaps/x86-64-v3/libc.so.6"
[2023-05-27T14:39:57Z INFO  openat] open (path CStr): "/home/taoky/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/lib/glibc-hwcaps/x86-64-v2/libc.so.6"
[2023-05-27T14:39:57Z INFO  openat] open (path CStr): "/home/taoky/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/lib/libc.so.6"
[2023-05-27T14:39:57Z INFO  openat] open (path CStr): "/etc/ld.so.cache"
[2023-05-27T14:39:57Z INFO  openat] open (path CStr): "/usr/lib/libc.so.6"
[2023-05-27T14:39:57Z INFO  openat] open (path CStr): "/usr/lib/locale/locale-archive"
[2023-05-27T14:39:57Z INFO  openat] open (path CStr): "/etc/passwd"
# Generated by NetworkManager
...
```

## Limitation

1. Your hook functions are executed by supervisor process (thread), not supervised one! This means that you may find difficulties when you need to do something on behalf of supervised process.
2. Be careful of TOCTOU attack! Seccomp unotify will NOT stop whole process when handling syscalls, so it is possible that the supervised process may change the syscall arguments after supervisor has checked them, and `continue_syscall` can be dangerous (thus it is marked as `unsafe` here).
3. Handling signals could be troublesome. It is possible that signals can interrupt syscalls or restart them, but supervisor has no knowledge of this. Try to check request validity in your functions to alleviate this problem. For more information please read `seccomp_unotify(2)`.
