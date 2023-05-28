use std::{
    env,
    fs::File,
    io::{self, Read},
    mem,
    net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6},
    os::fd::RawFd,
    process::{exit, Command},
    str::FromStr,
    sync::Arc,
};

use env_logger::Env;
use greenhook::{RemoteProcess, Supervisor, UNotifyEventRequest};
use libseccomp::ScmpSyscall;
use log::{debug, warn};
use nix::{
    sys::socket::{
        bind, getsockopt, sockopt, AddressFamily, SockType, SockaddrIn, SockaddrIn6, SockaddrLike,
        SockaddrStorage,
    },
    unistd::Pid,
};

#[derive(Debug)]
struct AddressInfo {
    addr_v4: Option<Ipv4Addr>,
    addr_v6: Ipv6Addr,
    only_v6: bool,
}

// Error Enum
#[derive(Debug)]
enum ParseError {
    InvalidIPv6Address,
    InvalidIPv4Address,
}

fn parse_address(ip: &str) -> Result<AddressInfo, ParseError> {
    if ip.contains(':') {
        let addr_v6 = Ipv6Addr::from_str(ip).map_err(|_| ParseError::InvalidIPv6Address)?;
        Ok(AddressInfo {
            addr_v4: None,
            addr_v6,
            only_v6: true,
        })
    } else {
        let addr_v4 = Ipv4Addr::from_str(ip).map_err(|_| ParseError::InvalidIPv4Address)?;
        let addr_v6 = addr_v4.to_ipv6_mapped();

        Ok(AddressInfo {
            addr_v4: Some(addr_v4),
            addr_v6,
            only_v6: false,
        })
    }
}

unsafe fn any_as_u8_mut_slice<T: Sized>(p: &mut T) -> &mut [u8] {
    ::core::slice::from_raw_parts_mut((p as *mut T) as *mut u8, ::core::mem::size_of::<T>())
}

enum ReturnType {
    Continue,
    Ret(i64),
    Deny(i32),
}

fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    let address: Arc<AddressInfo> = {
        let bind_addr = match env::var("BIND_ADDRESS") {
            Ok(addr) => addr,
            Err(_) => {
                log::error!("BIND_ADDRESS not set, exiting");
                exit(1);
            }
        };
        Arc::new(match parse_address(&bind_addr) {
            Ok(addr) => addr,
            Err(e) => {
                log::error!("error: failed to parse BIND_ADDRESS {}: {:?}", bind_addr, e);
                exit(1);
            }
        })
    };
    let allowlist: Arc<Vec<AddressInfo>> = {
        let mut res = Vec::new();
        let mut buf = Vec::with_capacity(4096);
        let f = File::open("/etc/resolv.conf")
            .and_then(|mut f| f.read_to_end(&mut buf))
            .and_then(|_| {
                resolv_conf::Config::parse(&buf)
                    .map_err(|_| std::io::Error::from_raw_os_error(nix::libc::EINVAL))
            });
        if let Ok(conf) = f {
            for nameserver in conf.nameservers {
                res.push(match parse_address(&nameserver.to_string()) {
                    Ok(addr) => addr,
                    Err(_) => {
                        warn!("failed to parse nameserver {}", nameserver);
                        continue;
                    }
                });
            }
        } else {
            warn!("failed to parse /etc/resolv.conf");
        }

        debug!("allowlist: {:?}", res);

        Arc::new(res)
    };

    let allowlist_cl = allowlist.clone();
    let allowlist_check_v4 = move |addr: &Ipv4Addr| -> bool {
        for allow_ip in allowlist_cl.iter() {
            if allow_ip.only_v6 {
                continue;
            }
            if allow_ip.addr_v4.unwrap() == *addr {
                return true;
            }
        }
        false
    };

    let allowlist_cl = allowlist.clone();
    let allowlist_check_v6 = move |addr: &Ipv6Addr| -> bool {
        for allow_ip in allowlist_cl.iter() {
            if allow_ip.addr_v6 == *addr {
                return true;
            }
        }
        false
    };

    let address_cl = address.clone();
    let my_bind = Arc::new(
        move |fd: RawFd, addr: &dyn SockaddrLike| -> Result<ReturnType, std::io::Error> {
            let sa_family = addr.family().ok_or(io::ErrorKind::InvalidData)?;
            if sa_family != AddressFamily::Inet && sa_family != AddressFamily::Inet6 {
                return Ok(ReturnType::Continue);
            }
            let sock_type = match getsockopt(fd, sockopt::SockType) {
                Err(_) => {
                    warn!("getsockopt() failed");
                    return Ok(ReturnType::Continue);
                }
                Ok(t) => t,
            };
            // We only want to handle TCP sockets
            if sock_type != SockType::Stream {
                return Ok(ReturnType::Continue);
            }

            let res = match sa_family {
                AddressFamily::Inet => {
                    if address_cl.only_v6 {
                        return Ok(ReturnType::Continue);
                    }
                    bind(
                        fd,
                        &SockaddrIn::from(SocketAddrV4::new(address_cl.addr_v4.unwrap(), 0)),
                    )
                }
                AddressFamily::Inet6 => bind(
                    fd,
                    &SockaddrIn6::from(SocketAddrV6::new(address_cl.addr_v6, 0, 0, 0)),
                ),
                _ => unreachable!(),
            };

            match res {
                Ok(_) => {
                    debug!("bind: allow");
                    Ok(ReturnType::Ret(0))
                }
                Err(e) => {
                    debug!("bind: deny: {:?}", e);
                    Ok(ReturnType::Deny(e as i32))
                }
            }
        },
    );

    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() == 0 {
        panic!(
            "Usage: {} <program> [args...]",
            std::env::args().nth(0).unwrap()
        );
    }
    let mut supervisor = Supervisor::new(2).unwrap();
    let bind_cl = my_bind.clone();
    supervisor.insert_handler(ScmpSyscall::new("bind"), move |req| {
        let inner =
            |req: &UNotifyEventRequest| -> Result<libseccomp::ScmpNotifResp, std::io::Error> {
                let sockfd = req.get_request().data.args[0] as RawFd;
                let addr_remote = req.get_request().data.args[1];
                let addr_len = req.get_request().data.args[2] as u32;
                let remote = RemoteProcess::new(Pid::from_raw(req.get_request().pid as i32))?;
                let mut addr: nix::libc::sockaddr = unsafe { mem::zeroed() };
                remote.read_mem(
                    unsafe { any_as_u8_mut_slice(&mut addr) },
                    addr_remote as usize,
                )?;
                if !req.is_valid() {
                    return Ok(req.fail_syscall(nix::libc::EACCES));
                }
                match bind_cl(
                    remote.get_fd(sockfd)?,
                    &unsafe { SockaddrStorage::from_raw(&addr, Some(addr_len)) }
                        .ok_or(io::ErrorKind::InvalidData)?,
                ) {
                    Ok(ReturnType::Continue) => Ok(unsafe { req.continue_syscall() }),
                    Ok(ReturnType::Ret(ret)) => Ok(req.return_syscall(ret)),
                    Ok(ReturnType::Deny(errno)) => Ok(req.fail_syscall(errno)),
                    Err(e) => Err(e),
                }
            };

        match inner(req) {
            Ok(res) => res,
            Err(e) => req.fail_syscall(e.raw_os_error().unwrap_or(nix::libc::ENOSYS)),
        }
    });

    let bind_cl = my_bind.clone();
    supervisor.insert_handler(ScmpSyscall::new("connect"), move |req| {
        let inner =
            |req: &UNotifyEventRequest| -> Result<libseccomp::ScmpNotifResp, std::io::Error> {
                let sockfd = req.get_request().data.args[0] as RawFd;
                let addr_remote = req.get_request().data.args[1];
                let addr_len = req.get_request().data.args[2] as u32;
                let remote = RemoteProcess::new(Pid::from_raw(req.get_request().pid as i32))?;
                debug!("{:?}", remote);
                let mut addr: nix::libc::sockaddr = unsafe { mem::zeroed() };
                remote.read_mem(
                    unsafe { any_as_u8_mut_slice(&mut addr) },
                    addr_remote as usize,
                )?;
                debug!("{:?} {}", addr, addr_len);
                if !req.is_valid() {
                    return Ok(req.fail_syscall(nix::libc::EACCES));
                }
                let addr = match unsafe { SockaddrStorage::from_raw(&addr, Some(addr_len)) } {
                    Some(a) => a,
                    None => {
                        return Ok(unsafe { req.continue_syscall() });
                    }
                };
                let sa_family = match addr.family() {
                    Some(f) => f,
                    None => {
                        return Ok(unsafe { req.continue_syscall() });
                    }
                };
                debug!("family: {:?}", sa_family);
                match sa_family {
                    AddressFamily::Inet => {
                        let addr = Ipv4Addr::from(addr.as_sockaddr_in().unwrap().ip());
                        if !allowlist_check_v4(&addr) {
                            if address.only_v6 {
                                return Ok(req.fail_syscall(nix::libc::ECONNREFUSED));
                            }
                            match bind_cl(
                                remote.get_fd(sockfd)?,
                                &SockaddrIn::from(SocketAddrV4::new(address.addr_v4.unwrap(), 0)),
                            ) {
                                Ok(ReturnType::Continue) => {}
                                Ok(ReturnType::Ret(r)) => {
                                    assert_eq!(r, 0)
                                }
                                Ok(ReturnType::Deny(errno)) => {
                                    warn!("bind() failed (IPv4) with errno {}", errno);
                                }
                                Err(e) => return Err(e),
                            }
                        } else {
                            debug!("allowlist check passed (IPv4)")
                        }
                    }
                    AddressFamily::Inet6 => {
                        let addr = addr.as_sockaddr_in6().unwrap().ip();
                        if !allowlist_check_v6(&addr) {
                            match bind_cl(
                                remote.get_fd(sockfd)?,
                                &SockaddrIn6::from(SocketAddrV6::new(address.addr_v6, 0, 0, 0)),
                            ) {
                                Ok(ReturnType::Continue) => {}
                                Ok(ReturnType::Ret(r)) => {
                                    assert_eq!(r, 0)
                                }
                                Ok(ReturnType::Deny(errno)) => {
                                    warn!("bind() failed (IPv6) with errno {}", errno);
                                }
                                Err(e) => return Err(e),
                            }
                        } else {
                            debug!("allowlist check passed (IPv6)")
                        }
                    }
                    _ => {}
                }

                Ok(unsafe { req.continue_syscall() })
            };

        debug!("connect: {:?}", req);
        match inner(req) {
            Ok(res) => res,
            Err(e) => req.fail_syscall(e.raw_os_error().unwrap_or(nix::libc::ENOSYS)),
        }
    });
    let mut cmd = Command::new(args[0].clone());
    let cmd = cmd.args(&args[1..]);
    let (mut child, thread_handle, pool) = supervisor.exec(cmd).unwrap();
    let status = Supervisor::wait(&mut child, thread_handle, pool).unwrap();
    if !status.success() {
        warn!("Child exited with status {}", status);
    }
    std::process::exit(status.code().unwrap_or(-1));
}
