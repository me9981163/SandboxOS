//! Raw Linux interfaces used by sbx.
//!
//! This is the only crate allowed to contain `unsafe`. The rest of the
//! workspace gets small safe wrappers so that every syscall boundary can be
//! audited in one place.
//!
//! The probe helpers in this file intentionally fork and use only
//! async-signal-safe operations in the child. The parent performs the
//! `/proc/<pid>/*_map` writes because an unprivileged process cannot map
//! itself: mapping must be done by a process with authority over the child.

use std::ffi::{CStr, CString};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::raw::{c_char, c_int, c_long, c_short, c_uint, c_ulong, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

pub const CLONE_NEWNS: c_int = 0x0002_0000;
pub const CLONE_NEWUTS: c_int = 0x0400_0000;
pub const CLONE_NEWIPC: c_int = 0x0800_0000;
pub const CLONE_NEWUSER: c_int = 0x1000_0000;
pub const CLONE_NEWPID: c_int = 0x2000_0000;
pub const CLONE_NEWNET: c_int = 0x4000_0000;
pub const CLONE_NEWCGROUP: c_int = 0x0200_0000;
pub const CLONE_NEWTIME: c_int = 0x0000_0080;

/// All namespace-creation flags a sandboxed process must not regain.
pub const CLONE_ALL_NEW_NAMESPACES: c_int = CLONE_NEWNS
    | CLONE_NEWUTS
    | CLONE_NEWIPC
    | CLONE_NEWUSER
    | CLONE_NEWPID
    | CLONE_NEWNET
    | CLONE_NEWCGROUP
    | CLONE_NEWTIME;

/// x32 syscall numbers carry this bit on x86-64. The filter must not mistake
/// them for native syscall numbers.
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

/// `TIOCSTI` injects a byte into a terminal input queue.
pub const TIOCSTI: c_ulong = 0x5412;

pub const MS_RDONLY: c_ulong = 1;
pub const MS_NOSUID: c_ulong = 2;
pub const MS_NODEV: c_ulong = 4;
pub const MS_NOEXEC: c_ulong = 8;

pub const MNT_DETACH: c_int = 2;
pub const SIGKILL: c_int = 9;

const LANDLOCK_CREATE_RULESET_VERSION: c_uint = 1;
const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;

// Filesystem access rights. ABI 1 defines the first thirteen; later ABIs add
// one right each. The runner only handles rights the running ABI knows about,
// because passing an unknown bit to landlock_create_ruleset returns EINVAL.
pub const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
pub const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
pub const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
pub const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
pub const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
pub const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
pub const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
pub const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
pub const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
pub const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
pub const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
pub const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
pub const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
pub const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 13;
pub const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14;
// IOCTL_DEV (1 << 15, ABI 5) is deliberately not handled. Inherited terminal
// descriptors point at host devpts inodes outside the sandbox hierarchy, so
// handling IOCTL_DEV would break ordinary terminal ioctls. TIOCSTI is blocked
// by the seccomp profile instead.

#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
}

#[repr(C)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: c_int,
    reserved: u32,
}

const PR_SET_NO_NEW_PRIVS: c_int = 38;
const PR_GET_NO_NEW_PRIVS: c_int = 39;
const PR_SET_PDEATHSIG: c_int = 1;
const PR_CAPBSET_DROP: c_int = 24;
const PR_CAP_AMBIENT: c_int = 47;
const PR_CAP_AMBIENT_CLEAR_ALL: c_int = 4;

const SECCOMP_SET_MODE_FILTER: c_uint = 1;
const SECCOMP_GET_ACTION_AVAIL: c_uint = 2;
pub const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;
pub const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
pub const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
pub const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_ALU: u16 = 0x04;
const BPF_AND: u16 = 0x50;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_RET: u16 = 0x06;
const BPF_K: u16 = 0x00;

/// x86-64 syscall audit architecture.
const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;

#[repr(C)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

/// Result of a fork: exactly one side continues as parent, one as child.
pub enum ForkResult {
    Parent { pid: c_int },
    Child,
}

/// Safe wrapper around `fork()`.
///
/// # Fork-safety
/// The caller must be single-threaded. The child may only perform
/// async-signal-safe operations until it exits or execs.
pub fn fork() -> io::Result<ForkResult> {
    // SAFETY: fork has no preconditions beyond being single-threaded, which is
    // documented on this function and enforced by the CLI architecture.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        Err(io::Error::last_os_error())
    } else if pid == 0 {
        Ok(ForkResult::Child)
    } else {
        Ok(ForkResult::Parent { pid })
    }
}

/// `unshare(2)`.
pub fn unshare(flags: c_int) -> io::Result<()> {
    // SAFETY: unshare only reads its integer argument.
    let rc = unsafe { libc::unshare(flags) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Terminate the current (forked) process immediately.
pub fn exit_now(code: i32) -> ! {
    // SAFETY: _exit never returns and does not run Rust destructors, which is
    // exactly what a forked child must do.
    unsafe { libc::_exit(code) }
}

/// A minimal, allocation-free pipe write used by forked children.
pub fn write_fd(fd: c_int, bytes: &[u8]) -> bool {
    let mut off = 0;
    while off < bytes.len() {
        // SAFETY: caller owns `fd`; the pointer and length describe a live
        // slice. EINTR is retried below.
        let n = unsafe {
            libc::write(
                fd,
                bytes[off..].as_ptr().cast::<c_void>(),
                bytes.len() - off,
            )
        };
        if n < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return false;
        }
        if n == 0 {
            return false;
        }
        off += n as usize;
    }
    true
}

/// A minimal, allocation-free pipe read used by forked children.
pub fn read_fd(fd: c_int, bytes: &mut [u8]) -> bool {
    let mut off = 0;
    while off < bytes.len() {
        // SAFETY: caller owns `fd`; the pointer and length describe a live
        // slice. EINTR is retried below.
        let n = unsafe {
            libc::read(
                fd,
                bytes[off..].as_mut_ptr().cast::<c_void>(),
                bytes.len() - off,
            )
        };
        if n < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return false;
        }
        if n == 0 {
            return false;
        }
        off += n as usize;
    }
    true
}

fn pipe() -> io::Result<(c_int, c_int)> {
    let mut fds = [0 as c_int; 2];
    // SAFETY: fds points to a valid two-element array. O_CLOEXEC avoids leaking
    // probe pipes into any future exec (probes never exec, but this is cheap).
    let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    if rc == 0 {
        Ok((fds[0], fds[1]))
    } else {
        Err(io::Error::last_os_error())
    }
}

pub fn close_fd(fd: c_int) {
    // SAFETY: closing an fd we own is safe; errors are intentionally ignored in
    // the child because there is nothing useful to report.
    unsafe {
        libc::close(fd);
    }
}

fn errno_name(errno: c_int) -> &'static str {
    match errno {
        libc::EPERM => "EPERM",
        libc::EACCES => "EACCES",
        libc::EINVAL => "EINVAL",
        libc::ENOSPC => "ENOSPC",
        libc::EUSERS => "EUSERS",
        libc::ENOMEM => "ENOMEM",
        libc::ENOSYS => "ENOSYS",
        libc::EOPNOTSUPP => "EOPNOTSUPP",
        libc::EBUSY => "EBUSY",
        _ => "errno",
    }
}

fn describe_errno(errno: c_int) -> String {
    format!("{} (errno {})", errno_name(errno), errno)
}

fn wait_for_child(pid: c_int) -> Result<i32, String> {
    let mut status: c_int = 0;
    loop {
        // SAFETY: pid came from fork and status points to a valid c_int.
        let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
        if rc == pid {
            break;
        }
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(format!("waitpid failed: {err}"));
        }
    }
    // These libc helpers only inspect the status value written by waitpid.
    if libc::WIFEXITED(status) {
        Ok(libc::WEXITSTATUS(status))
    } else if libc::WIFSIGNALED(status) {
        Err(format!(
            "child terminated by signal {}",
            libc::WTERMSIG(status)
        ))
    } else {
        Err("child ended in an unexpected wait state".to_string())
    }
}

/// Create a user namespace in a child, have the parent write the uid/gid maps,
/// then optionally create additional namespaces and verify a pid namespace.
///
/// `extra_flags` must not contain `CLONE_NEWUSER`; this function always creates
/// the user namespace first, then maps the caller's own uid/gid to themselves.
/// When `verify_pid` is true, `extra_flags` must include `CLONE_NEWPID`; the
/// child forks once more and checks that the grandchild is pid 1.
pub fn probe_userns(extra_flags: c_int, verify_pid: bool) -> Result<(), String> {
    let host_uid = {
        // SAFETY: getuid has no preconditions.
        unsafe { libc::getuid() }
    };
    let host_gid = {
        // SAFETY: getgid has no preconditions.
        unsafe { libc::getgid() }
    };

    let (ready_r, ready_w) = pipe().map_err(|e| format!("ready pipe: {e}"))?;
    let (ack_r, ack_w) = pipe().map_err(|e| format!("ack pipe: {e}"))?;

    match fork().map_err(|e| format!("fork: {e}"))? {
        ForkResult::Child => {
            close_fd(ready_r);
            close_fd(ack_w);

            // Step 1: enter the user namespace. This is the only operation
            // allowed before the parent writes the maps.
            // SAFETY: unshare takes an integer bitmask.
            if unsafe { libc::unshare(CLONE_NEWUSER) } != 0 {
                let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
                let _ = write_fd(ready_w, &[errno as u8]);
                exit_now(1);
            }
            if !write_fd(ready_w, &[0]) {
                exit_now(1);
            }

            // Wait for the parent to finish writing /proc/<pid>/{uid,gid}_map.
            let mut ack = [0u8; 1];
            if !read_fd(ack_r, &mut ack) || ack[0] != 1 {
                exit_now(2);
            }

            if extra_flags != 0 {
                // SAFETY: unshare takes an integer bitmask.
                if unsafe { libc::unshare(extra_flags) } != 0 {
                    let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
                    let _ = write_fd(ready_w, &[errno as u8]);
                    exit_now(3);
                }
            }

            if verify_pid {
                // A pid namespace only takes effect for children, so fork and
                // verify the first process really is pid 1.
                // SAFETY: fork is safe here: this child is single-threaded and
                // performs only async-signal-safe work.
                let grandchild = unsafe { libc::fork() };
                if grandchild < 0 {
                    exit_now(4);
                }
                if grandchild == 0 {
                    // SAFETY: getpid has no preconditions.
                    let is_init = unsafe { libc::getpid() } == 1;
                    exit_now(if is_init { 0 } else { 5 });
                }
                match wait_for_child(grandchild) {
                    Ok(0) => {}
                    _ => exit_now(6),
                }
            }

            // The maps must preserve the caller's ids, not turn them into root.
            // SAFETY: getuid/getgid have no preconditions.
            if unsafe { libc::getuid() } != host_uid || unsafe { libc::getgid() } != host_gid {
                exit_now(7);
            }
            exit_now(0);
        }
        ForkResult::Parent { pid } => {
            close_fd(ready_w);
            close_fd(ack_r);

            let mut ready = [0u8; 1];
            if !read_fd(ready_r, &mut ready) {
                let _ = wait_for_child(pid);
                close_fd(ready_r);
                close_fd(ack_w);
                return Err("child exited before signalling user namespace creation".to_string());
            }
            if ready[0] != 0 {
                let _ = wait_for_child(pid);
                close_fd(ready_r);
                close_fd(ack_w);
                return Err(format!(
                    "unshare(CLONE_NEWUSER) failed with {}",
                    describe_errno(ready[0] as c_int)
                ));
            }

            let map_root = format!("/proc/{pid}");
            let setgroups_path = format!("{map_root}/setgroups");
            // setgroups must be denied before gid_map is written. Some kernels
            // do not expose the file; ENOENT is the documented exception.
            match std::fs::write(&setgroups_path, b"deny") {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => {
                    let _ = wait_for_child(pid);
                    close_fd(ready_r);
                    close_fd(ack_w);
                    return Err(format!("writing {setgroups_path} failed: {e}"));
                }
            }

            let uid_map = format!("{host_uid} {host_uid} 1\n");
            let gid_map = format!("{host_gid} {host_gid} 1\n");
            if let Err(e) = std::fs::write(format!("{map_root}/uid_map"), uid_map) {
                let _ = wait_for_child(pid);
                close_fd(ready_r);
                close_fd(ack_w);
                return Err(format!("writing uid_map failed: {e}"));
            }
            if let Err(e) = std::fs::write(format!("{map_root}/gid_map"), gid_map) {
                let _ = wait_for_child(pid);
                close_fd(ready_r);
                close_fd(ack_w);
                return Err(format!("writing gid_map failed: {e}"));
            }

            let _ = write_fd(ack_w, &[1]);
            close_fd(ack_w);

            // Keep ready_r open until the child exits: the child uses the same
            // pipe to report a failure of the additional namespaces. Closing it
            // early would turn that report into SIGPIPE and hide the cause.
            let status = wait_for_child(pid);
            close_fd(ready_r);
            match status? {
                0 => Ok(()),
                1 => Err("child could not enter the user namespace".to_string()),
                2 => Err("parent did not acknowledge the uid/gid maps".to_string()),
                3 => Err(format!(
                    "namespace creation failed after mapping ({})",
                    if verify_pid {
                        "one of the other namespaces"
                    } else {
                        "unshare"
                    }
                )),
                4 => Err("fork inside the pid namespace failed".to_string()),
                5 => Err("grandchild was not pid 1 in the new pid namespace".to_string()),
                6 => Err("pid namespace verification child failed".to_string()),
                7 => Err("uid/gid maps did not preserve the caller's ids".to_string()),
                other => Err(format!("probe child exited with status {other}")),
            }
        }
    }
}

/// Query the Landlock ABI version through the syscall (not sysfs or config).
pub fn landlock_abi() -> Result<c_int, String> {
    // SAFETY: passing a null ruleset with the VERSION flag is the documented
    // way to query the ABI; no memory is dereferenced.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<c_void>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if rc < 0 {
        Err(describe_errno(
            io::Error::last_os_error().raw_os_error().unwrap_or(0),
        ))
    } else {
        c_int::try_from(rc).map_err(|_| "Landlock ABI does not fit in c_int".to_string())
    }
}

/// Filesystem rights this ABI understands.
///
/// Unknown bits make `landlock_create_ruleset` fail with `EINVAL`, so the mask
/// is grown only as the kernel reports support.
pub fn landlock_access_for_abi(abi: c_int) -> u64 {
    let mut access = LANDLOCK_ACCESS_FS_EXECUTE
        | LANDLOCK_ACCESS_FS_WRITE_FILE
        | LANDLOCK_ACCESS_FS_READ_FILE
        | LANDLOCK_ACCESS_FS_READ_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_FILE
        | LANDLOCK_ACCESS_FS_MAKE_CHAR
        | LANDLOCK_ACCESS_FS_MAKE_DIR
        | LANDLOCK_ACCESS_FS_MAKE_REG
        | LANDLOCK_ACCESS_FS_MAKE_SOCK
        | LANDLOCK_ACCESS_FS_MAKE_FIFO
        | LANDLOCK_ACCESS_FS_MAKE_BLOCK
        | LANDLOCK_ACCESS_FS_MAKE_SYM;
    if abi >= 2 {
        access |= LANDLOCK_ACCESS_FS_REFER;
    }
    if abi >= 3 {
        access |= LANDLOCK_ACCESS_FS_TRUNCATE;
    }
    access
}

/// One path-beneath rule. The path is an absolute path inside the sandbox.
pub struct LandlockRule {
    pub path: CString,
    pub access: u64,
}

/// Create and immediately close a ruleset, proving the kernel accepts the
/// requested access mask. Called from the parent before any fork.
pub fn landlock_probe(handled_access_fs: u64) -> io::Result<()> {
    let attr = LandlockRulesetAttr { handled_access_fs };
    // SAFETY: attr is a live ruleset attribute of the documented size and the
    // flags argument is zero, so the kernel only reads it.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &attr as *const LandlockRulesetAttr,
            std::mem::size_of::<LandlockRulesetAttr>(),
            0 as c_uint,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the syscall returned a fresh descriptor owned here.
    drop(unsafe { OwnedFd::from_raw_fd(fd as c_int) });
    Ok(())
}

/// Install the Landlock ruleset and restrict the calling process.
///
/// Must be called after `PR_SET_NO_NEW_PRIVS` (Landlock refuses otherwise) and
/// before `execve`. Only async-signal-safe operations are used: `open`,
/// `landlock_add_rule`, `landlock_restrict_self`, `close`.
pub fn apply_landlock(handled_access_fs: u64, rules: &[LandlockRule]) -> io::Result<()> {
    let attr = LandlockRulesetAttr { handled_access_fs };
    // SAFETY: attr is a live ruleset attribute; the size matches its type.
    let ruleset_fd = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &attr as *const LandlockRulesetAttr,
            std::mem::size_of::<LandlockRulesetAttr>(),
            0 as c_uint,
        )
    };
    if ruleset_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the syscall returned a fresh descriptor owned here.
    let ruleset = unsafe { OwnedFd::from_raw_fd(ruleset_fd as c_int) };

    for rule in rules {
        // O_PATH opens the inode for rule installation without read access.
        // SAFETY: rule.path is a live NUL-terminated string.
        let path_fd = unsafe {
            libc::open(
                rule.path.as_ptr(),
                libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if path_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: path_fd is a fresh descriptor owned here.
        let path = unsafe { OwnedFd::from_raw_fd(path_fd) };
        let beneath = LandlockPathBeneathAttr {
            allowed_access: rule.access,
            parent_fd: path.as_raw_fd(),
            reserved: 0,
        };
        // SAFETY: beneath describes path fd and access rights; the ruleset
        // descriptor is live and the rule type is a valid enum value.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_landlock_add_rule,
                ruleset.as_raw_fd(),
                LANDLOCK_RULE_PATH_BENEATH,
                &beneath as *const LandlockPathBeneathAttr,
                0 as c_uint,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
    }

    // SAFETY: ruleset is a live descriptor created above and the flags
    // argument is zero. After this call the process is permanently restricted.
    let rc = unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset.as_raw_fd(), 0) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Check whether a seccomp return action is supported by this kernel.
pub fn seccomp_action_available(action: u32) -> Result<bool, String> {
    let mut value = action;
    // SAFETY: args points to a live u32, as required by
    // SECCOMP_GET_ACTION_AVAIL.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_GET_ACTION_AVAIL,
            0 as c_uint,
            (&mut value) as *mut u32 as *mut c_void,
        )
    };
    if rc == 0 {
        Ok(true)
    } else {
        let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
        match errno {
            libc::EOPNOTSUPP | libc::EINVAL => Ok(false),
            _ => Err(describe_errno(errno)),
        }
    }
}

/// Install a minimal `SECCOMP_RET_ALLOW` filter in a forked child.
///
/// A filter cannot be removed once installed, so probing it in the doctor
/// process itself would silently change that process. The child therefore
/// makes the irreversible call and exits.
pub fn probe_seccomp_filter() -> Result<(), String> {
    match fork().map_err(|e| format!("fork: {e}"))? {
        ForkResult::Child => {
            // SAFETY: prctl with PR_SET_NO_NEW_PRIVS takes integer arguments.
            if unsafe { libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
                exit_now(1);
            }
            let filter = [SockFilter {
                code: BPF_RET | BPF_K,
                jt: 0,
                jf: 0,
                k: SECCOMP_RET_ALLOW,
            }];
            let prog = SockFprog {
                len: filter.len() as u16,
                filter: filter.as_ptr(),
            };
            // SAFETY: prog points to a valid sock_fprog whose filter points to
            // a live array of BPF instructions.
            let rc = unsafe {
                libc::syscall(
                    libc::SYS_seccomp,
                    SECCOMP_SET_MODE_FILTER,
                    0 as c_uint,
                    (&prog) as *const SockFprog as *const c_void,
                )
            };
            if rc != 0 {
                let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
                exit_now(if errno == libc::EINVAL { 2 } else { 3 });
            }
            exit_now(0);
        }
        ForkResult::Parent { pid } => match wait_for_child(pid)? {
            0 => Ok(()),
            1 => Err("PR_SET_NO_NEW_PRIVS failed".to_string()),
            2 => Err("seccomp filter rejected as invalid".to_string()),
            _ => Err("seccomp(SECCOMP_SET_MODE_FILTER) failed".to_string()),
        },
    }
}

/// Verify that `PR_SET_NO_NEW_PRIVS` works and reads back as 1.
pub fn probe_no_new_privs() -> Result<(), String> {
    match fork().map_err(|e| format!("fork: {e}"))? {
        ForkResult::Child => {
            // SAFETY: prctl with PR_SET/GET_NO_NEW_PRIVS uses integer args.
            if unsafe { libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
                exit_now(1);
            }
            // SAFETY: see above.
            let value = unsafe { libc::prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
            exit_now(if value == 1 { 0 } else { 2 });
        }
        ForkResult::Parent { pid } => match wait_for_child(pid)? {
            0 => Ok(()),
            1 => Err("PR_SET_NO_NEW_PRIVS failed".to_string()),
            2 => Err("PR_GET_NO_NEW_PRIVS did not return 1".to_string()),
            _ => Err("no_new_privs probe child failed".to_string()),
        },
    }
}

/// Kernel release from `uname(2)`.
pub fn kernel_release() -> io::Result<String> {
    // SAFETY: utsname is a plain C struct; zeroing it is valid and uname fills
    // it on success.
    let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
    // SAFETY: uts points to a valid utsname.
    if unsafe { libc::uname(&mut uts) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: release is a NUL-terminated array filled by uname.
    let release = unsafe { CStr::from_ptr(uts.release.as_ptr()) };
    Ok(release.to_string_lossy().into_owned())
}

/// Architecture name from `uname(2)`.
pub fn machine() -> io::Result<String> {
    // SAFETY: as in kernel_release.
    let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
    // SAFETY: as in kernel_release.
    if unsafe { libc::uname(&mut uts) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: machine is a NUL-terminated array filled by uname.
    let machine = unsafe { CStr::from_ptr(uts.machine.as_ptr()) };
    Ok(machine.to_string_lossy().into_owned())
}

/// Current seccomp mode: 0 = disabled, 1 = strict, 2 = filter.
pub fn seccomp_mode() -> io::Result<c_long> {
    // SAFETY: PR_GET_SECCOMP takes no pointer arguments.
    let value = unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) };
    if value < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(value as c_long)
    }
}

/// cgroup v2 presence: information only, never a sandbox requirement.
pub fn cgroup_v2_present() -> bool {
    std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists()
}

/// KVM presence: information only, never a sandbox requirement.
pub fn kvm_present() -> bool {
    std::path::Path::new("/dev/kvm").exists()
}

/// Useful for formatting syscall failures without exposing raw errno elsewhere.
pub fn last_os_error() -> io::Error {
    io::Error::last_os_error()
}

/// Result of waiting for a child, preserving the distinction between a normal
/// exit and death by signal (which sbx must map to 128+N).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitStatus {
    Exited(i32),
    Signaled(i32),
}

/// Wait for a specific child without allocating in the child's critical path.
pub fn waitpid_status(pid: c_int) -> io::Result<WaitStatus> {
    let mut status: c_int = 0;
    loop {
        // SAFETY: pid came from fork/clone and status points to a valid c_int.
        let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
        if rc == pid {
            break;
        }
        if rc < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
    }
    if libc::WIFEXITED(status) {
        Ok(WaitStatus::Exited(libc::WEXITSTATUS(status)))
    } else if libc::WIFSIGNALED(status) {
        Ok(WaitStatus::Signaled(libc::WTERMSIG(status)))
    } else {
        Err(io::Error::from_raw_os_error(libc::EIO))
    }
}

/// Wait for a specific child and return the raw wait status, or errno.
///
/// This variant performs no allocation so it is safe to call from the forked
/// supervisor. `EINTR` is retried.
pub fn waitpid_raw(pid: c_int) -> Result<c_int, c_int> {
    let mut status: c_int = 0;
    loop {
        // SAFETY: pid came from fork/clone and status points to a valid c_int.
        let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
        if rc == pid {
            return Ok(status);
        }
        if rc < 0 {
            let errno = io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO);
            if errno == libc::EINTR {
                continue;
            }
            return Err(errno);
        }
    }
}

/// Decode a raw status from `waitpid` without allocating.
pub fn decode_wait_status(status: c_int) -> Option<WaitStatus> {
    if libc::WIFEXITED(status) {
        Some(WaitStatus::Exited(libc::WEXITSTATUS(status)))
    } else if libc::WIFSIGNALED(status) {
        Some(WaitStatus::Signaled(libc::WTERMSIG(status)))
    } else {
        None
    }
}

/// Create a close-on-exec pipe. The CLOEXEC bit matters: the event/status pipe
/// must not leak into the target if a later setup step fails unexpectedly.
pub fn pipe_cloexec() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as c_int; 2];
    // SAFETY: fds points to a valid two-element array.
    let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: pipe2 returned two fresh descriptors owned by this function.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// Raw fd number for passing into a forked child. The OwnedFd must outlive use.
pub fn raw_fd(fd: &OwnedFd) -> c_int {
    fd.as_raw_fd()
}

/// Parent-side write of `uid_map` and `gid_map`. This deliberately lives in the
/// parent: an unprivileged process cannot map its own user namespace.
pub fn write_user_maps(pid: c_int, uid: u32, gid: u32) -> Result<(), String> {
    let root = format!("/proc/{pid}");
    let setgroups_path = format!("{root}/setgroups");
    match std::fs::write(&setgroups_path, b"deny") {
        Ok(()) => {}
        // Old kernels do not expose setgroups; ENOENT is documented as safe to
        // ignore only because gid_map is written afterwards and cannot map
        // groups in that case.
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("writing {setgroups_path} failed: {e}")),
    }
    std::fs::write(format!("{root}/uid_map"), format!("{uid} {uid} 1\n"))
        .map_err(|e| format!("writing uid_map failed: {e}"))?;
    std::fs::write(format!("{root}/gid_map"), format!("{gid} {gid} 1\n"))
        .map_err(|e| format!("writing gid_map failed: {e}"))?;
    Ok(())
}

/// Child side of the user-namespace handshake. It must only use raw syscalls.
///
/// Returns `Ok(())` only after the parent has written both maps and signalled
/// consent. `Err(errno)` is the raw errno for the failed step; `Err(EPIPE)` is
/// used for a broken handshake pipe.
pub fn enter_user_namespace(ready_fd: c_int, ack_fd: c_int) -> Result<(), c_int> {
    // SAFETY: unshare takes an integer bitmask.
    if unsafe { libc::unshare(CLONE_NEWUSER) } != 0 {
        return Err(io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO));
    }
    if !write_fd(ready_fd, &[0]) {
        return Err(libc::EPIPE);
    }
    let mut ack = [0u8; 1];
    if !read_fd(ack_fd, &mut ack) || ack[0] != 1 {
        return Err(libc::EPIPE);
    }
    Ok(())
}

/// `PR_SET_PDEATHSIG`. The parent uses SIGKILL so the target tree cannot survive
/// an `sbx` crash or an unconditional kill.
pub fn set_pdeathsig(signal: c_int) -> io::Result<()> {
    // SAFETY: prctl with PR_SET_PDEATHSIG takes integer arguments.
    let rc = unsafe { libc::prctl(PR_SET_PDEATHSIG, signal, 0, 0, 0) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Set `PR_SET_NO_NEW_PRIVS`.
pub fn set_no_new_privs() -> io::Result<()> {
    // SAFETY: prctl with PR_SET_NO_NEW_PRIVS takes integer arguments.
    let rc = unsafe { libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Syscalls denied by the default profile.
///
/// Every entry returns `EPERM`, not a kill. A denied program can report the
/// failure and keep running; `docs/SECCOMP.md` justifies each group. The
/// namespace/mount family is repeated here even though the mount namespace is
/// the primary boundary: defence in depth means one mistake is not enough.
const DENIED_SYSCALLS: &[c_long] = &[
    // Tracing and cross-process memory. These are the classic ways to read or
    // write another process's addresses after ptrace-style attachment.
    libc::SYS_ptrace,
    libc::SYS_process_vm_readv,
    libc::SYS_process_vm_writev,
    libc::SYS_kcmp,
    libc::SYS_pidfd_open,
    libc::SYS_pidfd_getfd,
    libc::SYS_pidfd_send_signal,
    // Namespace, mount and file-handle manipulation.
    libc::SYS_unshare,
    libc::SYS_setns,
    libc::SYS_mount,
    libc::SYS_umount2,
    libc::SYS_pivot_root,
    libc::SYS_chroot,
    libc::SYS_fsopen,
    libc::SYS_fsconfig,
    libc::SYS_fsmount,
    libc::SYS_fspick,
    libc::SYS_move_mount,
    libc::SYS_open_tree,
    libc::SYS_mount_setattr,
    libc::SYS_open_by_handle_at,
    libc::SYS_name_to_handle_at,
    // Kernel modules and kexec.
    libc::SYS_init_module,
    libc::SYS_finit_module,
    libc::SYS_delete_module,
    libc::SYS_kexec_load,
    libc::SYS_kexec_file_load,
    // bpf, perf, userfaultfd, io_uring and keyrings.
    libc::SYS_bpf,
    libc::SYS_perf_event_open,
    libc::SYS_userfaultfd,
    libc::SYS_io_uring_setup,
    libc::SYS_io_uring_enter,
    libc::SYS_io_uring_register,
    libc::SYS_keyctl,
    libc::SYS_add_key,
    libc::SYS_request_key,
    // Host system state. The namespaces already isolate most of this; denying
    // the calls keeps a mistake from changing state that is shared.
    libc::SYS_reboot,
    libc::SYS_swapon,
    libc::SYS_swapoff,
    libc::SYS_acct,
    libc::SYS_settimeofday,
    libc::SYS_clock_settime,
    libc::SYS_clock_adjtime,
    libc::SYS_adjtimex,
    libc::SYS_sethostname,
    libc::SYS_setdomainname,
    libc::SYS_syslog,
    libc::SYS_iopl,
    libc::SYS_ioperm,
    libc::SYS_fanotify_init,
    libc::SYS_quotactl,
];

/// A complete seccomp BPF program built in the parent and installed in the
/// target. Building before `fork()` keeps the target path allocation-free.
pub struct SeccompProgram {
    filter: Vec<SockFilter>,
}

impl SeccompProgram {
    /// Install the filter. `PR_SET_NO_NEW_PRIVS` must already be set.
    pub fn install(&self) -> io::Result<()> {
        let prog = SockFprog {
            len: self.filter.len() as u16,
            filter: self.filter.as_ptr(),
        };
        // SAFETY: prog points to a live sock_fprog whose filter vector outlives
        // this call. Flags are zero (single-threaded target, no TSYNC).
        let rc = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                SECCOMP_SET_MODE_FILTER,
                0 as c_uint,
                &prog as *const SockFprog,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FilterLabel {
    Allow,
    Deny,
    Enosys,
    ForeignAbi,
    X32Abi,
    IoctlCheck,
    CloneCheck,
}

#[derive(Clone, Copy)]
enum JumpTarget {
    Next,
    Label(FilterLabel),
}

enum FilterInsn {
    Code {
        code: u16,
        k: u32,
        jt: JumpTarget,
        jf: JumpTarget,
    },
    Ret(u32),
    Label(FilterLabel),
}

#[derive(Default)]
struct FilterBuilder {
    insns: Vec<FilterInsn>,
}

impl FilterBuilder {
    fn stmt(&mut self, code: u16, k: u32) {
        self.insns.push(FilterInsn::Code {
            code,
            k,
            jt: JumpTarget::Next,
            jf: JumpTarget::Next,
        });
    }

    fn jump(&mut self, code: u16, k: u32, jt: JumpTarget, jf: JumpTarget) {
        self.insns.push(FilterInsn::Code { code, k, jt, jf });
    }

    fn ret(&mut self, action: u32) {
        self.insns.push(FilterInsn::Ret(action));
    }

    fn label(&mut self, label: FilterLabel) {
        self.insns.push(FilterInsn::Label(label));
    }

    /// Resolve symbolic labels to BPF forward-jump offsets.
    ///
    /// The builder is internal and every label is emitted by this module, but
    /// returning an error keeps a future edit from turning a malformed profile
    /// into a panic during sandbox setup.
    fn finish(self) -> io::Result<Vec<SockFilter>> {
        let mut labels: Vec<(FilterLabel, usize)> = Vec::new();
        let mut count = 0usize;
        for insn in &self.insns {
            match insn {
                FilterInsn::Label(label) => labels.push((*label, count)),
                _ => count += 1,
            }
        }
        let position = |label: FilterLabel| -> io::Result<usize> {
            labels
                .iter()
                .find(|(candidate, _)| *candidate == label)
                .map(|(_, position)| *position)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "seccomp filter label is not defined",
                    )
                })
        };

        let mut out = Vec::with_capacity(count);
        let mut index = 0usize;
        for insn in self.insns {
            match insn {
                FilterInsn::Label(_) => {}
                FilterInsn::Ret(action) => {
                    out.push(SockFilter {
                        code: BPF_RET | BPF_K,
                        jt: 0,
                        jf: 0,
                        k: action,
                    });
                    index += 1;
                }
                FilterInsn::Code { code, k, jt, jf } => {
                    let resolve = |target: JumpTarget| -> io::Result<u8> {
                        match target {
                            JumpTarget::Next => Ok(0),
                            JumpTarget::Label(label) => {
                                let target = position(label)?;
                                if target <= index {
                                    return Err(io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        "seccomp jumps must be forward",
                                    ));
                                }
                                u8::try_from(target - index - 1).map_err(|_| {
                                    io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        "seccomp jump offset does not fit in u8",
                                    )
                                })
                            }
                        }
                    };
                    out.push(SockFilter {
                        code,
                        jt: resolve(jt)?,
                        jf: resolve(jf)?,
                        k,
                    });
                    index += 1;
                }
            }
        }
        Ok(out)
    }
}

/// Build the default Milestone 2 seccomp profile.
///
/// The profile is static, so an error here means a programming mistake in the
/// builder rather than an input problem. Returning it lets the caller fail
/// closed without panicking during sandbox setup.
pub fn default_seccomp_program() -> io::Result<SeccompProgram> {
    let deny = SECCOMP_RET_ERRNO | (libc::EPERM as u32);
    let enosys = SECCOMP_RET_ERRNO | (libc::ENOSYS as u32);
    let load = BPF_LD | BPF_W | BPF_ABS;
    let jeq = BPF_JMP | BPF_JEQ | BPF_K;
    let and = BPF_ALU | BPF_AND | BPF_K;

    let mut filter = FilterBuilder::default();

    // A process using a different syscall ABI must not be interpreted through
    // the native numbers.
    filter.stmt(load, 4);
    filter.jump(
        jeq,
        AUDIT_ARCH_X86_64,
        JumpTarget::Next,
        JumpTarget::Label(FilterLabel::ForeignAbi),
    );

    // x32 uses the native arch with a high bit on the syscall number.
    filter.stmt(load, 0);
    filter.stmt(and, X32_SYSCALL_BIT);
    filter.jump(
        jeq,
        0,
        JumpTarget::Next,
        JumpTarget::Label(FilterLabel::X32Abi),
    );
    filter.stmt(load, 0);

    for number in DENIED_SYSCALLS {
        filter.jump(
            jeq,
            *number as u32,
            JumpTarget::Label(FilterLabel::Deny),
            JumpTarget::Next,
        );
    }

    // glibc probes clone3 first; ENOSYS makes it fall back to clone, whose
    // flags this filter inspects.
    filter.jump(
        jeq,
        libc::SYS_clone3 as u32,
        JumpTarget::Label(FilterLabel::Enosys),
        JumpTarget::Next,
    );

    // ioctl is allowed except for TIOCSTI, which injects terminal input.
    filter.jump(
        jeq,
        libc::SYS_ioctl as u32,
        JumpTarget::Label(FilterLabel::IoctlCheck),
        JumpTarget::Label(FilterLabel::CloneCheck),
    );
    filter.label(FilterLabel::IoctlCheck);
    filter.stmt(load, 24); // seccomp_data.args[1], low 32 bits
    filter.jump(
        jeq,
        TIOCSTI as u32,
        JumpTarget::Label(FilterLabel::Deny),
        JumpTarget::Label(FilterLabel::Allow),
    );

    filter.label(FilterLabel::CloneCheck);
    filter.jump(
        jeq,
        libc::SYS_clone as u32,
        JumpTarget::Next,
        JumpTarget::Label(FilterLabel::Allow),
    );
    filter.stmt(load, 16); // seccomp_data.args[0], low 32 bits (clone flags)
    filter.stmt(and, CLONE_ALL_NEW_NAMESPACES as u32);
    filter.jump(
        jeq,
        0,
        JumpTarget::Label(FilterLabel::Allow),
        JumpTarget::Label(FilterLabel::Deny),
    );

    filter.label(FilterLabel::Deny);
    filter.ret(deny);
    filter.label(FilterLabel::Allow);
    filter.ret(SECCOMP_RET_ALLOW);
    filter.label(FilterLabel::Enosys);
    filter.ret(enosys);
    filter.label(FilterLabel::X32Abi);
    filter.ret(deny);
    filter.label(FilterLabel::ForeignAbi);
    filter.ret(deny);

    Ok(SeccompProgram {
        filter: filter.finish()?,
    })
}

/// Make every mount in this mount namespace private. Without this, mount
/// operations performed while building the sandbox could propagate to the host.
pub fn make_mounts_private() -> io::Result<()> {
    // SAFETY: mount with null source/fstype/data and integer flags is valid;
    // MS_REC|MS_PRIVATE is the documented recursive propagation change.
    let rc = unsafe {
        libc::mount(
            std::ptr::null(),
            c"/".as_ptr(),
            std::ptr::null(),
            (libc::MS_REC | libc::MS_PRIVATE) as c_ulong,
            std::ptr::null(),
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Mount a tmpfs at `target`.
pub fn mount_tmpfs(target: &CStr, options: &CStr, flags: c_ulong) -> io::Result<()> {
    // SAFETY: all pointers refer to valid NUL-terminated strings for the
    // duration of the call.
    let rc = unsafe {
        libc::mount(
            c"tmpfs".as_ptr(),
            target.as_ptr(),
            c"tmpfs".as_ptr(),
            flags,
            options.as_ptr().cast::<c_void>(),
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Mount a fresh procfs. `subset=pid` hides `/proc/sys`, `/proc/fs` and other
/// non-pid entries, reducing the writable kernel surface visible to the target.
pub fn mount_proc(flags: c_ulong) -> io::Result<()> {
    // SAFETY: all pointers refer to valid NUL-terminated strings.
    let rc = unsafe {
        libc::mount(
            c"proc".as_ptr(),
            c"/proc".as_ptr(),
            c"proc".as_ptr(),
            flags,
            c"subset=pid".as_ptr().cast::<c_void>(),
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[repr(C)]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

const MOUNT_ATTR_RDONLY: u64 = 0x0000_0001;
const MOUNT_ATTR_NOSUID: u64 = 0x0000_0002;
const MOUNT_ATTR_NODEV: u64 = 0x0000_0004;
const AT_RECURSIVE: c_uint = 0x0000_8000;

fn apply_mount_attrs(target: &CStr, recursive: bool, attr_set: u64) -> io::Result<()> {
    let attr = MountAttr {
        attr_set,
        attr_clr: 0,
        propagation: 0,
        userns_fd: 0,
    };
    let flags = if recursive { AT_RECURSIVE } else { 0 };
    // SAFETY: target is a valid C string; attr points to a live struct of the
    // size passed. mount_setattr validates both.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            libc::AT_FDCWD,
            target.as_ptr(),
            flags,
            &attr as *const MountAttr,
            std::mem::size_of::<MountAttr>(),
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Bind-mount `source` at `target` and apply the requested attributes to the
/// whole cloned subtree. `mount_setattr(AT_RECURSIVE)` is used instead of a
/// plain remount because a recursive bind can contain submounts that would
/// otherwise remain writable or suid.
pub fn mount_bind(
    source: &CStr,
    target: &CStr,
    recursive: bool,
    readonly: bool,
    allow_devices: bool,
) -> io::Result<()> {
    let mut flags = libc::MS_BIND as c_ulong;
    if recursive {
        flags |= libc::MS_REC as c_ulong;
    }
    // SAFETY: source and target are valid C strings; bind mounts ignore the
    // fstype/data arguments.
    let rc = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            std::ptr::null(),
            flags,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }

    let mut attrs = MOUNT_ATTR_NOSUID;
    if !allow_devices {
        attrs |= MOUNT_ATTR_NODEV;
    }
    if readonly {
        attrs |= MOUNT_ATTR_RDONLY;
    }
    apply_mount_attrs(target, recursive, attrs)
}

/// `pivot_root(2)`. The caller must ensure `new_root` is a mount point and
/// `put_old` is a directory underneath it.
pub fn pivot_root(new_root: &CStr, put_old: &CStr) -> io::Result<()> {
    // SAFETY: both pointers are valid NUL-terminated path strings. libc does
    // not expose a pivot_root wrapper for every target, so call the syscall
    // directly with the same two-pointer ABI.
    let rc = unsafe { libc::syscall(libc::SYS_pivot_root, new_root.as_ptr(), put_old.as_ptr()) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Unmount a path in the current mount namespace.
pub fn umount2(target: &CStr, flags: c_int) -> io::Result<()> {
    // SAFETY: target is a valid C string.
    let rc = unsafe { libc::umount2(target.as_ptr(), flags) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub fn chdir(path: &CStr) -> io::Result<()> {
    // SAFETY: path is a valid C string.
    let rc = unsafe { libc::chdir(path.as_ptr()) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub fn chroot(path: &CStr) -> io::Result<()> {
    // SAFETY: path is a valid C string.
    let rc = unsafe { libc::chroot(path.as_ptr()) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub fn setns(fd: c_int, nstype: c_int) -> io::Result<()> {
    // SAFETY: fd is an open namespace descriptor supplied by the caller.
    let rc = unsafe { libc::setns(fd, nstype) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub fn setuid(uid: u32) -> io::Result<()> {
    // SAFETY: setuid takes an integer argument.
    let rc = unsafe { libc::setuid(uid) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub fn setgid(gid: u32) -> io::Result<()> {
    // SAFETY: setgid takes an integer argument.
    let rc = unsafe { libc::setgid(gid) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Read the current UTS namespace hostname. Allocates, so only use outside the
/// forked target path.
pub fn gethostname() -> io::Result<String> {
    let mut buffer = vec![0u8; 256];
    // SAFETY: buffer is a live byte slice of the length passed.
    let rc = unsafe { libc::gethostname(buffer.as_mut_ptr().cast::<c_char>(), buffer.len()) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    let end = buffer.iter().position(|b| *b == 0).unwrap_or(buffer.len());
    String::from_utf8(buffer[..end].to_vec())
        .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
}

pub fn mkdir(path: &CStr, mode: u32) -> io::Result<()> {
    // SAFETY: path is a valid C string.
    let rc = unsafe { libc::mkdir(path.as_ptr(), mode as libc::mode_t) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub fn rmdir(path: &CStr) -> io::Result<()> {
    // SAFETY: path is a valid C string.
    let rc = unsafe { libc::rmdir(path.as_ptr()) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub fn symlink(target: &CStr, link_path: &CStr) -> io::Result<()> {
    // SAFETY: both pointers are valid C strings.
    let rc = unsafe { libc::symlink(target.as_ptr(), link_path.as_ptr()) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Create a file with fixed contents. Used for the synthesized `/etc`; the
/// contents are computed by the parent before `fork()`.
pub fn create_file(path: &CStr, mode: u32, contents: &[u8]) -> io::Result<()> {
    // SAFETY: path is a valid C string and open only reads its flag arguments.
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            mode as libc::mode_t,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let ok = write_fd(fd, contents);
    // SAFETY: fd was opened above and is owned here.
    unsafe {
        libc::close(fd);
    }
    if ok {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(libc::EIO))
    }
}

pub fn sethostname(name: &CStr) -> io::Result<()> {
    // SAFETY: name points to `len` live bytes.
    let rc = unsafe { libc::sethostname(name.as_ptr(), name.to_bytes().len()) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub fn setsid() -> io::Result<()> {
    // SAFETY: setsid has no pointer arguments.
    let rc = unsafe { libc::setsid() };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Drop ambient, bounding, permitted, effective and inheritable capabilities.
///
/// The order matters: ambient caps must go before `capset` clears permitted,
/// and the bounding set is dropped one capability at a time because Linux has
/// no set-wide syscall for it.
pub fn drop_all_capabilities() -> io::Result<()> {
    // SAFETY: prctl with PR_CAP_AMBIENT takes integer arguments.
    let ambient = unsafe { libc::prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) };
    if ambient != 0 {
        let err = io::Error::last_os_error();
        // Kernels before ambient support return EINVAL; there is no ambient
        // set to clear in that case.
        if err.raw_os_error() != Some(libc::EINVAL) {
            return Err(err);
        }
    }

    for cap in 0..=63 {
        // SAFETY: prctl with PR_CAPBSET_DROP takes integer arguments.
        let rc = unsafe { libc::prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) };
        if rc != 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINVAL) {
                break; // past cap_last_cap
            }
            return Err(err);
        }
    }

    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: c_int,
    }
    // `_LINUX_CAPABILITY_VERSION_3` describes 64 capabilities. The data buffer
    // is an array of two 12-byte `__user_cap_data_struct` values (effective,
    // permitted, inheritable for caps 0-31 and 32-63). Passing a smaller
    // buffer would let the kernel read out of bounds and reject the call.
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let header = CapHeader {
        version: 0x2008_0522,
        pid: 0,
    };
    let data = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: header and data point to live structs of the size the version
    // requires; capset validates the version and length.
    let rc = unsafe { libc::syscall(libc::SYS_capset, &header as *const CapHeader, data.as_ptr()) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Close every descriptor above stderr except `keep`.
///
/// `keep` is the status pipe, which is CLOEXEC: it survives until `execve` and
/// closes atomically on success, but the target never sees it. A fallback avoids
/// silently leaving descriptors open on pre-5.9 kernels.
pub fn close_fds_except(keep: c_int) -> io::Result<()> {
    for (first, last) in [
        (3u32, (keep - 1).max(0) as u32),
        ((keep + 1) as u32, u32::MAX),
    ] {
        if first > last {
            continue;
        }
        // SAFETY: close_range takes integer arguments.
        let rc = unsafe { libc::syscall(libc::SYS_close_range, first, last, 0 as c_uint) };
        if rc == 0 {
            continue;
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::ENOSYS) {
            return Err(err);
        }
        // Fallback: never silently skip descriptor hygiene.
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: limit points to a live rlimit.
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let upper = limit.rlim_cur.min(u32::MAX as libc::rlim_t) as u32;
        for fd in first..=last.min(upper) {
            if fd as c_int == keep {
                continue;
            }
            // SAFETY: closing an arbitrary fd number is safe; EBADF is ignored.
            unsafe {
                libc::close(fd as c_int);
            }
        }
    }
    Ok(())
}

/// Execute the target. Returns only on failure; the return value is errno.
///
/// The slices are the null-terminated pointer arrays built before `fork`.
/// Taking slices instead of raw pointers keeps the pointer validity invariant
/// at the caller and avoids exposing a raw-pointer dereference from safe code.
pub fn execve_raw(path: &CStr, argv: &[*const c_char], envp: &[*const c_char]) -> c_int {
    // SAFETY: argv/envp are null-terminated pointer arrays built from live
    // CStrings in the caller. execve does not return on success.
    unsafe { libc::execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
    io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

#[repr(C)]
struct IfReq {
    name: [c_char; 16],
    data: [u32; 6],
}

/// Bring up `lo` and give it 127.0.0.1/8 inside a fresh network namespace.
///
/// A new net namespace has a loopback interface but it starts down and without
/// an address. Using ioctls avoids depending on `ip` being present in the new
/// root. This is still "loopback only": there is no route to the host.
pub fn bring_up_loopback() -> io::Result<()> {
    // SAFETY: socket takes integer arguments.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut ifr = IfReq {
        name: [0; 16],
        data: [0; 6],
    };
    for (dst, src) in ifr.name.iter_mut().zip(b"lo\0".iter()) {
        *dst = *src as c_char;
    }

    // 127.0.0.1 in network byte order stored in a native u32.
    let addr = libc::sockaddr_in {
        sin_family: libc::AF_INET as u16,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes([127, 0, 0, 1]),
        },
        sin_zero: [0; 8],
    };
    // SAFETY: ifr.data is 24 bytes, large enough for sockaddr_in (16 bytes).
    unsafe {
        std::ptr::write(ifr.data.as_mut_ptr().cast::<libc::sockaddr_in>(), addr);
    }
    // SAFETY: fd is a live AF_INET socket and ifr is a valid ifreq.
    let rc = unsafe { libc::ioctl(fd, 0x8916u64, &mut ifr) }; // SIOCSIFADDR
    if rc != 0 {
        let err = io::Error::last_os_error();
        // SAFETY: fd is owned here.
        unsafe { libc::close(fd) };
        return Err(err);
    }

    let mask = libc::sockaddr_in {
        sin_family: libc::AF_INET as u16,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes([255, 0, 0, 0]),
        },
        sin_zero: [0; 8],
    };
    // SAFETY: as above.
    unsafe {
        std::ptr::write(ifr.data.as_mut_ptr().cast::<libc::sockaddr_in>(), mask);
    }
    // SAFETY: as above. SIOCSIFNETMASK.
    let rc = unsafe { libc::ioctl(fd, 0x891cu64, &mut ifr) };
    if rc != 0 {
        let err = io::Error::last_os_error();
        // SAFETY: fd is owned here.
        unsafe { libc::close(fd) };
        return Err(err);
    }

    // SAFETY: read the ifr_flags short at the start of the union storage.
    let flags_ptr = ifr.data.as_mut_ptr().cast::<c_short>();
    // SAFETY: fd/ifr as above. SIOCGIFFLAGS.
    let rc = unsafe { libc::ioctl(fd, 0x8913u64, &mut ifr) };
    if rc != 0 {
        let err = io::Error::last_os_error();
        // SAFETY: fd is owned here.
        unsafe { libc::close(fd) };
        return Err(err);
    }
    // SAFETY: flags_ptr points into ifr.data, which is live.
    unsafe {
        *flags_ptr |= (libc::IFF_UP | libc::IFF_RUNNING) as c_short;
    }
    // SAFETY: fd/ifr as above. SIOCSIFFLAGS.
    let rc = unsafe { libc::ioctl(fd, 0x8914u64, &mut ifr) };
    let err = if rc == 0 {
        None
    } else {
        Some(io::Error::last_os_error())
    };
    // SAFETY: fd is owned here.
    unsafe { libc::close(fd) };
    if let Some(e) = err {
        Err(e)
    } else {
        Ok(())
    }
}

pub fn getpid() -> c_int {
    // SAFETY: getpid has no preconditions.
    unsafe { libc::getpid() }
}

pub fn getuid() -> u32 {
    // SAFETY: getuid has no preconditions.
    unsafe { libc::getuid() }
}

pub fn getgid() -> u32 {
    // SAFETY: getgid has no preconditions.
    unsafe { libc::getgid() }
}

pub fn geteuid() -> u32 {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() }
}

pub fn kill(pid: c_int, signal: c_int) -> io::Result<()> {
    // SAFETY: kill takes integer arguments.
    let rc = unsafe { libc::kill(pid, signal) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

// ---------------------------------------------------------------------------
// Small helpers used by the escape tests. They are safe wrappers so that test
// code does not need its own `unsafe` blocks (AGENTS.md keeps unsafe in sbx-sys).
// ---------------------------------------------------------------------------

/// Read at most `max` bytes from `fd` once.
///
/// Unlike [`read_fd`], a short read is success: the escape tests use this on
/// files whose length is not known in advance.
pub fn read_fd_once(fd: c_int, max: usize) -> io::Result<Vec<u8>> {
    if max == 0 {
        return Ok(Vec::new());
    }
    let mut buffer = vec![0u8; max];
    loop {
        // SAFETY: buffer is a live, writable slice and `fd` is supplied by the
        // caller; the length is bounded by the allocation above.
        let n = unsafe { libc::read(fd, buffer.as_mut_ptr().cast::<c_void>(), buffer.len()) };
        if n < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        buffer.truncate(n as usize);
        return Ok(buffer);
    }
}

/// Install `from` at the fixed descriptor `to`, clearing close-on-exec.
///
/// The escape tests use this to prove that sbx closes inherited descriptors
/// above stderr before `execve`.
pub fn dup2_fd(from: &OwnedFd, to: c_int) -> io::Result<()> {
    // SAFETY: `from` is a live descriptor owned by the caller. dup2 removes
    // close-on-exec from the copy, which is the property under test.
    let rc = unsafe { libc::dup2(from.as_raw_fd(), to) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Connect to a TCP address as an untrusted process would.
pub fn connect_tcp(ip: [u8; 4], port: u16) -> io::Result<()> {
    // SAFETY: socket takes integer arguments.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let addr = libc::sockaddr_in {
        sin_family: libc::AF_INET as u16,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(ip),
        },
        sin_zero: [0; 8],
    };
    // SAFETY: addr is a fully initialised sockaddr_in and the length matches.
    let rc = unsafe {
        libc::connect(
            fd,
            (&addr as *const libc::sockaddr_in).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    let result = if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    };
    // SAFETY: fd is owned here.
    unsafe { libc::close(fd) };
    result
}

/// Whether stdin is a terminal. `TIOCSTI` is only meaningful on a tty.
pub fn stdin_is_tty() -> bool {
    // SAFETY: isatty takes an integer descriptor.
    unsafe { libc::isatty(0) == 1 }
}

/// Call `clone3` with deliberately invalid arguments.
///
/// Outside the sandbox the kernel returns `EINVAL` (the syscall is reached);
/// the Milestone 1 filter returns `ENOSYS` so that libc falls back to `clone`.
pub fn clone3_probe() -> io::Result<()> {
    // SAFETY: clone3 is passed a null argument pointer and a zero size; the
    // kernel validates both before dereferencing anything.
    let rc = unsafe { libc::syscall(libc::SYS_clone3, std::ptr::null::<c_void>(), 0usize) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Issue a raw syscall with six machine-word arguments.
///
/// Only the probe helpers below use this. They all pass deliberately invalid
/// arguments so that an unmodified kernel either returns a non-`EPERM` error or
/// succeeds without side effects, which makes the filter's `EPERM` observable.
fn probe_syscall(nr: c_long, args: [c_ulong; 6]) -> io::Result<c_long> {
    // SAFETY: libc::syscall forwards the six register-sized arguments to the
    // kernel. Each caller below documents why the pointers and values are safe
    // for its specific syscall.
    let rc = unsafe { libc::syscall(nr, args[0], args[1], args[2], args[3], args[4], args[5]) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(rc)
    }
}

/// Call the x32 variant of `getpid` by setting the x32 syscall-number bit.
pub fn x32_getpid_probe() -> io::Result<()> {
    let number = (libc::SYS_getpid as u32 | X32_SYSCALL_BIT) as c_long;
    probe_syscall(number, [0; 6]).map(|_| ())
}

/// Ask the kernel about `ptrace` with a pid that cannot exist.
pub fn ptrace_probe() -> io::Result<()> {
    // PTRACE_PEEKDATA, pid -1, addr 0, data 0. An unmodified kernel returns
    // ESRCH before looking at the address or data arguments.
    probe_syscall(
        libc::SYS_ptrace,
        [
            libc::PTRACE_PEEKDATA as c_ulong,
            (-1i64) as c_ulong,
            0,
            0,
            0,
            0,
        ],
    )
    .map(|_| ())
}

/// Read this process's own memory through `process_vm_readv`.
pub fn process_vm_readv_self(buffer: &mut [u8]) -> io::Result<usize> {
    let mut iov = libc::iovec {
        iov_base: buffer.as_mut_ptr() as *mut c_void,
        iov_len: buffer.len(),
    };
    // SAFETY: iov is a live, writable local buffer and the same iovec is used
    // for both local and remote addresses of this process. The kernel only
    // copies into the local iovec.
    let rc = probe_syscall(
        libc::SYS_process_vm_readv,
        [
            std::process::id() as c_ulong,
            (&mut iov) as *mut libc::iovec as c_ulong,
            1,
            (&iov) as *const libc::iovec as c_ulong,
            1,
            0,
        ],
    )?;
    usize::try_from(rc).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
}

/// Call `bpf` with an unknown command so an unmodified kernel returns EINVAL.
pub fn bpf_probe() -> io::Result<()> {
    probe_syscall(libc::SYS_bpf, [0xdead, 0, 0, 0, 0, 0]).map(|_| ())
}

/// Call `perf_event_open` with a null attribute pointer (EFAULT at the kernel).
pub fn perf_event_open_probe() -> io::Result<()> {
    probe_syscall(
        libc::SYS_perf_event_open,
        [
            0,
            (-1i64) as c_ulong,
            (-1i64) as c_ulong,
            (-1i64) as c_ulong,
            0,
            0,
        ],
    )
    .map(|_| ())
}

/// Call `userfaultfd` with an invalid flag word so the kernel returns EINVAL.
pub fn userfaultfd_probe() -> io::Result<()> {
    probe_syscall(libc::SYS_userfaultfd, [0xdead, 0, 0, 0, 0, 0]).map(|_| ())
}

/// Call `io_uring_setup` with a null params pointer (EFAULT at the kernel).
pub fn io_uring_setup_probe() -> io::Result<()> {
    probe_syscall(libc::SYS_io_uring_setup, [0, 0, 0, 0, 0, 0]).map(|_| ())
}

/// Call `keyctl` with an unknown operation so an unmodified kernel returns
/// ENOTSUP rather than EPERM.
pub fn keyctl_probe() -> io::Result<()> {
    probe_syscall(libc::SYS_keyctl, [0xdead, 0, 0, 0, 0, 0]).map(|_| ())
}

/// Open a pidfd for this process and close it immediately.
pub fn pidfd_open_probe() -> io::Result<()> {
    let fd = probe_syscall(
        libc::SYS_pidfd_open,
        [(std::process::id() as c_ulong), 0, 0, 0, 0, 0],
    )?;
    let fd = c_int::try_from(fd).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    close_fd(fd);
    Ok(())
}

/// Call `open_by_handle_at` with an invalid mount descriptor and null handle.
pub fn open_by_handle_at_probe() -> io::Result<()> {
    probe_syscall(
        libc::SYS_open_by_handle_at,
        [(-1i64) as c_ulong, 0, 0, 0, 0, 0],
    )
    .map(|_| ())
}

/// Open `path` without O_CLOEXEC so a test can prove that sbx closes inherited
/// descriptors before exec.
pub fn open_inheritable_read(path: &Path) -> io::Result<OwnedFd> {
    let bytes = path.as_os_str().as_bytes();
    let cpath = CString::new(bytes).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    // SAFETY: cpath is a valid C string.
    let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDONLY) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: open returned a fresh descriptor owned here.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn abstract_address(name: &str) -> io::Result<(libc::sockaddr_un, libc::socklen_t)> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > 106 {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    // SAFETY: sockaddr_un is a plain C struct; zeroing is a valid initial state.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as u16;
    addr.sun_path[0] = 0;
    for (dst, src) in addr.sun_path[1..].iter_mut().zip(bytes.iter()) {
        *dst = *src as c_char;
    }
    let offset = std::mem::offset_of!(libc::sockaddr_un, sun_path);
    Ok((addr, (offset + 1 + bytes.len()) as libc::socklen_t))
}

/// Connect to an abstract unix socket. Used to prove the sandbox net namespace
/// does not share the host's abstract socket namespace.
pub fn connect_abstract(name: &str) -> io::Result<()> {
    let (addr, len) = abstract_address(name)?;
    // SAFETY: socket takes integer arguments.
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: addr is a valid sockaddr_un and len covers its used bytes.
    let rc = unsafe {
        libc::connect(
            fd,
            (&addr as *const libc::sockaddr_un).cast::<libc::sockaddr>(),
            len,
        )
    };
    let err = if rc == 0 {
        None
    } else {
        Some(io::Error::last_os_error())
    };
    // SAFETY: fd is owned here.
    unsafe { libc::close(fd) };
    match err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// Bind and listen on an abstract unix socket for the test harness.
pub fn bind_abstract_listener(name: &str) -> io::Result<OwnedFd> {
    let (addr, len) = abstract_address(name)?;
    // SAFETY: socket takes integer arguments.
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: addr/len describe a valid abstract address.
    let rc = unsafe {
        libc::bind(
            fd,
            (&addr as *const libc::sockaddr_un).cast::<libc::sockaddr>(),
            len,
        )
    };
    if rc != 0 {
        let err = io::Error::last_os_error();
        // SAFETY: fd is owned here.
        unsafe { libc::close(fd) };
        return Err(err);
    }
    // SAFETY: fd is a live socket.
    let rc = unsafe { libc::listen(fd, 1) };
    if rc != 0 {
        let err = io::Error::last_os_error();
        // SAFETY: fd is owned here.
        unsafe { libc::close(fd) };
        return Err(err);
    }
    // SAFETY: fd is fresh and owned here.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Attempt `TIOCSTI` on stdin. A sandboxed process has no controlling terminal,
/// so this must fail even if fd 0 happens to be a pty slave.
pub fn tiocsti(byte: u8) -> io::Result<()> {
    let value = byte as c_char;
    // SAFETY: fd 0 is assumed live; ioctl reads one byte through the pointer.
    let rc = unsafe { libc::ioctl(0, libc::TIOCSTI, &value) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// First non-loopback IPv4 address, for the external-style connect attempt.
pub fn first_nonloopback_ipv4() -> Option<[u8; 4]> {
    let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: ifap points to a null pointer that getifaddrs fills on success.
    if unsafe { libc::getifaddrs(&mut ifap) } != 0 {
        return None;
    }
    let mut current = ifap;
    let mut found = None;
    while !current.is_null() {
        // SAFETY: getifaddrs returned a linked list of valid entries.
        let ifa = unsafe { &*current };
        if !ifa.ifa_addr.is_null() {
            // SAFETY: ifa_addr points to a sockaddr if non-null.
            let family = unsafe { (*ifa.ifa_addr).sa_family };
            if family == libc::AF_INET as u16 {
                // SAFETY: AF_INET means the pointer really is sockaddr_in.
                let sin = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in) };
                let bytes = sin.sin_addr.s_addr.to_ne_bytes();
                if bytes != [127, 0, 0, 1] && bytes[0] != 0 {
                    found = Some(bytes);
                    break;
                }
            }
        }
        // SAFETY: current is a valid list node; ifa_next may be null.
        current = unsafe { (*current).ifa_next };
    }
    // SAFETY: ifap came from getifaddrs and is freed exactly once.
    unsafe { libc::freeifaddrs(ifap) };
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    const X86_64: u32 = AUDIT_ARCH_X86_64;
    const I386: u32 = 0x4000_0003;

    fn deny_eperm() -> u32 {
        SECCOMP_RET_ERRNO | (libc::EPERM as u32)
    }

    fn deny_enosys() -> u32 {
        SECCOMP_RET_ERRNO | (libc::ENOSYS as u32)
    }

    /// A deliberately small interpreter for the exact instruction subset used
    /// by `FilterBuilder`. It lives in the test module so the production code
    /// does not gain a second, unused BPF implementation.
    fn evaluate(program: &SeccompProgram, nr: u32, arch: u32, args: [u64; 6]) -> u32 {
        let mut data = [0u8; 64];
        data[0..4].copy_from_slice(&nr.to_ne_bytes());
        data[4..8].copy_from_slice(&arch.to_ne_bytes());
        for (index, arg) in args.iter().enumerate() {
            let start = 16 + index * 8;
            data[start..start + 8].copy_from_slice(&arg.to_ne_bytes());
        }
        let read_u32 = |offset: u32| -> u32 {
            let start = offset as usize;
            u32::from_ne_bytes(data[start..start + 4].try_into().expect("in range"))
        };

        let mut accumulator = 0u32;
        let mut pc = 0usize;
        loop {
            let instruction = program
                .filter
                .get(pc)
                .unwrap_or_else(|| panic!("filter ran off the end at {pc}"));
            pc += 1;
            match instruction.code {
                code if code == BPF_LD | BPF_W | BPF_ABS => accumulator = read_u32(instruction.k),
                code if code == BPF_ALU | BPF_AND | BPF_K => accumulator &= instruction.k,
                code if code == BPF_JMP | BPF_JEQ | BPF_K => {
                    let offset = if accumulator == instruction.k {
                        instruction.jt
                    } else {
                        instruction.jf
                    };
                    pc += offset as usize;
                }
                code if code == BPF_RET | BPF_K => return instruction.k,
                other => panic!("unexpected BPF instruction {other:#x} at {}", pc - 1),
            }
        }
    }

    fn run_syscall(nr: c_long, args: [u64; 6]) -> u32 {
        evaluate(
            &default_seccomp_program().expect("seccomp profile"),
            nr as u32,
            X86_64,
            args,
        )
    }

    #[test]
    fn filter_allows_ordinary_syscalls() {
        for number in [
            libc::SYS_getpid,
            libc::SYS_read,
            libc::SYS_write,
            libc::SYS_openat,
            libc::SYS_futex,
            libc::SYS_execve,
            libc::SYS_exit_group,
        ] {
            assert_eq!(run_syscall(number, [0; 6]), SECCOMP_RET_ALLOW, "{number}");
        }
    }

    #[test]
    fn filter_denies_every_denylisted_syscall_with_eperm() {
        for number in DENIED_SYSCALLS {
            assert_eq!(
                run_syscall(*number, [0; 6]),
                deny_eperm(),
                "syscall {number} is not denied"
            );
        }
    }

    #[test]
    fn filter_returns_enosys_for_clone3() {
        assert_eq!(run_syscall(libc::SYS_clone3, [0; 6]), deny_enosys());
    }

    #[test]
    fn filter_denies_foreign_and_x32_abis() {
        let program = default_seccomp_program().expect("seccomp profile");
        assert_eq!(
            evaluate(&program, libc::SYS_getpid as u32, I386, [0; 6]),
            deny_eperm()
        );
        let x32 = libc::SYS_getpid as u32 | X32_SYSCALL_BIT;
        assert_eq!(evaluate(&program, x32, X86_64, [0; 6]), deny_eperm());
    }

    #[test]
    fn filter_denies_tiocsti_but_allows_other_ioctls() {
        assert_eq!(
            run_syscall(libc::SYS_ioctl, [0, TIOCSTI, 0, 0, 0, 0]),
            deny_eperm()
        );
        assert_eq!(
            run_syscall(libc::SYS_ioctl, [0, libc::TCGETS, 0, 0, 0, 0]),
            SECCOMP_RET_ALLOW
        );
    }

    #[test]
    fn filter_allows_clone_without_namespace_flags() {
        assert_eq!(
            run_syscall(libc::SYS_clone, [libc::SIGCHLD as u64, 0, 0, 0, 0, 0]),
            SECCOMP_RET_ALLOW
        );
        for flag in [CLONE_NEWUSER, CLONE_NEWNS, CLONE_NEWPID, CLONE_NEWTIME] {
            assert_eq!(
                run_syscall(libc::SYS_clone, [flag as u64, 0, 0, 0, 0, 0]),
                deny_eperm(),
                "clone flag {flag:#x}"
            );
        }
    }

    #[test]
    fn filter_is_structurally_sound() {
        let program = default_seccomp_program().expect("seccomp profile");
        assert!(!program.filter.is_empty());
        assert!(
            program.filter.len() <= 4096,
            "a BPF program may not exceed 4096 instructions"
        );
        for (index, instruction) in program.filter.iter().enumerate() {
            for offset in [instruction.jt, instruction.jf] {
                let target = index + 1 + offset as usize;
                assert!(
                    target <= program.filter.len(),
                    "jump from {index} points past the end"
                );
            }
        }
    }

    #[test]
    fn landlock_access_mask_tracks_abi() {
        let base = landlock_access_for_abi(1);
        assert_eq!(base & LANDLOCK_ACCESS_FS_REFER, 0);
        assert_eq!(base & LANDLOCK_ACCESS_FS_TRUNCATE, 0);
        assert_ne!(base & LANDLOCK_ACCESS_FS_EXECUTE, 0);
        assert_ne!(base & LANDLOCK_ACCESS_FS_MAKE_REG, 0);
        assert_ne!(landlock_access_for_abi(2) & LANDLOCK_ACCESS_FS_REFER, 0);
        assert_eq!(landlock_access_for_abi(2) & LANDLOCK_ACCESS_FS_TRUNCATE, 0);
        assert_ne!(landlock_access_for_abi(3) & LANDLOCK_ACCESS_FS_TRUNCATE, 0);
        assert_eq!(landlock_access_for_abi(10), landlock_access_for_abi(3));
    }
}
