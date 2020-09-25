//! Functions that handle all the `ptrace` and `wait` nastiness for us.
use std::fs;
use std::fmt;
use std::slice;
use std::process;
use std::cmp::min;
use std::ffi::CString;
use std::mem::{self, MaybeUninit};
use std::convert::TryInto;
use lazy_static::lazy_static;
use libc::{self, c_void, c_char};
use crate::system::{self, SystemError};

// Re-export some common syscall names so we don't have to cast all the time.
pub const SYS_CLONE: usize = libc::SYS_clone as usize;
pub const SYS_FORK: usize = libc::SYS_fork as usize;
pub const SYS_VFORK: usize = libc::SYS_vfork as usize;
pub const SYS_EXECVE: usize = libc::SYS_execve as usize;
pub const SYS_WAIT4: usize = libc::SYS_wait4 as usize;
pub const SYS_WAITID: usize = libc::SYS_waitid as usize;
pub const SYS_KILL: usize = libc::SYS_kill as usize;
pub const SYS_PTRACE: usize = libc::SYS_ptrace as usize;
pub const SYS_SETPGID: usize = libc::SYS_setpgid as usize;
pub const SYS_SETSID: usize = libc::SYS_setsid as usize;
pub const SYS_TKILL: usize = libc::SYS_tkill as usize;
pub const SYS_TGKILL: usize = libc::SYS_tgkill as usize;
pub const SYS_EXECVEAT: usize = libc::SYS_execveat as usize;

lazy_static! {
    static ref PAGE_SIZE: usize = {
        let ret = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        assert_ne!(ret, -1, "Failed to query page size");
        ret as usize
    };
}

/// Possible errors that can occur for ptrace operations.
/// 
/// This doesn't cover all of the possible errors for the functions used, but
/// if a non-plausible error occurs we'll just panic anyway so who cares.
#[derive(Debug)]
pub enum TraceError {
    /// The tracee either doesn't exist (in which case it probably ended and
    /// we will get a notification of how it ended when we next wait on it)
    /// or the tracee is not currently ptrace-stopped. It is up to us to keep
    /// track of whether the tracee is stopped or not to be able to distinguish
    /// between these two errors (see `man 2 ptrace`).
    Search,
    /// An invalid memory access occurred when probing around in the tracee.
    /// The underlying errors are actually `libc::EFAULT` and `libc::EIO` - both
    /// of which are merged into this error (see `man 2 ptrace`).
    Fault,
    /// Occurs when we try to wait for a tracee to change state via [`wait`] but
    /// there are no valid children/tracees left for us to wait on.
    ///
    /// [`wait`]: fn.wait.html
    NoChild,
    /// Occurs when we try to wait for a _specific_ tracee to change state (via
    /// [`waitpid`]) but the specific tracee either no longer exists (and has
    /// been reaped) or is not a valid tracee/child of us.
    ///
    /// [`waitpid`]: fn.waitpid.html
    BadChild,
}

impl fmt::Display for TraceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Search => write!(f, "The tracee doesn't exist or isn't stopped."),
            Self::Fault => write!(f, "Invalid memory access in tracee."),
            Self::NoChild => write!(f, "No valid tracees are left to wait on."),
            Self::BadChild => write!(f, "The specific process is not a valid tracee."),
        }
    }
}

impl From<TraceError> for String {
    fn from(error: TraceError) -> String {
        error.to_string()
    }
}

impl From<TraceError> for SystemError {
    fn from(error: TraceError) -> SystemError {
        SystemError::from(error)
    }
}

/// Represents a wait status returned by the `wait(2)` or `waitpid(2)` syscalls.
#[derive(Debug, PartialEq)]
pub enum Status {
    Exited { exit_status: i32 },
    Killed { signal: i32 },
    /// `sender_id` is negative if a sender couldn't be identified.
    SignalStop { signal: i32, sender_id: i32 },
    Continued,
    ForkEvent { child_id: i32 },
    ExecEvent,
    CloneEvent,
    ExitEvent,
    SyscallEvent,
}

impl Status {
    /// Returns true if `Status` correspond to `libc::WIFSTOPPED(...) == true`.
    pub fn is_stopped(&self) -> bool {
        match self {
            Self::Exited { .. } => false,
            Self::Killed { .. } => false,
            Self::Continued => false,
            _ => true,
        }
    }
}

/// Represents the invocation of a system call.
pub struct Syscall {
    /// System call ID. These are architecture dependent.
    pub id: usize,
    /// No Linux system call has more than 6 arguments. We'll cast each argument
    /// to the system word size, which is sufficient to hold them.
    pub args: [usize; 6],
}

/// This is for errors that realistically should never happen. No point in
/// devoting heaps of code to handling errors that won't occur, so we'll just
/// throw our arms in the air and panic instead. Also these kinds of errors
/// are probably really hard to recover from anyway since they could leave us
/// in a really confusing state.
#[doc(hidden)]
fn ptrace_panic(mode: &str, pid: i32, errno: i32) -> ! {
    panic!("ptrace(PTRACE_{}, {}) = {} (errno={})", mode, pid, system::errno_str(errno), errno)
}

/// Returns true if the provided `clone` syscall is equivalent to a `fork`.
///
/// Modern libc implementations do not directly call the fork system call since
/// it is deprecated. Instead, the more modern and flexible `clone` system call
/// is called (which is also used to create new threads).
pub fn is_forklike_clone(syscall: &Syscall) -> bool {
    assert!(syscall.id == SYS_CLONE);
    // According to the Linux kernel source (kernel/fork.c), the `flags` argument
    // to clone (which is what we're interested in) *might* not be the first, so
    // hypothetically this may need to be changed if porting (probably not).
    (syscall.args[0] & 0xFF) == libc::SIGCHLD.try_into().unwrap()
}

/// Get the return value of the current syscall.
///
/// The result is only valid if the tracee is currently in a syscall-exit-stop.
///
/// # Errors
///
/// * [`Search`]
///
/// [`Search`]: enum.TraceError.html#variant.Search
pub fn get_syscall_ret(pid: i32) -> Result<usize, TraceError> {
    let val: i64;

    system::clear_errno();
    unsafe {
        val = libc::ptrace(libc::PTRACE_PEEKUSER, pid, 8 * libc::RAX, 0);
    }

    match system::errno() {
        libc::ESRCH => Err(TraceError::Search),
        0 => Ok(val as usize),
        _ => ptrace_panic("PEEKUSER", pid, system::errno()),
    }
}

/// Change which syscall the tracee is about to execute. 
///
/// Valid in a syscall-entry-stop only.
///
/// # Errors
///
/// * [`Search`]
///
/// [`Search`]: enum.TraceError.html#variant.Search
pub fn set_syscall(pid: i32, syscall_id: usize) -> Result<(), TraceError> {
    let addr = (8 * libc::ORIG_RAX) as *mut c_void;
    let data = (syscall_id as usize) as *const c_void;

    system::clear_errno();
    unsafe {
        libc::ptrace(libc::PTRACE_POKEUSER, pid, addr, data);
    }

    match system::errno() {
        libc::ESRCH => Err(TraceError::Search),
        0 => Ok(()),
        _ => ptrace_panic("POKEUSER", pid, system::errno()),
    }
}

/// Retrieve the id and arguments of the current syscall.
/// 
/// If the syscall has less than the maximum number of arguments, then the other
/// entries of the returned arguments will be equal to whatever values happened
/// to lie in the relevant registers of the tracee. This will only give a valid
/// answer when in a syscall-entry-stop.
///
/// # Errors
///
/// * [`Search`]
///
/// [`Search`]: enum.TraceError.html#variant.Search
pub fn which_syscall(pid: i32) -> Result<Syscall, TraceError> {
    let mut regs;

    system::clear_errno();
    unsafe {
        regs = MaybeUninit::<libc::user_regs_struct>::uninit().assume_init();
        let addr: *mut libc::user_regs_struct = &mut regs;
        libc::ptrace(libc::PTRACE_GETREGS, pid, 0, addr as *mut c_void);
    }

    // being pedantic with all these try_into casts to usize, but I'm assuming
    // they'll all compile down to no-ops on a 64-bit system anyway.
    match system::errno() {
        libc::ESRCH => Err(TraceError::Search),
        0 => Ok(Syscall {
            id: {
                println!("{} {}", regs.orig_rax, regs.orig_rax as i64);
                regs.orig_rax.try_into().unwrap()
            }, 
            args: [ 
                regs.rdi.try_into().unwrap(),
                regs.rsi.try_into().unwrap(),
                regs.rdx.try_into().unwrap(),
                regs.r10.try_into().unwrap(),
                regs.r8.try_into().unwrap(),
                regs.r9.try_into().unwrap(),
            ],
        }),
        _ => ptrace_panic("GETREGS", pid, system::errno()),
    }
}

/// Change an argument in the syscall that the tracee is about to execute.
/// 
/// Should only be called when in a syscall-entry-stop, otherwise you'll be
/// modifying some random register inside the tracee.
///
/// Will panic if the arguement index exceeds the range for the maximum number
/// of syscall arguments.
///
/// # Errors
///
/// * [`Search`]
///
/// [`Search`]: enum.TraceError.html#variant.Search
pub fn set_syscall_arg(pid: i32, val: usize, index: usize) -> Result<(), TraceError> {
    const ADDRS: [i32; 6] = [
        8 * libc::RDI,
        8 * libc::RSI,
        8 * libc::RDX,
        8 * libc::R10,
        8 * libc::R8,
        8 * libc::R9,
    ];
    let addr = ADDRS[index] as *mut c_void; // panics if index is out-of-range

    system::clear_errno();
    unsafe {
        // TODO casts not necessary for ptrace calls?
        libc::ptrace(libc::PTRACE_POKEUSER, pid, addr, val as *const c_void);
    }

    match system::errno() {
        libc::ESRCH => Err(TraceError::Search),
        0 => Ok(()),
        _ => ptrace_panic("POKEUSER", pid, system::errno()),
    }
}

/// Return the current stack base pointer in the tracee (i.e., the value of the
/// stack base register).
///
/// # Errors
///
/// * [`Search`]
///
/// [`Search`]: enum.TraceError.html#variant.Search
pub fn get_tracee_stack_base(pid: i32) -> Result<*mut u8, TraceError> {
    let reg_addr = (8 * libc::RBP) as *const c_void;
    let rbp;

    system::clear_errno();
    unsafe {
        rbp = libc::ptrace(libc::PTRACE_PEEKUSER, pid, reg_addr, 0) as *mut u8;
    }

    match system::errno() {
        libc::ESRCH => Err(TraceError::Search),
        0 => Ok(rbp),
        _ => ptrace_panic("PEEKUSER", pid, system::errno()),
    }
}

/// Figures out the PID of a newly forked child (created by `parent_id`). This
/// should only be called when the process is stopped due to `PTRACE_EVENT_FORK`.
/// This is a helper method for [`waitpid_internal`].
///
/// A tuple of `(parent_id, status)` is returned, where `parent_id` is equal to
/// the provided argument and `status` is a `Status::ForkEvent` that contains
/// the PID of the newly forked child.
///
/// # Errors
///
/// * [`Search`]
///
/// [`Status::ForkEvent`]: enum.Status.html#variant.ForkEvent
/// [`Search`]: enum.TraceError.html#variant.Search
/// [`waitpid_internal`]: fn.waitpid_internal.html
#[doc(hidden)]
fn diagnose_fork_event(parent_id: i32) -> Result<(i32, Status), i32> {
    unsafe {
        let mut child_id = MaybeUninit::<libc::c_ulong>::uninit().assume_init();
        if libc::ptrace(libc::PTRACE_GETEVENTMSG, parent_id, 0, &mut child_id) == -1 {
            return Err(system::errno());
        }
        Ok((parent_id, Status::ForkEvent { child_id: child_id.try_into().unwrap() }))
    }
}

/// Figures out the PID of the process that sent `signal` to `pid`. The process
/// must be in a `ptrace` signal stop. This is a helper for [`waitpid_internal`].
///
/// A tuple of `pid` and a [`Status::SignalStop`] is returned on success, or an 
/// `errno` value on failure.
///
/// [`Status::SignalStop`]: enum.Status.html#variant.SignalStop
/// [`waitpid_internal`]: fn.waitpid_internal.html
#[doc(hidden)]
fn diagnose_signal_stop(pid: i32, signal: i32) -> Result<(i32, Status), i32> {
    unsafe {
        let mut siginfo = MaybeUninit::<libc::siginfo_t>::uninit().assume_init();
        if libc::ptrace(libc::PTRACE_GETSIGINFO, pid, 0, &mut siginfo) == -1 {
            return Err(system::errno());
        }
        Ok((pid, Status::SignalStop { signal, sender_id: siginfo.si_pid() }))
    }
}

/// Directly calls `libc::waitpid` with the specifid pid. If the underlying wait
/// succeeded, a tuple of `(pid, status)` is returned, where `pid` is the PID
/// returned by the wait call, and `status` is the resulting wait status decoded
/// into a [`Status`] enum. On error, an `errno` value is returned. 
///
/// [`Status`]: enum.Status.html
#[doc(hidden)]
fn waitpid_internal(target_id: i32) -> Result<(i32, Status), i32> {
    unsafe {
        let mut status = MaybeUninit::<libc::c_int>::uninit().assume_init();
        let pid = libc::waitpid(target_id, &mut status, 0);
        if pid == -1 {
            return Err(system::errno());
        }
        if libc::WIFEXITED(status) {
            return Ok((pid, Status::Exited { exit_status: libc::WEXITSTATUS(status) }));
        }
        if libc::WIFSIGNALED(status) {
            return Ok((pid, Status::Killed { signal: libc::WTERMSIG(status) }));
        }
        if libc::WIFCONTINUED(status) {
            return Ok((pid, Status::Continued));
        }

        assert!(libc::WIFSTOPPED(status));
        
        if libc::WSTOPSIG(status) == libc::SIGTRAP | 0x80 {
            return Ok((pid, Status::SyscallEvent));
        }

        let is_event = |event| (status >> 8) == (libc::SIGTRAP | (event << 8));
    
        if is_event(libc::PTRACE_EVENT_FORK) { 
            return diagnose_fork_event(pid); 
        } else if is_event(libc::PTRACE_EVENT_EXEC) {
            return Ok((pid, Status::ExecEvent));
        } else if is_event(libc::PTRACE_EVENT_CLONE) {
            return Ok((pid, Status::CloneEvent));
        } else if is_event(libc::PTRACE_EVENT_EXIT) {
            return Ok((pid, Status::ExitEvent));
        }

        diagnose_signal_stop(pid, libc::WSTOPSIG(status))
    }
}

/// Waits for a single child or tracee to change state. 
/// 
/// This call will block until either the tracee changes state or some error
/// occurs. `pid` should be a valid PID for a *single* process.
///
/// Returns a [`Status`] enum describing the change-of-state that occurred for
/// the child process, this is a decoded version of the raw integer status that
/// `waitpid(2)` returns.
///
/// # Errors
///
/// * [`BadChild`]: The process specified by `pid` either does not exist or is
/// not a valid child or tracee of this process.
///
/// Any other errors from the underlying `libc::waitpid` call will cause this
/// function to panic (e.g. `libc::EINTR`). Ensure that such conditions cannot 
/// happen (e.g., in the case of `EINTR`, make sure `SA_RESTART` is set for any
/// signal handlers that could possibly run in the same thread as `waitpid`).
///
/// [`Status`]: enum.Status.html
/// [`BadChild`]: enum.TraceError.html#variant.BadChild
pub fn waitpid(pid: i32) -> Result<Status, TraceError> {
    assert!(pid > 0);
    match waitpid_internal(pid) {
        Ok((_, status)) => Ok(status),
        Err(libc::ESRCH) => Err(TraceError::Search),
        Err(libc::ECHILD) => Err(TraceError::BadChild),
        Err(e) => panic!("waitpid({}) = {} ({})", pid, system::errno_str(e), e),
    }
}

/// Waits for any one child or tracee to change state. 
///
/// The wait call will block until either a tracee changes state or some error
/// occurs.
///
/// Returns a [`Status`] enum describing the change-of-state that occurred for
/// the child process, this is a decoded version of the raw integer status that
/// `wait(2)` returns.
///
/// # Errors
///
/// * [`NoChild`]: This process has no children or tracees to wait for.
///
/// Any other errors from the underlying `libc::waitpid` call will cause this
/// function to panic (e.g. `libc::EINTR`). Ensure that such conditions cannot 
/// happen (e.g., in the case of `EINTR`, make sure `SA_RESTART` is set for any
/// signal handlers that could possibly run in the same thread as `wait`).
///
/// [`Status`]: enum.Status.html
/// [`NoChild`]: enum.TraceError.html#variant.NoChild
pub fn wait() -> Result<(i32, Status), TraceError> {
    match waitpid_internal(-1) {
        Ok((pid, status)) => Ok((pid, status)),
        Err(libc::ESRCH) => Err(TraceError::Search),
        Err(libc::ECHILD) => Err(TraceError::NoChild),
        Err(e) => panic!("wait() = {} ({})", system::errno_str(e), e),
    }
}

/// Helper function for [`setup_child`] to convert to null-terminated C strings.
/// This function doesn't care if the string contains embedded nulls.
///
/// [`setup_child`]: fn.setup_child.html
#[doc(hidden)]
fn string_to_cstring_vec(string: &str) -> Vec<c_char> {
    // convert the string into a vector of raw bytes
    let mut cstr = string
        .to_string()
        .into_bytes()
        .iter()
        .map(|&b| b as c_char)
        .collect::<Vec<_>>();

    // append the null terminator
    cstr.push(0);

    cstr
}

/// Helper function for [`setup_child`]. This is how the child communicates
/// errors back to the parent. We don't directly return the errno value since
/// it might exceed the valid range for exit statuses. The parent can then
/// decode the error with [`exit_status_to_errno`].
///
/// [`setup_child`]: fn.setup_child.html
/// [`exit_status_to_errno`]: fn.exit_status_to_errno.html
#[doc(hidden)]
fn errno_to_exit_status(errno: i32) -> i32 {
    match errno {
        libc::EBUSY => 1,
        libc::EFAULT => 2,
        libc::EINVAL => 3,
        libc::EIO => 4,
        libc::EPERM => 5,
        libc::ESRCH => 6,
        _ => 7,
    }
}

/// Helper function for [`start`] to exec the traced child process. This will
/// never return (it exits on failure and execs on success).
///
/// [`start`]: fn.start.html
#[doc(hidden)]
fn setup_child(path: &str, args: &[String]) -> ! {
    // don't want our children to inherit our blocked signals
    system::SigSet::all().unblock();

    unsafe {
        if libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) == -1 {
            process::exit(errno_to_exit_status(system::errno()));
        }
    
        // sync up with tracer
        libc::raise(libc::SIGSTOP);

        if libc::setpgid(0, 0) == -1 {
            process::exit(errno_to_exit_status(system::errno()));
        }

        // sync up with tracer
        libc::raise(libc::SIGSTOP);
    }

    // Convert the path and each argument to a null terminated cstring
    let path = string_to_cstring_vec(path);
    let c_args = args
        .iter()
        .map(|x| string_to_cstring_vec(x))
        .collect::<Vec<_>>();

    // Build the argv array containing the raw addresses to each argument
    let mut argv = c_args
        .iter()
        .map(|x| x.as_ptr())
        .collect::<Vec<_>>();

    // Add the null array terminator to the list of arguments
    argv.push(0 as *const c_char);

    unsafe {
        libc::execvp(path.as_ptr(), argv.as_ptr());
    }

    // If we're here, the exec failed. The tracer will learn of the cause
    // of failure via ptrace (it's tracing us as we speak!!).
    std::process::exit(1);
}

/// Helper function for [`wait_for_init_stop`]. Decodes the error status that
/// might be returned by the child process before it's able to exec (see the
/// [`setup_child`] and [`errno_to_exit_status`] functions).
///
/// [`wait_for_init_stop`]: fn.wait_for_init_stop.html
/// [`setup_child`]: fn.setup_child.html
/// [`errno_to_exit_status`]: fn.errno_to_exit_status.html
#[doc(hidden)]
fn exit_status_to_errno(status: i32) -> i32 {
    match status {
        1 => libc::EBUSY,
        2 => libc::EFAULT,
        3 => libc::EINVAL,
        4 => libc::EIO,
        5 => libc::EPERM,
        6 => libc::ESRCH,
        _ => 0,
    }
}

/// Helper function for [`start_tracee`]. Waits for the tracee to get stopped by
/// the SIGSTOP signal.
///
/// # Errors
///
/// * [`SystemError`]: If the tracee exited, then the exit status is converted
/// into a [`SystemError`] (with `descr` as the description). Otherwise a custom
/// [`SystemError`] is returned (e.g. the tracee was unexpectedly killed).
///
/// [`start_tracee`]: fn.start_tracee.html
/// [`SystemError`]: ../system/struct.SystemError.html
#[doc(hidden)]
fn wait_for_init_stop(pid: i32, descr: &str) -> Result<(), SystemError> {
    match waitpid(pid)? {
        Status::SignalStop { signal: libc::SIGSTOP, .. } => Ok(()),
        Status::Exited { exit_status } => {
            Err(SystemError::new(exit_status_to_errno(exit_status), descr))
        },
        Status::Killed { signal } => {
            Err(SystemError::from(format!("Tracee killed by unexpected signal {}", signal)))
        },
        Status::SignalStop { signal, .. } => {
            Err(SystemError::from(format!("Tracee stopped by unexpected signal {}", signal)))
        },
        _ => {
            Err(SystemError::from("Unexpected change of state from tracee"))
        }
    }
}

/// Kill the specified PID with `SIGKILL` and try to reap it. Ignores errors.
#[doc(hidden)]
fn kill_and_reap(pid: i32) {
    unsafe {
        libc::kill(pid, libc::SIGKILL);
    }
    // Just keep looping until process disappears (causing waitpid to fail)
    while let Ok(_) = waitpid(pid) { }
}

/// Starts a tracee using the specified program and arguments.
///
/// The child is started in a new process group, of which it is the leader.
/// This function also prevents the child from inheriting any of our blocked
/// signals (see [`SigSet`]). The child will be created using the following 
/// `ptrace(2)` options:
///
/// * `PTRACE_O_EXITKILL`: If we end, the tracee automatically gets SIGKILL'ed.
///
/// * `PTRACE_O_TRACEFORK`: Automatically continue tracing forked children.
/// This option also generates additional ptrace events (which are decoded for
/// you by [`wait`] and [`waitpid`] into [`Status::ForkEvent`]) and causes the
/// newly forked child to receive a `SIGSTOP` signal after the fork.
///
/// * `PTRACE_O_TRACEEXEC`: Automatically stops at the next successful exec
/// and generate an additional ptrace event if the exec succeeds (which will
/// be decoded by [`wait`] and [`waitpid`] into [`Status::ExecEvent`]). This
/// extra event will be generated before the syscall-exit-stop.
///
/// * `PTRACE_O_TRACECLONE`: Automatically trace cloned children. This option
/// also generates additional ptrace events (which are decoded by [`wait`] and
/// [`waitpid`] into [`Status::CloneEvent`]) and causes the newly cloned child
/// to receive a `SIGSTOP` signal after the clone. Since `PTRACE_O_TRACEFORK`
/// is also set, a [`Status::ForkEvent`] will actually be generated instead of
/// a [`Status::CloneEvent`] if [`is_forklike_clone`] is true.
/// 
/// * `PTRACE_O_TRACESYSGOOD`: Helps disambiguate syscalls from other events.
/// This option won't matter for you, since the events are decoded internally
/// into the [`Status`] enum by this module.
///
/// On success, the PID of the newly created child is returned.
///
/// # Errors
/// 
/// On failure, a [`SystemError`] is returned describing what happened. This
/// will not catch an `exec` failure - that is up to the tracer to check since
/// they'll be able to inspect the `exec` syscall that occurs if they want.
///
/// [`SigSet`]: ../system/struct.SigSet.html
/// [`wait`]: fn.wait.html
/// [`waitpid`]: fn.waitpid.html
/// [`Status::ForkEvent`]: enum.Status.html#variant.ForkEvent
/// [`Status::ExecEvent`]: enum.Status.html#variant.ExecEvent
/// [`Status::CloneEvent`]: enum.Status.html#variant.CloneEvent
/// [`is_forklike_clone`]: fn.is_forklike_clone.html
/// [`Status`]: enum.Status.html
/// [`SystemError`]: ../system/struct.SystemError.html
pub fn start_tracee(path: &str, args: &[String]) -> Result<i32, SystemError> {
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(SystemError::from_errno("fork"));
    }
    if pid == 0 {
        setup_child(path, args);
        // unreachable
    }

    // Ensure that ptrace(PTRACE_TRACEME, ...) succeeded, then continue the
    // tracee for the next step in the sequence.
    wait_for_init_stop(pid, "ptrace(PTRACE_TRACEME)")?;
    if unsafe { libc::ptrace(libc::PTRACE_CONT, pid, 0, 0) } == -1 {
        let errno = system::errno();
        kill_and_reap(pid);
        return Err(SystemError::new(errno, "ptrace(PTRACE_CONT)"));
    }

    // see man page for ptrace(2) for a description on each of these
    const PTRACE_OPTIONS: libc::c_int =
        libc::PTRACE_O_EXITKILL
        | libc::PTRACE_O_TRACESYSGOOD
        | libc::PTRACE_O_TRACEEXEC
        | libc::PTRACE_O_TRACEFORK
        | libc::PTRACE_O_TRACECLONE;

    let options = PTRACE_OPTIONS as usize;

    // Ensure that the setpgid call succeeded and then configure the options
    // that we need when tracing. We'll then leave the tracee stopped for the
    // caller to resume when they're ready.
    wait_for_init_stop(pid, "setpgid")?;
    if unsafe { libc::ptrace(libc::PTRACE_SETOPTIONS, pid, 0, options) } == -1 {
        let errno = system::errno();
        kill_and_reap(pid);
        return Err(SystemError::new(errno, "ptrace(PTRACE_SETOPTIONS)"));
    }

    Ok(pid)
}

/// Resumes the traced process until the next event occurs.
///
/// The tracee is resumed with `ptrace(PTRACE_SYSCALL, ...)`, which means that
/// the tracee will also be stopped at the entry or exit of a syscall.
///
/// The possible events are described by the [`Status`] enum. 
///
/// If `signal` is non-zero, then the specified signal will be delivered to the
/// process upon resumption.
///
/// # Errors
///
/// * [`Search`]
///
/// [`Search`]: enum.TraceError.html#variant.Search
/// [`Status`]: enum.Status.html
pub fn resume_tracee(pid: i32, signal: i32) -> Result<(), TraceError> {
    // Tell tracee to resume until it reaches a syscall-stop or other stop. If
    // we have a pending signal to deliver, we'll do that too.
    system::clear_errno();
    unsafe { 
        libc::ptrace(libc::PTRACE_SYSCALL, pid, 0, signal);
    }
    match system::errno() {
        0 => Ok(()),
        libc::ESRCH => Err(TraceError::Search),
        _ => ptrace_panic("SYSCALL", pid, system::errno()),
    }
}

/// Copy a raw sequence of bytes from the address `src` in the tracee's address
/// space to the slice `dest` in our address space. Copies `dest.len()` bytes.
///
/// # Errors
///
/// * [`Search`]
/// * [`Fault`]
///
/// [`Search`]: enum.TraceError.html#variant.Search
/// [`Fault`]: enum.TraceError.html#variant.Fault
#[doc(hidden)]
unsafe fn copy_from_tracee_raw(
    pid: i32,
    src: *const u8,
    dest: &mut [u8]
) -> Result<(), TraceError> {
    let local = libc::iovec { 
        iov_base: dest.as_ptr() as *mut c_void,
        iov_len: dest.len()
    };
    let remote = libc::iovec {
        iov_base: src as *mut c_void,
        iov_len: dest.len()
    };

    let nread = libc::process_vm_readv(pid, &local, 1, &remote, 1, 0);
    if nread == -1 {
        return match system::errno() {
            libc::ESRCH => Err(TraceError::Search), // TODO EPERM?
            e => panic!("Weird error from process_vm_readv: {}", system::errno_str(e)),
        }
    }
    // This shouldn't happen. If it fails with one block it should return -1.
    assert_eq!(nread as usize, dest.len(), "process_vm_readv is behaving weirdly");

    Ok(())
}

/// Copy a raw sequence of bytes from the slice `src` in our address space to
/// the address `dest` in the tracee's address space. Copies `src.len()` bytes.
///
/// # Errors
///
/// * [`Search`]
/// * [`Fault`]
///
/// [`Search`]: enum.TraceError.html#variant.Search
/// [`Fault`]: enum.TraceError.html#variant.Fault
#[doc(hidden)]
unsafe fn copy_to_tracee_raw(
    pid: i32, 
    src: &[u8],
    dest: *mut u8
) -> Result<(), TraceError> {
    let local = libc::iovec { 
        iov_base: src.as_ptr() as *mut c_void,
        iov_len: src.len()
    };
    let remote = libc::iovec { 
        iov_base: dest as *mut c_void,
        iov_len: src.len()
    };

    let nwrite = libc::process_vm_writev(pid, &local, 1, &remote, 1, 0);
    if nwrite < 0 {
        return match system::errno() {
            libc::ESRCH => Err(TraceError::Search), // TODO EPERM?
            e => panic!("Weird error from process_vm_writev: {}", system::errno_str(e)),
        }
    }
    // This shouldn't happen. If it fails with one block it should return -1.
    assert_eq!(nwrite as usize, src.len(), "process_vm_writev is behaving weirdly");

    Ok(())
}

/// Zero out a segment of memory in the tracee's address space at the address
/// given by `dest` and for a size of `len`.
///
/// # Errors
///
/// * [`Search`]
/// * [`Fault`]
///
/// [`Search`]: enum.TraceError.html#variant.Search
/// [`Fault`]: enum.TraceError.html#variant.Fault
pub fn zero_tracee(pid: i32, dest: *mut u8, len: usize) -> Result<(), TraceError> {
    // Apart from directly using PTRACE_POKEDATA calls, I'm not sure of any way
    // to write directly to the tracee (as opposed to copying). Since this is
    // actually a copy operation, we need a bunch of zeros in our memory space
    // to copy from, so we'll just create some fixed sized array of zeros to use
    // and if we need more then that we'll just do multiple copies. This array
    // won't add to the executable size, since the system will set up the region
    // of zeros for us when the program is loaded.
    const NUM_ZEROS: usize = 4096;
    const ZEROS: [u8; NUM_ZEROS] = [0; NUM_ZEROS];

    let num_blocks = len / NUM_ZEROS;
    let remainder = len % NUM_ZEROS;

    for _i in 0..num_blocks {
        unsafe {
            copy_to_tracee_raw(pid, &ZEROS[..], dest)?;
        }
    }

    if remainder > 0 {
        unsafe {
            copy_to_tracee_raw(pid, &ZEROS[..remainder], dest)?;
        }
    }

    Ok(())
}

/// Copy an object T from the address `src` in the tracee's memory space into
/// our own memory space, and return it in a box.
///
/// This function is unsafe since it is not a safe operation to construct 
/// arbitrary objects from arbitrary patterns of bytes, since invariants of 
/// those objects may be violated. If you're using this to copy an object for
/// which any sequence of bytes is valid, then you can safely use this.
///
/// # Errors
///
/// * [`Search`]
/// * [`Fault`]
///
/// [`Search`]: enum.TraceError.html#variant.Search
/// [`Fault`]: enum.TraceError.html#variant.Fault
pub unsafe fn copy_from_tracee<T>(pid: i32, src: *const T) -> Result<Box<T>, TraceError> {
    let mut result = Box::new(MaybeUninit::<T>::uninit().assume_init());
    let src = src as *const u8;
    let dest_ptr = &mut (*result) as *mut T as *mut u8;
    let dest_len = mem::size_of::<T>();
    copy_from_tracee_raw(pid, src, slice::from_raw_parts_mut(dest_ptr, dest_len))?;
    Ok(result)
}

/// Copy an object from our address space to `dest` in tracee's address space.
///
/// # Errors
///
/// * [`Search`]
/// * [`Fault`]
///
/// [`Search`]: enum.TraceError.html#variant.Search
/// [`Fault`]: enum.TraceError.html#variant.Fault
pub fn copy_to_tracee<T>(pid: i32, object: &T, dest: *mut T) -> Result<(), TraceError> {
    unsafe {
        let src_ptr = object as *const T as *const u8;
        let src_len = mem::size_of::<T>();
        let dest = dest as *mut u8;
        copy_to_tracee_raw(pid, slice::from_raw_parts(src_ptr, src_len), dest)?;
    }
    Ok(())
}

/// Rounds `num` up to the nearest multiple of `multiple_of`.
#[doc(hidden)]
fn round_up_to_multiple(num: usize, multiple_of: usize) -> usize {
    (num + multiple_of - 1) / multiple_of * multiple_of
}

/// Takes an input byte span starting at the address `start` and with a length
/// of `len` bytes, and returns a new size for the span so that it does not
/// cross a page boundary. If the span doesn't cross a page boundary, then the
/// returned size will be equal to `len`.
#[doc(hidden)]
fn limit_span_length_to_page_boundary(start: *const u8, len: usize) -> usize {
    let page_size = *PAGE_SIZE;
    // Limit the span length to the block size so that the next steps work
    let len = min(len, page_size);
    // Calculate the index of the page that self.cur_addr lies in
    let page_index = (start as usize) / page_size;
    // Calculate the first address after the end of that page
    let page_end = (page_index + 1) * page_size;
    // Calculate the first address after the end of the span (as a usize)
    let span_end = (start as usize) + len;

    min(page_end, span_end) - (start as usize)
}

/// Returns true if the byte-representation of `obj` consists of only zeros.
#[doc(hidden)]
fn is_object_all_zeros<T>(obj: &T) -> bool {
    let ptr = obj as *const T as *const u8;
    for i in 0..mem::size_of::<T>() {
        if unsafe { ptr.add(i).read() } != 0 {
            return false;
        }
    }
    true
}

/// This method does all the work of [`copy_nulled_array_from_tracee`] (which is
/// a wrapper around this method). The reason this method is separate is so that
/// the entire method doesn't have to be unsafe (the wrapper method is declared
/// unsafe not because Rust forces us, but to force callers to be explicit - see
/// the documentation comments for [`copy_nulled_array_from_tracee`]).
///
/// Don't use this function directly, use [`copy_nulled_array_from_tracee`].
///
/// # Errors
///
/// * [`Search`]
/// * [`Fault`]
///
/// [`Search`]: enum.TraceError.html#variant.Search
/// [`Fault`]: enum.TraceError.html#variant.Fault
/// [`copy_nulled_array_from_tracee`]: fn.copy_nulled_array_from_tracee.html
#[doc(hidden)]
pub fn copy_nulled_array_from_tracee_internal<T>(
    pid: i32,
    src: *const T,
    max_count: Option<usize>
) -> Result<(Vec<T>, bool), TraceError> {
    // Too big => unecessary copying, too small => too much context-switching.
    const BLOCK_SIZE: usize = 1024;

    let max_count = if let Some(c) = max_count { c } else { usize::max_value() };
    let mut cur_addr = src as *const u8;
    let mut num_bytes_read = 0;
    let mut items: Vec<T> = Vec::new();

    loop {
        let copy_size_in_bytes = limit_span_length_to_page_boundary(cur_addr, BLOCK_SIZE);
        let new_vec_size_in_bytes = num_bytes_read + copy_size_in_bytes;
        let new_vec_size = round_up_to_multiple(new_vec_size_in_bytes, mem::size_of::<T>());
        unsafe {
            items.resize_with(new_vec_size, || MaybeUninit::uninit().assume_init());

            // Get a byte slice representing the vector
            let vec_as_bytes: &mut [u8] = slice::from_raw_parts_mut(
                items.as_ptr() as *mut u8,
                items.len() * mem::size_of::<T>()
            );

            // Copy into the vector
            let start = num_bytes_read;
            let end = start + copy_size_in_bytes;
            copy_from_tracee_raw(pid, cur_addr, &mut vec_as_bytes[start..end])?;
        }

        let null_search_start = num_bytes_read / mem::size_of::<T>();
        let null_search_end = null_search_start + (copy_size_in_bytes / mem::size_of::<T>());
        num_bytes_read += copy_size_in_bytes;
        
        for i in null_search_start..null_search_end {
            let hit_null = is_object_all_zeros(&items[i]);
            if hit_null || i >= max_count {
                items.truncate(i);
                items.shrink_to_fit();
                return Ok((items, hit_null));
            }
        }
        
        cur_addr = unsafe { cur_addr.add(copy_size_in_bytes) };
    }
}

/// Copy an array of objects of some type from the tracee's memory space into
/// our own address space. The array is assumed to be terminated by `NULL`.
/// In this case, `NULL` is taken to mean a sequence of `mem::size_of::<T>()`
/// bytes, which are all zero.
///
/// The `NULL` object is not included in the returned array.
///
/// If `max_count` is not `None`, then the function will stop reading after that
/// many objects. A tuple of the resulting array and a boolean is returned on
/// success, where the boolean is `true` if the `max_count` wasn't exceeded.
///
/// This function is marked unsafe just like [`copy_from_tracee`] since it is
/// not a safe operation to form arbitrary objects out of arbitrary patterns 
/// of bytes. This is fine to use if you're okay with that.
///
/// # Errors
///
/// * [`Search`]
/// * [`Fault`]
///
/// [`Search`]: enum.TraceError.html#variant.Search
/// [`Fault`]: enum.TraceError.html#variant.Fault
/// [`copy_from_tracee`]: fn.copy_from_tracee.html
pub unsafe fn copy_nulled_array_from_tracee<T>(
    pid: i32,
    src: *const T,
    max_count: Option<usize>
) -> Result<(Vec<T>, bool), TraceError> {
    copy_nulled_array_from_tracee_internal(pid, src, max_count)
}

/// Copies a null-terminated C string starting at the address `src` from the
/// tracee's address space into our own.
///
/// If `max_count` is not `None`, then the function will stop reading after
/// `max_count` characters.
///
/// On success, a tuple of the resulting `CString` is returned, and a boolean
/// that is `true` if the terminating byte was reached before `max_count`.
///
/// # Errors
///
/// * [`Search`]
/// * [`Fault`]
///
/// [`Search`]: enum.TraceError.html#variant.Search
/// [`Fault`]: enum.TraceError.html#variant.Fault
pub fn copy_cstring_from_tracee(
    pid: i32,
    src: *const u8,
    max_count: Option<usize>
) -> Result<(CString, bool), TraceError> {
    match unsafe { copy_nulled_array_from_tracee(pid, src, max_count) } {
        Ok((bytes, hit_null)) => Ok((CString::new(bytes).unwrap(), hit_null)),
        Err(e) => Err(e),
    }
}

/*/// Retrives the program path for the specified process.
///
/// If an error occurs, a [`SystemError`] is returned describing
/// the cause of the error. This realistically shouldn't happen
/// if the `pid` refers to a valid (even a zombie) process.
pub fn get_program_path(pid: i32) -> Result<CString, SystemError> {
    const PATH_MAX: usize = libc::PATH_MAX as usize;

    let mut buf: [u8; PATH_MAX] = unsafe { MaybeUninit::uninit().assume_init() };
    let buf_ptr = buf.as_mut_ptr() as *mut c_char;

    let procfs_path = format!("/proc/{}/exe\0", pid).into_bytes();
    let path_ptr = procfs_path.as_ptr() as *const c_char;

    let count = unsafe { libc::readlink(path_ptr, buf_ptr, PATH_MAX) };
    if count == -1 {
        Err(SystemError::from_errno("readlink"))
    } else {
        let count = count as usize;
        Ok(CString::new(&buf[0..count]).unwrap())
    }
}

/// Retrieves the command line for the specified process.
///
/// If an error occurs, a [`SystemError`] is returned describing
/// the cause of the error. This realistically shouldn't happen
/// if the `pid` refers to a valid (even a zombie) process.
pub fn get_command_line(pid: i32) -> Result<Vec<CString>, SystemError> {
    let mut contents = fs::read(format!("/proc/{}/cmdline", pid))?;
    let num_nulls = contents.iter().filter(|&&b| b == 0).count();
    let mut args = Vec::<CString>::with_capacity(num_nulls);

    let mut start = 0;
    for i in 0..contents.len() {
        if contents[i] == 0 {
            args.push(CString::new(&contents[start..i]).unwrap());
            start = i + 1;
        }
    }
    
    Ok(args)
}*/
