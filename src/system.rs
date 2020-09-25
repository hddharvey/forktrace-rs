//! General routines for Unix-y system stuff.
// Don't know how portable my arrays are. I would use libc::strerror for the
// errno values but strerror isn't thread-safe and strerror_r is weird. Don't
// worry, I didn't type these full arrays out. Used a cheeky Python script.
use libc;
use std::io;
use std::fmt;
use std::mem::MaybeUninit;

/// Some weird Linux-specific error for when `fork` is interrupted.
///
/// This is returned by fork when interrupted by a signal but is only visible
/// to tracers, and is otherwise not visible to userspace.
pub const ERESTARTNOINTR: i32 = 513;

/// An internal error code of Linux for when a syscall is interrupted.
///
/// This is visible to tracers. It indicates that a syscall returned due to the
///  delivery of a signal and needs to be restarted. `fork` won't return this
/// (see [`ERESTARTNOINTR`]), but other calls that block (such as `wait4` and
/// `waitid`) will return this.
///
/// [`ERESTARTNOINTR`]: constant.ERESTARTNOINTR.html
pub const ERESTARTSYS: i32 = 512;

/// Represents a set of signals that we can perform actions on.
pub struct SigSet {
    sigset: libc::sigset_t,
}

/// Represents an error from a libc function with an associated errno value
/// or optionally just an error message with no associated error value.
pub struct SystemError {
    errno: i32,
    // If errno != 0, then this should describe what function produced the 
    // error (e.g. a function name). Otherwise, it's just a message.
    message: String,
}

#[doc(hidden)]
const NUM_SIGNALS: usize = 32;
#[doc(hidden)]
const SIGNALS: [&str; NUM_SIGNALS] = [
    "None",
    "SIGHUP",
    "SIGINT",
    "SIGQUIT",
    "SIGILL",
    "SIGTRAP",
    "SIGABRT",
    "SIGBUS",
    "SIGFPE",
    "SIGKILL",
    "SIGUSR1",
    "SIGSEGV",
    "SIGUSR2",
    "SIGPIPE",
    "SIGALRM",
    "SIGTERM",
    "SIGSTKFLT",
    "SIGCHLD",
    "SIGCONT",
    "SIGSTOP",
    "SIGTSTP",
    "SIGTTIN",
    "SIGTTOU",
    "SIGURG",
    "SIGXCPU",
    "SIGXFSZ",
    "SIGVTALRM",
    "SIGPROF",
    "SIGWINCH",
    "SIGIO",
    "SIGPWR",
    "SIGSYS",
];

#[doc(hidden)]
const NUM_ERRORS: usize = 134;
#[doc(hidden)]
const ERRORS: [&str; NUM_ERRORS] = [
    "Success",
    "Operation not permitted",
    "No such file or directory",
    "No such process",
    "Interrupted system call",
    "Input/output error",
    "No such device or address",
    "Argument list too long",
    "Exec format error",
    "Bad file descriptor",
    "No child processes",
    "Resource temporarily unavailable",
    "Cannot allocate memory",
    "Permission denied",
    "Bad address",
    "Block device required",
    "Device or resource busy",
    "File exists",
    "Invalid cross-device link",
    "No such device",
    "Not a directory",
    "Is a directory",
    "Invalid argument",
    "Too many open files in system",
    "Too many open files",
    "Inappropriate ioctl for device",
    "Text file busy",
    "File too large",
    "No space left on device",
    "Illegal seek",
    "Read-only file system",
    "Too many links",
    "Broken pipe",
    "Numerical argument out of domain",
    "Numerical result out of range",
    "Resource deadlock avoided",
    "File name too long",
    "No locks available",
    "Function not implemented",
    "Directory not empty",
    "Too many levels of symbolic links",
    "??????",
    "No message of desired type",
    "Identifier removed",
    "Channel number out of range",
    "Level 2 not synchronised",
    "Level 3 halted",
    "Level 3 reset",
    "Link number out of range",
    "Protocol driver not attached",
    "No CSI structure available",
    "Level 2 halted",
    "Invalid exchange",
    "Invalid request descriptor",
    "Exchange full",
    "No anode",
    "Invalid request code",
    "Invalid slot",
    "??????",
    "Bad font file format",
    "Device not a stream",
    "No data available",
    "Timer expired",
    "Out of streams resources",
    "Machine is not on the network",
    "Package not installed",
    "Object is remote",
    "Link has been severed",
    "Advertise error",
    "Srmount error",
    "Communication error on send",
    "Protocol error",
    "Multihop attempted",
    "RFS specific error",
    "Bad message",
    "Value too large for defined data type",
    "Name not unique on network",
    "File descriptor in bad state",
    "Remote address changed",
    "Can not access a needed shared library",
    "Accessing a corrupted shared library",
    ".lib section in a.out corrupted",
    "Attempting to link in too many shared libraries",
    "Cannot exec a shared library directly",
    "Invalid or incomplete multibyte or wide character",
    "Interrupted system call should be restarted",
    "Streams pipe error",
    "Too many users",
    "Socket operation on non-socket",
    "Destination address required",
    "Message too long",
    "Protocol wrong type for socket",
    "Protocol not available",
    "Protocol not supported",
    "Socket type not supported",
    "Operation not supported",
    "Protocol family not supported",
    "Address family not supported by protocol",
    "Address already in use",
    "Cannot assign requested address",
    "Network is down",
    "Network is unreachable",
    "Network dropped connection on reset",
    "Software caused connection abort",
    "Connection reset by peer",
    "No buffer space available",
    "Transport endpoint is already connected",
    "Transport endpoint is not connected",
    "Cannot send after transport endpoint shutdown",
    "Too many references: cannot splice",
    "Connection timed out",
    "Connection refused",
    "Host is down",
    "No route to host",
    "Operation already in progress",
    "Operation now in progress",
    "Stale file handle",
    "Structure needs cleaning",
    "Not a XENIX named type file",
    "No XENIX semaphores available",
    "Is a named type file",
    "Remote I/O error",
    "Disk quota exceeded",
    "No medium found",
    "Wrong medium type",
    "Operation cancelled",
    "Required key not available",
    "Key has expired",
    "Key has been revoked",
    "Key was rejected by service",
    "Owner died",
    "State not recoverable",
    "Operation not possible due to RF-kill",
    "Memory page has hardware error",
];

/// Returns the process ID (actually the thread group ID) of the calling thread.
pub fn getpid() -> i32 {
    unsafe {
        libc::getpid()
    }
}

/// Returns a string describing the value of C's errno variable.
pub fn errno_str(error: i32) -> String {
    if error < 0 || error as usize >= NUM_ERRORS {
        return "??????".to_string();
    }
    ERRORS[error as usize].to_string()
}

/// Returns a string describing a POSIX signal or "?????" if unknown.
pub fn signal_str(signal: i32) -> String {
    if signal < 0 || signal as usize >= NUM_SIGNALS {
        return "??????".to_string();
    }
    SIGNALS[signal as usize].to_string()
}

/// Resets the value of libc's errno variable to 0 for this thread.
pub fn clear_errno() {
    unsafe {
        let errno = libc::__errno_location() as *mut libc::c_int;
        errno.write(0);
    }
}

/// Retrieves the value of libc's errno variable for this thread.
pub fn errno() -> i32 {
    unsafe {
        let errno = libc::__errno_location() as *mut libc::c_int;
        errno.read() as i32
    }
}

impl SigSet {
    /// Create a sigset that contains no signals.
    pub fn empty() -> Self {
        unsafe {
            let mut set = MaybeUninit::<libc::sigset_t>::uninit().assume_init();
            libc::sigemptyset(&mut set);
            SigSet { sigset: set }
        }
    }

    /// Create a sigset that contains all the signals.
    pub fn all() -> Self {
        unsafe {
            let mut set = MaybeUninit::<libc::sigset_t>::uninit().assume_init();
            libc::sigfillset(&mut set);
            SigSet { sigset: set }
        }
    }
    
    /// Add a signal to the set. Panics if signal isn't a valid signal number.
    pub fn add(&mut self, signal: i32) -> &mut Self {
        unsafe {
            if libc::sigaddset(&mut self.sigset, signal) == -1 {
                panic!("sigaddset failed: {} ({})", errno_str(errno()), errno());
            }
        }
        self
    }

    /// Changes the calling thread's signal mask to block the signals in this set.
    pub fn block(&self) {
        unsafe {
            let oldset = 0 as *mut libc::sigset_t;
            if libc::pthread_sigmask(libc::SIG_BLOCK, &self.sigset, oldset) == -1 {
                panic!("pthread_sigmask(SIG_BLOCK) failed: {} ({})", 
                    errno_str(errno()), errno());
            }
        }
    }

    /// Changes the calling thread's signal mask to unblock the signals in this set.
    pub fn unblock(&self) {
        unsafe {
            let oldset = 0 as *mut libc::sigset_t;
            if libc::pthread_sigmask(libc::SIG_UNBLOCK, &self.sigset, oldset) == -1 {
                panic!("pthread_sigmask(SIG_UNBLOCK) failed: {} ({})", 
                    errno_str(errno()), errno());
            }
        }
    }
}

impl SystemError {
    /// Create a SystemError using the provided errno value and origin description.
    pub fn new(errno: i32, cause: &str) -> Self {
        SystemError { errno, message: cause.to_string() }
    }

    /// Create a SystemError using the current value of errno.
    pub fn from_errno(cause: &str) -> Self {
        SystemError { errno: errno(), message: cause.to_string() }
    }

    pub fn from<T: Into<String>>(msg: T) -> Self {
        SystemError { errno: 0, message: msg.into() }
    }
}

impl From<io::Error> for SystemError {
    fn from(error: io::Error) -> Self {
        if let Some(errno) = error.raw_os_error() {
            SystemError { errno, message: format!("{:?}", error.kind()) }
        } else {
            SystemError { errno: 0, message: format!("{:?}", error.kind()) }
        }
    }
}

impl fmt::Display for SystemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.errno == 0 {
            write!(f, "{}", self.message)
        } else {
            write!(f, "{}: {} (errno={})", self.message, errno_str(self.errno), self.errno)
        }
    }
}

impl fmt::Debug for SystemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_string())
    }
}
