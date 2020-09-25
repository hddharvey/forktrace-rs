mod process;
mod system;
mod ptrace;
mod syscalls;
mod util;

use std::env;
use log::{info, warn, error};
use std::mem;
use process::{Event, Tree, ProcessKey, ForkEvent, WaitEvent, Process};
use ptrace::TraceError;
use system::SystemError;
use std::collections::HashMap;

struct Logger;
static LOGGER: Logger = Logger;

impl log::Log for Logger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            println!("{}: {}", record.level(), record.args());
        }
    }

    fn flush(&self) { }
}

fn handle_syscall(pid: i32) -> Result<usize, TraceError> {
    // syscall-entry-stop
    let syscall = ptrace::which_syscall(pid)?;
    let name = syscalls::get(syscall.id).unwrap().name;
    println!("{} syscall {}", pid, name);

    if syscall.id == ptrace::SYS_EXECVE {
        let path = syscall.args[0] as *const u8;
        let args = syscall.args[1] as *const *const u8;

        let (path_str, _) = ptrace::copy_cstring_from_tracee(pid, path, None)?;
        let (arg_ptrs, _) = unsafe { ptrace::copy_nulled_array_from_tracee(pid, args, None)? };

        let mut args: Vec<String> = Vec::with_capacity(arg_ptrs.len());
        for arg_ptr in arg_ptrs {
            let (arg_str, _) = ptrace::copy_cstring_from_tracee(pid, arg_ptr, None)?;
            args.push(util::escaped_string(&arg_str));
        }

        println!("{} execed {} with args {:?}", pid, util::escaped_string(&path_str), args);
    }

    Ok(syscall.id)
}

// bit of a mess... just hacked something together for testing purposes
fn main() -> Result<(), SystemError> {
    log::set_logger(&LOGGER).unwrap();
    log::set_max_level(log::LevelFilter::Info);

    let args: Vec<String> = env::args().collect();

    let mut tree = Tree::new();

    println!("Starting command; {:?}", &args[1..]);

    let leader_id = ptrace::start_tracee(&args[1], &args[1..])?;
    let leader = tree.add_leader(leader_id, &args[1], &args[1..]);
    println!("leader {}", tree.describe_process(leader));

    println!("Created tracee. PID = {}", leader_id);

    struct Tracee {
        signal: i32,
        stopped: bool,
        syscall: Option<usize>,
        proc: ProcessKey,
    };
    let mut tracees = HashMap::<i32, Tracee>::new();
    tracees.insert(leader_id, Tracee { signal: 0, stopped: true, syscall: None, proc: leader });
    ptrace::resume_tracee(leader_id, 0)?;

    while !tracees.is_empty() {
        let (pid, status) = ptrace::wait()?;
        let stopped = match status {
            ptrace::Status::SyscallEvent => { 
                let tracee = tracees.get_mut(&pid).unwrap();
                if let Some(s) = tracee.syscall {
                    let name = syscalls::get(s).unwrap().name;
                    println!("{} exited syscall {}", pid, name);
                    tracee.syscall = None;
                } else {
                    tracee.syscall = Some(handle_syscall(pid)?);
                }
                true 
            },
            ptrace::Status::Continued => { println!("{} {:?}", pid, status); false },
            ptrace::Status::ForkEvent { child_id } => {
                let (key, event) = tree.notify_forked(tracees[&pid].proc, child_id, None);
                tracees.insert(child_id, Tracee { signal: 0, stopped: true, syscall: None, proc: key });
                println!("adding new tracee {}...", child_id);
                ptrace::resume_tracee(child_id, 0)?;
                println!("{} {:?}", pid, status);
                true // the parent is stopped
            },
            ptrace::Status::SignalStop { signal, .. } => {
                tracees.get_mut(&pid).unwrap().signal = if signal == 19 { 0 } else { signal };
                println!("{} {:?}", pid, status);
                true
            },
            _ => { println!("{} {:?}", pid, status); true },
        };
        if !stopped {
            continue;
        }
        if let Err(e) = ptrace::resume_tracee(pid, tracees[&pid].signal) {
            println!("resume_tracee gave error: {:?}, removing {}...", e, pid);
            tracees.remove(&pid);
        } else {
            tracees.get_mut(&pid).unwrap().signal = 0;
        }
    }
    tree.print_tree(&mut std::io::stdout());

    Ok(())
}
