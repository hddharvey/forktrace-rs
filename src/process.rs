//! Data structures that represent a process tree and the events within it.
use std::io::Write;
use log::{debug, info};
use crate::system;
use slab::Slab;

/// A key into the process tree.
#[derive(Clone, Copy)]
pub struct ProcessKey {
    key: usize, // just a wrapper around usize for readability
}

/// Describes the location of a line of source code in a tracee program.
pub struct SourceLoc {
    file: String,
    func: String,
    line: u32,
}

/// Describes when a process is created via `fork` or a `fork`-like `clone`.
pub struct ForkEvent {
    pub child: ProcessKey,
}

/// Describes a wait call that did not result in a reap.
///
/// This applies to wait calls that have failed or to non-blocking calls (with
/// `WNOHANG`) that returned 0 since there were no children available at that
/// moment. 'Failed' includes wait calls that were interrupted by a signal and
/// are scheduled to be restarted (`error` would be [`system::ERESTARTSYS`]).
///
/// [`system::ERESTARTSYS`]: ../system/constant.ERESTARTSYS.html
#[derive(Clone)]
pub struct WaitEvent {
    /// The `errno` value returned by the `wait` call.
    pub error: i32,
    /// Same meaning as the `pid` argument to `waitpid(2)`.
    pub waited_id: i32,
    /// This is true if the wait call had `WNOHANG` in its flags.
    pub nohang: bool,
}

/// Describes when a parent has successfully `wait`ed on a child process.
pub struct ReapEvent {
    pub child: ProcessKey,
    /// Same meaning as the `pid` argument to `waitpid(2)`.
    pub waited_id: i32,
    /// This is true if the wait call had `WNOHANG` in its flags.
    pub nohang: bool,
}

/// Describes when one process sends a signal to (an)other process(s).
///
/// This event doesn't actually describe that a signal has been _received_, but
/// only that it has been sent. What we'll do is add this event to the source
/// and destination processes when a signal is sent. Later on, the destination
/// is likely to get a [`SignalEvent`] added to it once the signal is delivered.
///
/// [`SignalEvent`]: struct.SignalEvent.html
pub struct KillEvent {
    /// Has the same meaning as the `pid` argument of `kill(2)`.
    pub target_id: i32,
    pub source: ProcessKey,
    /// This will be None if the target was not a single process or if it was a
    /// single process but that process couldn't be found in the process tree.
    pub dest: Option<ProcessKey>,
    pub signal: i32,
    /// Indicates whether a specific thread was targetted or the whole process.
    pub to_thread: bool,
    pub sender: bool,
}

/// Describes when a process received a signal of some sort.
pub struct SignalEvent {
    /// The pid of the process who sent the signal, or `-1` if we don't know.
    pub sender_id: i32,
    /// The value of `WTERMSIG`/`WSTOPSIG` (the signal that the process received).
    pub signal: i32,
    /// Did this signal kill the process?
    pub killed: bool,
}

/// Describes when a process has exited via the `exit` syscall (which includes
/// returning from the `main` function).
pub struct ExitEvent {
    /// The exit status passed to the exit system call.
    pub exit_status: i32,
}

/// Describes a successful `exec` call.
pub struct ExecEvent {
    /// The path to the program that was exec'ed.
    pub path: String,
    /// The argv array for the exec'ed progarm (including `argv[0]`).
    pub args: Vec<String>,
    /// The error status of exec. If this equals `0`, the exec succeeded.
    pub error: i32,
}

pub enum EventKind {
    Fork(Box<ForkEvent>),
    Wait(Box<WaitEvent>),
    Reap(Box<ReapEvent>),
    Kill(Box<KillEvent>),
    Signal(Box<SignalEvent>),
    Exit(Box<ExitEvent>),
    Exec(Box<ExecEvent>),
}

/// Describes an event for a single thread of a process
pub struct Event {
    pub kind: EventKind,
    /// The source location where this occurred, if relevant.
    pub location: Option<Box<SourceLoc>>,
}

/// Describes a thread or process within the process tree.
///
/// Wait a minute, threads too? Yes. On Linux, threads are actually processes
/// and processes are actually thread groups or groups of processes that share
/// memory, file descriptors, etc.
pub struct Process {
    pid: i32,
    /// This should be true if the process's parent and any eligible subreapers
    /// within this process tree have all died.
    orphaned: bool,
    events: Vec<Event>,
    /// This is the path to the program that the process was running when it
    /// was created. Note that this is before the process will have had any
    /// chance to do an `exec()` call.
    initial_path: String,
    /// Same as `initial_path` but for the argv array rather than program path.
    initial_args: Vec<String>,
}

/// An object that manages the entire process tree.
///
/// This can have multiple 'leaders' in it, each of which are a process that (as
/// far as the Tree is concerned) have no ancestors.
pub struct Tree {
    processes: Slab<Process>,
    leaders: Vec<ProcessKey>,
}

impl Event {
    fn new(kind: EventKind, location: Option<SourceLoc>) -> Event {
        match location {
            None => Event { kind, location: None },
            Some(l) => Event { kind, location: Some(Box::new(l)) },
        }
    }
}

impl Process {
    /// Creates a new process that starts with the specified command line. The 
    /// process's command line could later change if `ExecEvent`s are added.
    #[doc(hidden)]
    fn new(pid: i32, path: &str, args: &[String]) -> Self {
        Process {
            pid,
            orphaned: false,
            initial_path: path.to_string(),
            initial_args: Vec::from(args),
            events: Vec::new(),
        }
    }

    /// Retrieve the PID of this process.
    pub fn pid(&self) -> i32 {
        self.pid
    }

    /// Determine if this process has been orphaned or not.
    pub fn orphaned(&self) -> bool {
        self.orphaned
    }

    /// Returns the event that lead to our demise, or `None` if we're not dead.
    pub fn death(&self) -> Option<&Event> {
        if let Some(event) = self.events.last() {
            match &event.kind {
                EventKind::Exit(_) => return Some(event),
                EventKind::Signal(e) => return if e.killed { Some(event) } else { None },
                _ => return None,
            }
        }
        None
    }

    /// Returns the number of events that this process has.
    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    /// Retrieves a immutable reference to an event owned by this process.
    pub fn event(&self, event_index: usize) -> &Event {
        &self.events[event_index]
    }

    /// Retrieves an immutable iterator to the list of this process's events.
    pub fn events(&self) -> std::slice::Iter<Event> {
        self.events.iter()
    }

    /// Figures out the command line that process had at the event index.
    ///
    /// If the event at `event_index` is an exec, then the returned command line
    /// is the command line prior to the exec. If `event_index` is none, then
    /// the most recent command line is returned instead.
    ///
    /// Returns a tuple of the path and arguments.
    pub fn command_line_at(&self, event_index: Option<usize>) -> (String, Vec<String>) {
        if self.events.is_empty() {
            return (self.initial_path.clone(), self.initial_args.clone());
        }

        let start = if let Some(i) = event_index { i } else { self.events.len() };

        for event in self.events[..start].iter().rev() {
            if let EventKind::Exec(e) = &event.kind {
                if e.error == 0 {
                    return (e.path.clone(), e.args.clone()); // this was a successful exec
                }
            }
        }

        (self.initial_path.clone(), self.initial_args.clone())
    }
}

impl Tree {
    /// Create a new process tree.
    ///
    /// All processes in this tree can only refer to other processes within this
    /// tree. The tree is also allowed to have multiple leaders.
    pub fn new() -> Self {
        Tree { processes: Slab::new(), leaders: Vec::new() }
    }

    /// Add a new leader to the process tree.

    /// Retrieve a reference to a process in the tree. Panics if the key is bad.
    pub fn get(&self, key: ProcessKey) -> &Process {
        self.processes.get(key.key).unwrap()
    }

    /// Retrieve a mutable reference to a process. Panics if the key is bad.
    pub fn get_mut(&mut self, key: ProcessKey) -> &mut Process {
        self.processes.get_mut(key.key).unwrap()
    }

    /// Create a new leader process in the tree and return a key to it.
    ///
    /// `path` and `args` are the command line that the leader currently has.
    pub fn add_leader(&mut self, pid: i32, path: &str, args: &[String]) -> ProcessKey {
        let key = ProcessKey { key: self.processes.insert(Process::new(pid, path, args)) };
        self.leaders.push(key);
        key
    }

    /// Helper method to add an event (makes things a little less verbose).
    ///
    /// Returns an index into the process's event list of the new event.
    #[doc(hidden)]
    fn add_event(
        &mut self, 
        proc: ProcessKey, 
        kind: EventKind, 
        at: Option<SourceLoc>
    ) -> usize {
        let process = self.get_mut(proc);
        process.events.push(Event::new(kind, at));
        process.events.len() - 1
    }

    /// Notify the process tree that a `wait` call by a process has failed.
    ///
    /// See [`WaitEvent`] for a description of when this can happen.
    ///
    /// `waited_id` has the same meaing as the `pid` argument to `waitpid(2)`
    /// and `nohang` specifies whether the wait was initiated with `WNOHANG`.
    ///
    /// The index of the newly created event for `proc` is returned.
    ///
    /// [`WaitEvent`]: struct.WaitEvent.html
    pub fn notify_failed_wait(
        &mut self,
        proc: ProcessKey,
        error: i32, 
        waited_id: i32, 
        nohang: bool,
        at: Option<SourceLoc>
    ) -> usize {
        let e = WaitEvent { error, waited_id, nohang };
        self.add_event(proc, EventKind::Wait(Box::new(e)), at)
    }

    /// Notify the process tree that one process has reaped another.
    ///
    /// `waited_id` has the same meaing as the `pid` argument to `waitpid(2)`
    /// and `nohang` specifies whether the wait was initiated with `WNOHANG`.
    ///
    /// The index of the newly created event for `parent` is returned.
    pub fn notify_reaped(
        &mut self,
        parent: ProcessKey,
        child: ProcessKey, 
        waited_id: i32, 
        nohang: bool,
        at: Option<SourceLoc>
    ) -> usize {
        let e = ReapEvent { child, waited_id, nohang };
        self.add_event(parent, EventKind::Reap(Box::new(e)), at)
    }

    /// Notify the process tree that a process has `fork`ed a new child.
    ///
    /// Returns a key to the newly created child Process and the index of the
    /// newly created event for `parent`.
    pub fn notify_forked(
        &mut self,
        parent: ProcessKey,
        child_id: i32,
        at: Option<SourceLoc>
    ) -> (ProcessKey, usize) {
        let (path, args) = self.get(parent).command_line_at(None);
        // The child will start off with the same command line as its parent
        let child_key = self.processes.insert(Process::new(child_id, &path, &args));
        let child_key = ProcessKey { key: child_key };
        let e = ForkEvent { child: child_key };
        (child_key, self.add_event(parent, EventKind::Fork(Box::new(e)), at))
    }

    /// Notify the process tree that a process has attempted to exec.
    ///
    /// If `error` is zero, then the `exec` succeeded. If `error` is non-zero,
    /// it is the `errno` value returned by `exec`.
    ///
    /// The index of the newly created event for `proc` is returned.
    pub fn notify_execed(
        &mut self,
        proc: ProcessKey,
        path: String, 
        args: Vec<String>, 
        error: i32,
        at: Option<SourceLoc>
    ) -> usize {
        let e = ExecEvent { path, args, error };
        self.add_event(proc, EventKind::Exec(Box::new(e)), at)
    }

    /// Notify the process tree that a process exited.
    ///
    /// The index of the newly created event for `proc` is returned.
    pub fn notify_exited(
        &mut self,
        proc: ProcessKey, 
        exit_status: i32, 
        at: Option<SourceLoc>
    ) -> usize {
        let e = ExitEvent { exit_status };
        self.add_event(proc, EventKind::Exit(Box::new(e)), at)
    }

    /// Notify the process tree that a process was killed by a signal.
    ///
    /// If the most recent event was a non-fatal [`SignalEvent`] for the same
    /// signal, then that event is promoted to a killing signal instead of a
    /// new event being created.
    ///
    /// The index of the relevant event for `proc` is returned. This is either
    /// the newly added event (if no promotion occurred), or the old event that
    /// was promoted to a killing event.
    ///
    /// # Notes
    ///
    /// It's possible to conceive of scenarios where this 'merging' behaviour
    /// results in unintended behaviour:
    ///
    /// 1. A signal handler for, say `SIGINT`, is installed by a process.
    /// 2. The process receives `SIGINT` and the handler is run.
    /// 3. [`notify_signaled`] is called to register the signal delivery.
    /// 4. The process uninstalls the handler for `SIGINT`.
    /// 5. The process receives `SIGINT`, which now kills the process.
    /// 6. `notify_killed` is called to register the killing event.
    ///
    /// In this scenario, the merging behaviour of this function would cause
    /// the process to end up with a single (fatal) `SignalEvent` when there
    /// should actually be two `SignalEvent`s: a non-fatal one, followed by a
    /// fatal one.
    ///
    /// You can avoid this by ensuring that you always call [`notify_signaled`]
    /// beforehand so that we always merge with the correct event. This is not
    /// necessary for `SIGKILL` since it can only ever be delivered once.
    ///
    /// When tracing with `ptrace`, the above behaviour should come naturally,
    /// since the tracee is always notified of the delivery of signals first,
    /// before receiving the notification that the tracee was killed (except
    /// for `SIGKILL`, but as mentioned before, this doesn't matter).
    ///
    /// [`SignalEvent`]: struct.SignalEvent.html
    /// [`notify_signaled`]: #method.notify_signaled
    pub fn notify_killed(
        &mut self,
        proc: ProcessKey, 
        signal: i32, 
        at: Option<SourceLoc>
    ) -> usize {
        if let Some(event) = self.get_mut(proc).events.last_mut() {
            if let EventKind::Signal(e) = &mut event.kind {
                if e.signal == signal {
                    e.killed = true; // promote to a killing signal
                    // reborrow the process as immutable to keep rust happy...
                    let process = self.get(proc);
                    let event = process.events.last().unwrap();
                    info!("{} {}", process.pid, event.describe(self));
                    return process.events.len() - 1;
                }
            }
        }
        let e = SignalEvent { sender_id: -1, signal, killed: true };
        self.add_event(proc, EventKind::Signal(Box::new(e)), at)
    }

    /// Notify the process tree that a process received a signal.
    ///
    /// The signal may or may not be fatal. If the signal turns out to be
    /// fatal, then you follow this with a call to [`notify_killed`] and
    /// this signal will be promoted to a killing event.
    ///
    /// If the signal has an unknown sender, then specify `sender_id` as `-1`.
    ///
    /// The index of the newly added event for `proc` is returned.
    ///
    /// [`notify_killed`]: #method.notify_killed
    pub fn notify_signaled(
        &mut self, 
        proc: ProcessKey,
        sender_id: i32, 
        signal: i32, 
        at: Option<SourceLoc>
    ) -> usize {
        let e = SignalEvent { sender_id, signal, killed: false };
        self.add_event(proc, EventKind::Signal(Box::new(e)), at)
    }

    /// Notify the process tree that a process has sent a signal.
    ///
    /// `target_id` has the same meaning as the `pid` argument of `kill(2)`.
    /// The target could be a single process, a process group, or all processes.
    ///
    /// `to_thread` specifies whether a specific thread was targetted or the
    /// entire process. Signals are handled and blocked on a per-thread basis,
    /// but if a signal is fatal, then the entire process will be killed.
    ///
    /// `dest` can be left as `None` if the target either was not a single
    /// process, or the target couldn't be found within this process tree.
    ///
    /// `at` (if not `None`) should be the location where the source process
    /// sent the signal, not a location in the destination process.
    ///
    /// The index of the newly added event for `source` is returned.
    pub fn notify_signal_send(
        &mut self,
        source: ProcessKey, 
        dest: Option<ProcessKey>,
        target_id: i32, 
        signal: i32,
        to_thread: bool,
        at: Option<SourceLoc>
    ) -> usize {
        // Add the event to the receiving process if one was provided
        if let Some(dest) = dest {
            let e = KillEvent { 
                target_id, 
                signal, 
                to_thread, 
                source,
                dest: Some(dest), 
                sender: false
            };
            // Specify the location as None since that is intended for us
            self.add_event(dest, EventKind::Kill(Box::new(e)), None);
        }
        
        // Add the event to the sending process
        let e = KillEvent { 
            target_id, 
            signal, 
            to_thread, 
            source,
            dest, 
            sender: true 
        };
        self.add_event(source, EventKind::Kill(Box::new(e)), at)
    }

    /// Notifies the process tree that a process has no eligible parents
    /// or subreapers (within this process tree) left to reap it.
    pub fn notify_orphaned(&mut self, proc: ProcessKey) {
        self.get_mut(proc).orphaned = true;
    }

    /// A helper method for [`print_tree`] to print a tree indented by some
    /// amount. `forked` should be true of `process` was forked by another.
    ///
    /// [`print_tree`]: #method.print_tree
    #[doc(hidden)]
    fn print_indented_tree(
        &self,
        writer: &mut dyn Write, 
        indent: i32,
        process: &Process, 
        forked: bool
    ) {
        fn print_indent(writer: &mut dyn Write, indent: i32) {
            for i in 1..=indent { write!(writer, "    ").unwrap(); }
        }

        let (path, args) = process.command_line_at(None);
        let descr = if forked { "forked" } else { "leader" };
        print_indent(writer, indent);
        writeln!(writer, "{} process {} {} [ {} ]",
            descr, process.pid, path, args.join(" ")).unwrap();

        for event in &process.events {
            if let EventKind::Fork(e) = &event.kind {
                self.print_indented_tree(writer, indent + 1, self.get(e.child), true);
            } else {
                print_indent(writer, indent);
                writeln!(writer, "{}", event.describe(self)).unwrap();
            }
        }
    }

    /// Prints the entire process tree out to `writer` in an indented format.
    ///
    /// The output isn't very pretty, but this is useful for debugging.
    pub fn print_tree(&self, writer: &mut dyn Write) {
        for &leader in &self.leaders {
            self.print_indented_tree(writer, 0, self.get(leader), false);
        }
    }

    /// Returns a string describing the specified process.
    pub fn describe_process(&self, proc: ProcessKey) -> String {
        let process = self.get(proc);
        let (path, args) = process.command_line_at(None);
        format!("{} {} [ {} ]", process.pid, path, args.join(" "))
    }

    /// Returns a string describing a process's event.
    ///
    /// This will panic if `event_index` exceeds the process's [`event_count()`].
    ///
    /// [`event_count()`]: struct.Process.html#method.event_count
    pub fn describe_event(&self, proc: ProcessKey, event_index: usize) -> String {
        self.get(proc).events[event_index].describe(self)
    }
}

#[doc(hidden)]
fn get_wait_target_string(waited_id: i32) -> String {
    if waited_id == -1 {
        "any child".to_string()
    } else if waited_id > 0 {
        waited_id.to_string()
    } else if waited_id == 0 {
        "their group".to_string()
    } else {
        (-waited_id).to_string()
    }
}

// TODO implement Display instead
impl ToString for SourceLoc {
    fn to_string(&self) -> String {
        format!("{}:{}:{}", self.file, self.func, self.line)
    }
}

impl ForkEvent {
    fn describe(&self, tree: &Tree) -> String {
        format!("forked {}", tree.get(self.child).pid)
    }
}

impl WaitEvent {
    fn describe(&self, _tree: &Tree) -> String {
        let target = get_wait_target_string(self.waited_id);
        if self.error == 0 {
            if self.nohang {
                format!("waited for {} (WNOHANG) {{returned 0}}", target)
            } else {
                format!("started waiting for {}", target)
            }
        } else {
            let err = system::errno_str(self.error);
            if self.nohang {
                format!("waited for {} (WNOHANG) {{failed: {}}}", target, err)
            } else {
                format!("waited for {} {{failed: {}}}", target, err)
            }
        }
    }
}

impl ReapEvent {
    fn describe(&self, tree: &Tree) -> String {
        let target = get_wait_target_string(self.waited_id);
        let child = tree.get(self.child);
        if self.nohang {
            format!("reaped {} {{waited for {} (WNOHANG)}}", child.pid, target)
        } else {
            format!("reaped {} {{waited for {}}}", child.pid, target)
        }
    }
}

impl KillEvent {
    fn describe(&self, _tree: &Tree) -> String {
        let target;
        let id_string;
        if self.target_id == -1 {
            target = "all processes";
        } else if self.target_id == 0 {
            target = "their group";
        } else {
            id_string = self.target_id.to_string();
            target = &id_string;
        }

        let kind = if self.to_thread { "thread" } else { "process" };
        let name = system::signal_str(self.signal);

        if self.sender {
            format!("sent {} ({}) to {} {{as a {}}}", name, self.signal, target, kind)
        } else {
            format!("sent {} ({}) from {} {{as a {}}}", name, self.signal, target, kind)
        }
    }
}

impl SignalEvent {
    fn describe(&self, _tree: &Tree) -> String {
        let origin;
        let id_string;
        if self.sender_id <= 0 {
            origin = "???";
        } else if self.sender_id == system::getpid() {
            origin = "tracer";
        } else {
            id_string = self.sender_id.to_string();
            origin = &id_string;
        }

        let action = if self.killed { "killed by" } else { "received" };
        let name = system::signal_str(self.signal);

        format!("{} {} ({}) {{origin: {}}}", action, name, self.signal, origin)
    }
}

impl ExitEvent {
    fn describe(&self, _tree: &Tree) -> String {
        format!("exited {}", self.exit_status)
    }
}

impl ExecEvent {
    fn describe(&self, _tree: &Tree) -> String {
        if self.error == 0 {
            format!("execed {} [ {} ]", self.path, self.args.join(" "))
        } else {
            format!("failed to exec {}: {}", self.path, system::errno_str(self.error))
        }
    }
}

impl EventKind {
    fn describe(&self, tree: &Tree) -> String {
        // TODO is there a better way?
        match self {
            Self::Fork(e) => e.describe(tree),
            Self::Wait(e) => e.describe(tree),
            Self::Reap(e) => e.describe(tree),
            Self::Kill(e) => e.describe(tree),
            Self::Signal(e) => e.describe(tree),
            Self::Exit(e) => e.describe(tree),
            Self::Exec(e) => e.describe(tree),
        }
    }
}

impl Event {
    fn describe(&self, tree: &Tree) -> String {
        if let Some(loc) = &self.location {
            format!("{} @ {}", self.kind.describe(tree), loc.to_string())
        } else {
            self.kind.describe(tree)
        }
    }
}
