# Rust + libc Rules

**Installing a signal handler: cast through a fn pointer, not straight to sighandler_t**
`libc::signal(SIGHUP, on_sighup as libc::sighandler_t)` warns "direct cast of a
function item into an integer". Cast through an explicit fn-pointer type first:

```rust
extern "C" fn on_sighup(_: libc::c_int) { RELOAD.store(true, Ordering::SeqCst) }

let handler = on_sighup as extern "C" fn(libc::c_int);
unsafe { libc::signal(libc::SIGHUP, handler as libc::sighandler_t) };
```

Keep handlers trivial (set an `AtomicBool`); do real work in the main loop, which sees
the interrupted blocking syscall return `EINTR` (check `e.raw_os_error() == Some(libc::EINTR)`).

**Liveness probe `kill(pid, 0)`: EPERM means ALIVE, not dead**
When an unprivileged process probes a root-owned daemon (filewallctl → filewalld),
`kill(pid, 0)` returns `EPERM` — the process exists but you may not signal it. Only
`ESRCH` means "no such process". Treating every `Err` as "stale pid" misreports a
healthy root daemon as down. Classify: `Ok | Err(EPERM)` → running, `Err(ESRCH)` →
stale, anything else → unknown. (`nix::Errno`, match on the variant.)
