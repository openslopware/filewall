# Rust + Unix-socket (UnixListener/UnixStream) Rules

**A long-lived daemon must re-accept, not hold one connection forever**
If you `listener.accept()` once and keep that `UnixStream` for the process
lifetime, the daemon breaks permanently when the peer dies: writes hit
`BrokenPipe`, and a restarted client's connection sits unaccepted in the listen
backlog forever. Restarting the daemon is then the only recovery. Re-accept when
the link dies. For a single-threaded event loop that must stay responsive, use a
non-blocking accept (`listener.set_nonblocking(true)` → `accept()` →
restore blocking) returning `Ok(None)` on `WouldBlock`, rather than blocking the
whole loop on a fresh `accept()`.

**Distinguish a dead peer from a read timeout by ErrorKind**
A `set_read_timeout` expiry surfaces as `ErrorKind::WouldBlock` on Unix (keep the
link, deny/retry once). A dead peer is `BrokenPipe` (write) or `UnexpectedEof`
(read), plus `ConnectionReset`/`ConnectionAborted`/`NotConnected` — these mean
drop the link and reconnect:

```rust
fn is_disconnect(e: &io::Error) -> bool {
    matches!(e.kind(), BrokenPipe | UnexpectedEof | ConnectionReset
        | ConnectionAborted | NotConnected)
}
```

**On Linux an accepted socket does NOT inherit the listener's O_NONBLOCK**
So after a non-blocking `accept()` the returned stream is blocking; a subsequent
`set_read_timeout` works normally.
