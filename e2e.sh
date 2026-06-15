#!/bin/bash
# End-to-end test for the filewall MVP.
#
# Run as your NORMAL user (NOT via sudo) from a session with a display:
#     ./e2e.sh
# or in the Claude session:
#     ! /home/pulsar/slowdata/development/priv/filewall/e2e.sh
#
# It starts filewall-ui as you (so yad reaches your session) and filewalld as
# root (via the zenity askpass helper for the sudo password), then exercises:
#   1. an ALLOWED binary  (head)  -> reads with NO prompt
#   2. an UNLISTED binary (cat)   -> pops the filewall prompt; you click Allow/Deny
# Prereqs: yad (filewall-ui dialog) and zenity (sudo askpass helper).
set -u
cd "$(dirname "$0")"
ROOT="$(pwd)"
export SUDO_ASKPASS="$ROOT/phase0/askpass.sh"

WATCH="$HOME/.filewall-e2e"
KEY="$WATCH/secret.key"
CFG="/tmp/filewall-e2e.toml"
RULES="/tmp/filewall-e2e-rules.toml"
SOCK="/run/filewall/prompt.sock"
DLOG="/tmp/filewalld.e2e.log"
ULOG="/tmp/filewall-ui.e2e.log"

cleanup() {
  echo "--- cleanup ---"
  [ -n "${UI:-}" ] && kill "$UI" 2>/dev/null
  sudo -A pkill -f 'target/release/filewalld' 2>/dev/null
  rm -f "$CFG"
  sudo -A rm -f "$RULES" 2>/dev/null
  rm -rf "$WATCH" 2>/dev/null   # also clears files/subdirs the directory-mark cases create
}
trap cleanup EXIT

mkdir -p "$WATCH"
head -c 64 /dev/urandom > "$KEY"
sudo -A rm -f "$RULES" 2>/dev/null   # start from a clean learned-rules file

cat > "$CFG" <<EOF
default_action = "prompt"
prompt_timeout_seconds = 30
socket_path = "$SOCK"
rules_path = "$RULES"

[[watch]]
path = "$WATCH"
allow = ["/usr/bin/head"]
learn_object = "file"
exclude = ["**/*.tmp"]
EOF

echo "=== building release ==="
cargo build --release 2>&1 | tail -1

echo "=== starting filewall-ui (as $USER) ==="
./target/release/filewall-ui "$SOCK" >"$ULOG" 2>&1 &
UI=$!

echo "=== starting filewalld (as root; askpass will prompt for your password) ==="
# Scope debug logging to our crate so per-access ALLOW lines (incl. "ALLOW
# (excluded)") show in the log for the assertions below, without globset/regex chatter.
sudo -A RUST_LOG=filewalld=debug ./target/release/filewalld "$CFG" >"$DLOG" 2>&1 &

echo "=== waiting for daemon to mark files and enter event loop ==="
for i in $(seq 1 30); do
  if grep -q "entering event loop" "$DLOG" 2>/dev/null; then break; fi
  sleep 1
done
if ! grep -q "entering event loop" "$DLOG"; then
  echo "!! daemon did not become ready; log:"; cat "$DLOG"; exit 1
fi
echo "daemon ready."

echo
echo "=== CASE 1: ALLOWED binary (head) — expect NO prompt, success ==="
if head -c 16 "$KEY" >/dev/null 2>&1; then
  echo "RESULT: head SUCCEEDED (allowlisted, no prompt) ✓"
else
  echo "RESULT: head FAILED (unexpected) ✗"
fi

echo
echo "=== CASE 2: UNLISTED binary (cat) — a filewall prompt should appear NOW ==="
echo "          (click Allow once or Deny once)"
if cat "$KEY" >/dev/null 2>&1; then
  echo "RESULT: cat was ALLOWED (you clicked Allow) ✓"
else
  echo "RESULT: cat was DENIED  (you clicked Deny / timeout) — EPERM ✓"
fi

echo
echo "=== CASE 3: LEARNED RULE (persistence loop) — manual verification ==="
echo "          This proves the daily-driver feature. Follow along:"
echo
echo "  a) A prompt should appear for 'cat' below. Click [Always allow]."
if cat "$KEY" >/dev/null 2>&1; then
  echo "     -> cat ALLOWED."
else
  echo "     -> cat DENIED (did you click Always deny?)."
fi
echo
echo "  b) The decision should now be persisted. Inspect it:"
echo "       sudo ./target/release/filewallctl list \"$RULES\""
sudo -A ./target/release/filewallctl list "$RULES" 2>/dev/null || \
  echo "     (run the command above yourself if this needs a password)"
echo
echo "  c) A SECOND 'cat' should now read with NO prompt (rule fires):"
if cat "$KEY" >/dev/null 2>&1; then
  echo "     -> cat ALLOWED with no prompt ✓ (learned rule worked)"
else
  echo "     -> cat DENIED ✗ (unexpected if you clicked Always allow)"
fi
echo
echo "  d) Revoke the rule and reload the daemon, then it prompts again:"
echo "       sudo ./target/release/filewallctl remove 0 \"$RULES\""
echo "     (remove auto-sends SIGHUP; the daemon re-reads $RULES)"

# ---------------------------------------------------------------------------
# Directory-marking cases (FAN_EVENT_ON_CHILD). The watch on $WATCH is a
# directory watch, so the daemon marks the *directory* (not each file) and the
# kernel fires for every child. These prove the four behaviors per-file marking
# could not: new files, new subdirs, atomic rename, and event-time excludes.
#
# Each `cat` of a non-excluded, non-learned file pops a prompt — click Deny (or
# let it time out). What we assert afterwards is only that an *event fired* (the
# daemon logged the access), which per-file marking would have missed.
# ---------------------------------------------------------------------------
echo
echo "=== CASE 4: NEW FILE created after startup — expect a prompt for 'cat' ==="
NEWF="$WATCH/new-after-start.txt"
echo "created-after-daemon-started" > "$NEWF"
cat "$NEWF" >/dev/null 2>&1 && echo "  cat allowed" || echo "  cat denied/timed out"

echo
echo "=== CASE 5: NEW SUBDIR + file — expect a prompt (live subdir marking) ==="
SUB="$WATCH/sub-after-start"
mkdir -p "$SUB"
SUBF="$SUB/in-subdir.txt"
echo "inside-a-brand-new-subdir" > "$SUBF"
sleep 1   # let treewatch process IN_CREATE and mark the new subdir
# NOTE: the very FIRST open in a just-created subdir may slip (the IN_CREATE
# race, documented in docs/fanotify-notes.md); this post-mark open is the one
# we assert on.
cat "$SUBF" >/dev/null 2>&1 && echo "  cat allowed" || echo "  cat denied/timed out"

echo
echo "=== CASE 6: ATOMIC RENAME (temp + mv) — expect a prompt (mark didn't orphan) ==="
DATF="$WATCH/rotated.dat"
echo "v1" > "$DATF"
echo "v2" > "$WATCH/.rotated.new"
mv -f "$WATCH/.rotated.new" "$DATF"   # atomic replace: new inode under the marked dir
cat "$DATF" >/dev/null 2>&1 && echo "  cat allowed" || echo "  cat denied/timed out"

echo
echo "=== CASE 7: EXCLUDED file (*.tmp) — expect NO prompt, cat SUCCEEDS ==="
TMPF="$WATCH/scratch.tmp"
echo "noise" > "$TMPF"
if cat "$TMPF" >/dev/null 2>&1; then
  echo "  cat SUCCEEDED with no prompt ✓ (event auto-allowed as excluded)"
else
  echo "  cat FAILED ✗ (excluded file should never be denied)"
fi

echo
echo "=== ASSERTIONS (from daemon log) ==="
fail=0
assert_logged() { # <substr> <description>
  if grep -qF "$1" "$DLOG"; then echo "  PASS: $2"; else echo "  FAIL: $2 (no '$1' in $DLOG)"; fail=1; fi
}
# Directory marking: log reports dirs, not a per-file count.
assert_logged "dir(s) (children covered)" "watch marked directories (not per-file)"
# Events fired for the new file / new-subdir file / atomically-renamed file.
assert_logged "new-after-start.txt" "CASE 4: event fired for newly-created file"
assert_logged "in-subdir.txt"       "CASE 5: event fired for file in new subdir"
assert_logged "marked new dir"       "CASE 5: treewatch live-marked the new subdir"
assert_logged "rotated.dat"          "CASE 6: event fired after atomic rename"
# Excluded file was auto-allowed in the event loop (no prompt).
assert_logged "ALLOW (excluded)"     "CASE 7: excluded file auto-allowed (event-loop re-check)"
[ "$fail" -eq 0 ] && echo "  ALL ASSERTIONS PASSED ✓" || echo "  SOME ASSERTIONS FAILED ✗"

echo
echo "=== daemon log ==="
cat "$DLOG"
echo "=== DONE ==="
