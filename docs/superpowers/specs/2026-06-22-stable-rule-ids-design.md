# Stable rule IDs for `filewallctl`

## Problem

`filewallctl list` shows each learned rule with a leading `IDX` column that is
just the rule's position in the `Vec<LearnedRule>` (`enumerate()` in
`list_table`). `remove <index>` calls `Vec::remove`, which shifts every later
element down by one — so any index captured from a `list` is invalidated by the
first removal. Scripts that want to "list obsolete rules, then delete a set"
must re-query after every single removal. We want identifiers that stay valid
across removals so `list` output is usable for automation.

## Goal

Give every learned rule a **stable, never-reused identifier**, surface it in
`list` (table + json/yaml), and let `remove` take a batch of those ids in one
call.

## Decisions (settled during brainstorming)

1. **Stored monotonic counter id**, not a content-hash or UUID. A persisted
   `next_id` allocator assigns each rule a `u64` at creation. Identical-content
   rules stay distinct (the daemon does not dedupe on learn — `rules.push` at
   `main.rs:425` blindly appends), and ids survive ordering changes.
2. **Batch removal by id**: `remove <id> [id...]` removes every matched rule in
   one pass, with a single disk write and a single SIGHUP. The positional index
   meaning is dropped.
3. **Strict missing-id**: `remove` removes whatever ids matched, but exits
   non-zero if *any* requested id was absent — so automation notices a stale id.
   The matched removals are still persisted.
4. **`list` shows `ID`, not `IDX`**: the positional column is replaced by the
   stable id. Two number columns would be confusing and the position no longer
   means anything to `remove`.
5. **`remove` drops its optional trailing `[rules_path]`**: all positional args
   are now ids. (`list` keeps its optional path arg.)

## Data model — `filewall-rules`

Two new fields, both `#[serde(default)]` so existing `rules.toml` files load
unchanged.

```rust
pub struct LearnedRule {
    pub id: u64,            // NEW. 0 = unassigned sentinel; real ids start at 1.
    pub created_unix: u64,
    pub action: RuleAction,
    pub exe: String,
    pub object: PathBuf,
    pub object_kind: ObjectKind,
    pub cwd: Option<String>,
}

pub struct Rules {
    pub next_id: u64,       // NEW, MUST be the first field (see TOML note).
    pub rules: Vec<LearnedRule>,
}
```

### TOML field-order constraint

`next_id` **must be declared before `rules`** in the `Rules` struct. The `toml`
crate serializes struct fields in declaration order, and TOML forbids a bare key
(`next_id = N`) appearing after an array-of-tables (`[[rule]]`). Declaring
`next_id` last would emit invalid TOML that fails to re-parse. A save/load
roundtrip test guards this. (To be captured as a project rule afterward.)

### ID allocation (owned by the store)

```rust
fn alloc_id(&mut self) -> u64 {
    let id = self.next_id.max(1);   // ids start at 1; 0 stays the sentinel
    self.next_id = id + 1;
    id
}

pub fn push(&mut self, mut rule: LearnedRule) {
    rule.id = self.alloc_id();
    self.rules.push(rule);
}
```

`policy.rs::learned_rule` leaves `id: 0`; `Rules::push` stamps the real id.
The daemon's existing `rules.push(rule)` call needs no change.

### Backfill / migration — in `Rules::load`

Deterministic and idempotent; runs on every load:

```rust
let max_id = self.rules.iter().map(|r| r.id).max().unwrap_or(0);
self.next_id = self.next_id.max(max_id + 1);
for r in &mut self.rules {
    if r.id == 0 {
        r.id = self.next_id;
        self.next_id += 1;
    }
}
```

Assignment follows the stable `Vec` order (TOML array order), so an unprivileged
`filewallctl list` — which cannot write the root-owned `rules.toml` — and the
root daemon compute **identical** ids from the same file content. The first
writer (the daemon on its next learn, or a `remove`) persists them durably.
`next_id` only ever climbs, so an id is never reused even after removing the
highest-id rule and learning a new one.

## `filewallctl` changes

- Replace `remove_at(index)` with:
  ```rust
  fn remove_ids(rules: &mut Rules, ids: &[u64])
      -> (Vec<LearnedRule>, Vec<u64>) // (removed, missing)
  ```
- `cmd_remove`: parse all positional args as `u64`; on any parse failure, print a
  usage error. Remove every matched rule. If at least one was removed,
  `save_atomic` **once** and `send_sighup` **once**; if nothing matched, skip both
  (no needless write or daemon reload). Report removed ids and missing ids. Exit
  `FAILURE` if `missing` is non-empty (any matched removals still persisted), else
  `SUCCESS`.
- `Ack` reporting (json/yaml) carries the removed and missing id lists; the table
  path prints a line per removed rule plus a warning line for any missing ids.
- `list_table`: header `ID  ACTION  EXE  OBJECT  KIND  CWD  CREATED` (the `IDX`
  column becomes `ID`, sourced from `rule.id`). Drop the `enumerate()` index.
- `id` appears in `--json`/`--yaml` automatically (serde field on
  `LearnedRule`), enabling `filewallctl list --json | jq '.[].id'`.
- usage string: `remove <id> [id...]   Remove rules by id, then SIGHUP`.

## Error handling

- Corrupt/missing `rules.toml` still yields an empty set (existing behavior).
- A `remove` with all-missing ids removes nothing, skips the disk write and the
  SIGHUP entirely, and exits non-zero.
- Disk write failure on `remove` reports the error and exits non-zero (existing
  behavior preserved).

## Testing (TDD)

`filewall-rules`:
- backfill assigns sequential ids to id-0 rules, in `Vec` order;
- backfill preserves rules that already have ids and sets `next_id` above the max;
- `push` allocates `next_id` and bumps it;
- no id reuse: remove the highest-id rule, push a new one, assert new id > removed;
- save/load roundtrip preserves ids and `next_id` (also guards TOML field order).

`filewallctl`:
- `remove_ids` returns the matched rules and the missing ids correctly;
- `list_table` renders an `ID` column sourced from `rule.id`.

## Out of scope

- Deduping identical-content rules on learn.
- Editing rules in place (rules remain create/remove only).
- A `--rules <path>` flag for `remove` (default path only after this change).
