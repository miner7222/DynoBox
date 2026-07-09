# Power Menu DBP Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a bundled `.dbp` patch that makes a long press of the power key show Global Actions instead of launching Lenovo LeVoice.

**Architecture:** Patch `PhoneWindowManager.getResolvedLongPressOnPowerBehavior()I` to return behavior `1` (`LONG_PRESS_POWER_GLOBAL_ACTIONS`) inside `system/framework/services.jar`. A dedicated `method_const_int` operation keeps the rewrite size-preserving and remains effective when `--fuck-lgsi` disables `LongPressPowerStartLevoice`, which bypasses the helper predicate entirely.

**Tech Stack:** TOML `.dbp`, Rust unit tests, Dalvik method descriptors.

## Global Constraints

- Preserve the existing DBP operations and add a typed `method_const_int` operation.
- Target only `system/framework/services.jar`.
- Do not modify `framework.jar`, `ZuiSystemUI.apk`, or Android resources.
- Keep the patch size-preserving and compatible with deferred dm-verity regeneration.

---

### Task 1: Add and document the bundled power-menu patch

**Files:**
- Create: `patches/power-menu.dbp`
- Modify: `crates/dyno-app/src/dex_patch.rs`
- Modify: `crates/dyno-app/src/dbp.rs`
- Modify: `patches/README.md`

**Interfaces:**
- Consumes: `DbpOp::MethodConstInt` and `load_dbp(&Path)`.
- Produces: bundled patch name `power-menu` with one `()I → 1` operation.

- [x] **Step 1: Write the failing bundled-patch regression test**

Extend `bundled_dbp_files_parse` in `crates/dyno-app/src/dbp.rs`:

```rust
let pm = load_dbp(&patches_dir().join("power-menu.dbp")).expect("power-menu.dbp");
assert_eq!(pm.name, "power-menu");
assert_eq!(pm.ops.len(), 1);
match &pm.ops[0] {
    DbpOp::MethodConstInt {
        partition,
        file,
        class,
        method,
        proto,
        value,
    } => {
        assert_eq!(partition, "system");
        assert_eq!(file, "system/framework/services.jar");
        assert_eq!(
            class,
            "Lcom/android/server/policy/PhoneWindowManager;"
        );
        assert_eq!(method, "getResolvedLongPressOnPowerBehavior");
        assert_eq!(proto, "()I");
        assert_eq!(*value, 1);
    }
    _ => panic!("power-menu must use method_const_int"),
}
```

- [x] **Step 2: Run the focused test and verify it fails**

Run:

```text
cargo test -p dynobox-app bundled_dbp_files_parse --lib
```

Expected: FAIL because `method_const_int` and its DEX rewrite primitive do not
exist yet.

- [x] **Step 3: Add the integer method rewrite and minimal DBP**

Add `force_method_return_int`, selecting `const/4`, `const/16`, or `const`
according to the configured value. Add `DbpOp::MethodConstInt`, validate its
return descriptor as `I`, and route it through `apply_one_op`.

Create `patches/power-menu.dbp`:

```toml
name = "power-menu"
description = "Show Global Actions instead of Lenovo LeVoice on long power-key press."

[[op]]
kind = "method_const_int"
partition = "system"
file = "system/framework/services.jar"
class = "Lcom/android/server/policy/PhoneWindowManager;"
method = "getResolvedLongPressOnPowerBehavior"
value = 1
```

- [x] **Step 4: Document the bundled patch**

Add a `power-menu.dbp` bullet under `patches/README.md` → `Bundled patches`, explaining that `PhoneWindowManager` is forced to resolve behavior `1` (`LONG_PRESS_POWER_GLOBAL_ACTIONS`) even when the LeVoice helper path is disabled.

- [x] **Step 5: Run focused and workspace verification**

Run:

```text
cargo test -p dynobox-app bundled_dbp_files_parse --lib
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Expected: all commands exit `0`.
