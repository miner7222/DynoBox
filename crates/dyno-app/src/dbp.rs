//! `.dbp` (DynoBox Patch) files: external, user-authorable TOML patches
//! applied to APKs inside partition images during resign (`--plus`).
//!
//! A `.dbp` document names a set of size-preserving patch ops. Archive ops
//! target one APK/JAR inside one partition image and rewrite a method, invocation
//! result, field read, Intent launch, or compiled resource in place. Text ops
//! replace one exact byte string inside a regular file with another same-length
//! string. Dex rewrites use the [`crate::dex_patch`] primitives. This is how DynoBox ships
//! the former built-in launcher and ZuiSettings locale patches as data
//! instead of code.
//!
//! Example:
//!
//! ```toml
//! name = "debloat-launcher"
//! description = "Force ZuiLauncher home search + first-run to ROW."
//!
//! [[op]]
//! kind = "method_const_bool"
//! partition = "system"
//! file = "system/priv-app/ZuiLauncher/ZuiLauncher.apk"
//! class = "Lcom/android/launcher3/Utilities;"
//! method = "isZuiRow"
//! # proto defaults to "()Z"
//! value = true
//!
//! [[op]]
//! kind = "invoke_const_bool"
//! partition = "system"
//! file = "system/priv-app/ZuiSettings/ZuiSettings.apk"
//! scan_class = "Lcom/android/settings/localepicker/LocaleListEditor;"
//! target_class = "Lcom/lenovo/common/utils/LenovoUtils;"
//! target_method = "isPrcVersion"
//! value = false
//! ```

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::{Context, Result, anyhow};
use memchr::memmem;
use serde::Deserialize;

use crate::dex_patch::{
    NopAnchor, force_field_const_bool, force_fragment_render_gone, force_invoke_const_bool,
    force_invoke_const_int, force_method_broadcast_finish, force_method_return_bool,
    force_method_return_int, force_method_return_void, force_nop_anchored_invoke,
    force_remoteviews_gone, force_view_gone, parse_method_descriptor,
    redirect_intent_action_to_broadcast,
};
use crate::ext4_helpers::{lookup_inode_at_path, open_ext4_volume, write_via_extents};
use crate::fuck_lgsi::{
    crc32_ieee, parse_zip_central_directory, recompute_dex_header_sums, write_u32_le,
};

/// Default JVM descriptor for the boolean predicates these ops target.
fn default_bool_proto() -> String {
    "()Z".to_string()
}

fn default_int_proto() -> String {
    "()I".to_string()
}

fn default_void_proto() -> String {
    "()V".to_string()
}

fn default_on_create_bundle_proto() -> String {
    "(Landroid/os/Bundle;)V".to_string()
}

fn default_on_create_view() -> String {
    "onCreateView".to_string()
}

/// A parsed `.dbp` document.
#[derive(Debug, Clone, Deserialize)]
pub struct DbpDocument {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default, rename = "op")]
    pub ops: Vec<DbpOp>,
}

/// One patch operation. `kind` selects the patch primitive.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DbpOp {
    /// Force a `()Z` method body to `value` for every caller.
    MethodConstBool {
        partition: String,
        file: String,
        class: String,
        method: String,
        #[serde(default = "default_bool_proto")]
        proto: String,
        value: bool,
    },
    /// Force an integer-returning method body to `value` for every caller.
    MethodConstInt {
        partition: String,
        file: String,
        class: String,
        method: String,
        #[serde(default = "default_int_proto")]
        proto: String,
        value: i32,
    },
    /// Neutralize a `void` method: rewrite its body to `return-void` for every
    /// caller (used to disable init/register hooks at their source).
    MethodNop {
        partition: String,
        file: String,
        class: String,
        method: String,
        #[serde(default = "default_void_proto")]
        proto: String,
    },
    /// Force a compiled boolean resource inside a STORED `resources.arsc` APK
    /// entry to `value`.
    ResourceBool {
        partition: String,
        file: String,
        resource: String,
        value: bool,
    },
    /// Force a compiled dimension resource inside a STORED `resources.arsc` APK
    /// entry to `dp` density-independent pixels.
    ResourceDimen {
        partition: String,
        file: String,
        resource: String,
        dp: i32,
    },
    /// Replace an exact byte string inside a regular file with another string
    /// of identical byte length. Replaces only the first match by default, or
    /// every non-overlapping match when `all` is set. Intended for small
    /// property-file edits where growing the ext4 file would be unnecessary
    /// risk.
    TextReplace {
        partition: String,
        file: String,
        from: String,
        to: String,
        #[serde(default)]
        all: bool,
    },
    /// Force `invoke-static target_class.target_method()Z` results to `value`
    /// at every call site inside `scan_class` (optionally one `scan_method`).
    InvokeConstBool {
        partition: String,
        file: String,
        scan_class: String,
        #[serde(default)]
        scan_method: Option<String>,
        target_class: String,
        target_method: String,
        #[serde(default = "default_bool_proto")]
        proto: String,
        value: bool,
    },
    /// Like [`DbpOp::InvokeConstBool`] but for an int-returning (`I`) method:
    /// force each `target_class.target_method(...)I` result to `value` at its
    /// call sites in `scan_class` (e.g. pin a `Settings.*.getInt(...)` gate).
    InvokeConstInt {
        partition: String,
        file: String,
        scan_class: String,
        #[serde(default)]
        scan_method: Option<String>,
        target_class: String,
        target_method: String,
        #[serde(default = "default_int_proto")]
        proto: String,
        value: i32,
    },
    /// Force scoped reads of one exact boolean instance field to `value` by
    /// replacing `iget-boolean` with a size-preserving constant load.
    FieldConstBool {
        partition: String,
        file: String,
        scan_class: String,
        #[serde(default)]
        scan_method: Option<String>,
        target_class: String,
        target_field: String,
        value: bool,
    },
    /// Retarget an existing Intent action string reference and replace the
    /// associated `startActivity(Intent, Bundle)` with `sendBroadcast(Intent)`.
    /// Both strings must already exist in the dex string table.
    IntentActionBroadcast {
        partition: String,
        file: String,
        from_action: String,
        to_action: String,
    },
    /// Rewrite one Activity method body to `super` + `finish()` +
    /// broadcast(`action`) + `return-void`. Skips an OOBE entry screen (e.g. Lenovo ID)
    /// while advancing the setup wizard through an already-registered action.
    MethodBroadcastFinish {
        partition: String,
        file: String,
        class: String,
        method: String,
        #[serde(default = "default_on_create_bundle_proto")]
        proto: String,
        super_class: String,
        action: String,
    },
    /// Collapse a statically-embedded `<fragment>` tile by rewriting its
    /// `onCreateView` to inflate `layout` and return it with visibility `GONE`.
    /// Removes a homepage/entry tile without editing the compiled binary layout.
    FragmentHide {
        partition: String,
        file: String,
        class: String,
        #[serde(default = "default_on_create_view")]
        method: String,
        layout: u32,
    },
    /// Nop the first `target_class.target_method(...)` invoke (result
    /// discarded) that follows a constant load inside `scan_class.scan_method`.
    /// Drops a single imperative call site (e.g. a `List.add`/`Map.put`)
    /// disambiguated by a nearby anchor constant.
    NopInvoke {
        partition: String,
        file: String,
        scan_class: String,
        scan_method: String,
        target_class: String,
        target_method: String,
        proto: String,
        #[serde(default)]
        anchor_string: Option<String>,
        #[serde(default)]
        anchor_int: Option<i32>,
    },
    /// Force `setVisibility(GONE)` on the `findViewById`-bound views in
    /// `view_ids` inside `scan_class.scan_method`. Hides static layout entries
    /// that have no visibility gate; one field-backed view is the anchor that
    /// loads `View.GONE` into `scratch_reg`, reused by the other views.
    ForceViewGone {
        partition: String,
        file: String,
        scan_class: String,
        scan_method: String,
        view_ids: Vec<i32>,
        scratch_reg: u8,
    },
    /// Hide a `RemoteViews` view by rewriting one of its setup call sites in
    /// `scan_class.scan_method` (a `const vId, view_id` followed by a 2-unit
    /// arg-load + 3-unit invoke) into `RemoteViews.setViewVisibility(id, GONE)`.
    RemoteviewsHide {
        partition: String,
        file: String,
        scan_class: String,
        scan_method: String,
        view_id: i32,
        rv_reg: u8,
        scratch_reg: u8,
    },
}

impl DbpOp {
    pub fn partition(&self) -> &str {
        match self {
            DbpOp::MethodConstBool { partition, .. }
            | DbpOp::MethodConstInt { partition, .. }
            | DbpOp::MethodNop { partition, .. }
            | DbpOp::ResourceBool { partition, .. }
            | DbpOp::ResourceDimen { partition, .. }
            | DbpOp::TextReplace { partition, .. }
            | DbpOp::InvokeConstBool { partition, .. }
            | DbpOp::InvokeConstInt { partition, .. }
            | DbpOp::FieldConstBool { partition, .. }
            | DbpOp::IntentActionBroadcast { partition, .. }
            | DbpOp::MethodBroadcastFinish { partition, .. }
            | DbpOp::FragmentHide { partition, .. }
            | DbpOp::NopInvoke { partition, .. }
            | DbpOp::ForceViewGone { partition, .. }
            | DbpOp::RemoteviewsHide { partition, .. } => partition,
        }
    }

    pub fn file(&self) -> &str {
        match self {
            DbpOp::MethodConstBool { file, .. }
            | DbpOp::MethodConstInt { file, .. }
            | DbpOp::MethodNop { file, .. }
            | DbpOp::ResourceBool { file, .. }
            | DbpOp::ResourceDimen { file, .. }
            | DbpOp::TextReplace { file, .. }
            | DbpOp::InvokeConstBool { file, .. }
            | DbpOp::InvokeConstInt { file, .. }
            | DbpOp::FieldConstBool { file, .. }
            | DbpOp::IntentActionBroadcast { file, .. }
            | DbpOp::MethodBroadcastFinish { file, .. }
            | DbpOp::FragmentHide { file, .. }
            | DbpOp::NopInvoke { file, .. }
            | DbpOp::ForceViewGone { file, .. }
            | DbpOp::RemoteviewsHide { file, .. } => file,
        }
    }

    fn is_text_replace(&self) -> bool {
        matches!(self, DbpOp::TextReplace { .. })
    }
}

/// A partition name is safe when it maps to a single `<partition>.img` file
/// directly under the output directory — no path separators, no `..`, no
/// drive/UNC prefix. This blocks a shared `.dbp` from steering host file access
/// outside the resign output via a crafted `partition` value.
fn partition_name_is_safe(partition: &str) -> bool {
    !partition.is_empty()
        && partition
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// An in-image file path is safe when it has no `..` component and is not
/// rooted, so it resolves under the image root rather than escaping it.
fn file_path_is_safe(file: &str) -> bool {
    !file.is_empty()
        && !file.starts_with('/')
        && !file.starts_with('\\')
        && file
            .split(['/', '\\'])
            .all(|c| c != ".." && !c.contains(':'))
}

fn resource_name_is_safe(resource: &str) -> bool {
    !resource.is_empty()
        && resource
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
}

/// Load + validate a `.dbp` file. Fails on malformed TOML, an empty op list, a
/// descriptor that isn't a boolean (`()Z`-shaped) getter, or a partition / file
/// path that could steer access outside the intended image.
pub fn load_dbp(path: &Path) -> Result<DbpDocument> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading .dbp file {}", path.display()))?;
    let doc: DbpDocument =
        toml::from_str(&text).with_context(|| format!("parsing .dbp file {}", path.display()))?;
    if doc.ops.is_empty() {
        return Err(anyhow!("{}: .dbp has no [[op]] entries", path.display()));
    }
    for op in &doc.ops {
        let bail = |msg: String| anyhow!("{}: patch `{}`: {msg}", path.display(), doc.name);
        if !partition_name_is_safe(op.partition()) {
            return Err(bail(format!(
                "unsafe partition name `{}` (expected a bare name like `system`)",
                op.partition()
            )));
        }
        if !file_path_is_safe(op.file()) {
            return Err(bail(format!(
                "unsafe file path `{}` (must be relative to the image root, no `..`)",
                op.file()
            )));
        }
        match op {
            DbpOp::MethodConstBool { proto, .. } | DbpOp::InvokeConstBool { proto, .. } => {
                validate_method_proto(proto, "Z", "boolean (`Z`)", &bail)?;
            }
            DbpOp::MethodConstInt { proto, .. } | DbpOp::InvokeConstInt { proto, .. } => {
                validate_method_proto(proto, "I", "integer (`I`)", &bail)?;
            }
            DbpOp::MethodNop { proto, .. } => {
                validate_method_proto(proto, "V", "void (`V`)", &bail)?;
            }
            DbpOp::ResourceBool { resource, .. } => {
                if !resource_name_is_safe(resource) {
                    return Err(bail(format!(
                        "unsafe resource name `{resource}` (expected an Android resource entry name)"
                    )));
                }
            }
            DbpOp::ResourceDimen { resource, dp, .. } => {
                if !resource_name_is_safe(resource) {
                    return Err(bail(format!(
                        "unsafe resource name `{resource}` (expected an Android resource entry name)"
                    )));
                }
                if !(0..=0x00ff_ffff).contains(dp) {
                    return Err(bail(format!(
                        "resource dimension `{resource}` value {dp}dp out of range (0..=16777215)"
                    )));
                }
            }
            DbpOp::TextReplace { from, to, .. } => {
                if from.is_empty() {
                    return Err(bail("text_replace `from` must not be empty".to_string()));
                }
                if from.len() != to.len() {
                    return Err(bail(format!(
                        "text_replace `from` and `to` must have identical byte length ({} != {})",
                        from.len(),
                        to.len()
                    )));
                }
            }
            DbpOp::FieldConstBool {
                scan_class,
                scan_method,
                target_class,
                target_field,
                ..
            } => {
                for (label, class) in [
                    ("scan_class", scan_class.as_str()),
                    ("target_class", target_class.as_str()),
                ] {
                    if !(class.starts_with('L') && class.ends_with(';') && class.len() > 2) {
                        return Err(bail(format!(
                            "field_const_bool `{label}` must be a JVM descriptor like `Lcom/x/Y;`, got `{class}`"
                        )));
                    }
                }
                if scan_method.as_ref().is_some_and(String::is_empty) {
                    return Err(bail(
                        "field_const_bool `scan_method` must not be empty when set".to_string(),
                    ));
                }
                if target_field.is_empty() {
                    return Err(bail(
                        "field_const_bool `target_field` must not be empty".to_string(),
                    ));
                }
            }
            DbpOp::IntentActionBroadcast {
                from_action,
                to_action,
                ..
            } => {
                if from_action.is_empty() || to_action.is_empty() {
                    return Err(bail(
                        "intent_action_broadcast actions must not be empty".to_string(),
                    ));
                }
                if from_action == to_action {
                    return Err(bail(
                        "intent_action_broadcast `from_action` and `to_action` must differ"
                            .to_string(),
                    ));
                }
            }
            DbpOp::MethodBroadcastFinish {
                class,
                method,
                proto,
                super_class,
                action,
                ..
            } => {
                for (label, class_name) in [
                    ("class", class.as_str()),
                    ("super_class", super_class.as_str()),
                ] {
                    if !(class_name.starts_with('L')
                        && class_name.ends_with(';')
                        && class_name.len() > 2)
                    {
                        return Err(bail(format!(
                            "method_broadcast_finish `{label}` must be a JVM descriptor like `Lcom/x/Y;`, got `{class_name}`"
                        )));
                    }
                }
                if method.is_empty() {
                    return Err(bail(
                        "method_broadcast_finish `method` must not be empty".to_string(),
                    ));
                }
                if action.is_empty() {
                    return Err(bail(
                        "method_broadcast_finish `action` must not be empty".to_string(),
                    ));
                }
                if parse_method_descriptor(proto).is_none() {
                    return Err(bail(format!(
                        "method_broadcast_finish `proto` is not a valid JVM descriptor: `{proto}`"
                    )));
                }
            }
            DbpOp::FragmentHide { class, method, .. } => {
                if !(class.starts_with('L') && class.ends_with(';') && class.len() > 2) {
                    return Err(bail(format!(
                        "fragment_hide `class` must be a JVM descriptor like `Lcom/x/Frag;`, got `{class}`"
                    )));
                }
                if method.is_empty() {
                    return Err(bail("fragment_hide `method` must not be empty".to_string()));
                }
            }
            DbpOp::NopInvoke {
                scan_class,
                scan_method,
                target_class,
                proto,
                anchor_string,
                anchor_int,
                ..
            } => {
                if !(scan_class.starts_with('L')
                    && scan_class.ends_with(';')
                    && scan_class.len() > 2)
                {
                    return Err(bail(format!(
                        "nop_invoke `scan_class` must be a JVM descriptor like `Lcom/x/Y;`, got `{scan_class}`"
                    )));
                }
                if !(target_class.starts_with('L')
                    && target_class.ends_with(';')
                    && target_class.len() > 2)
                {
                    return Err(bail(format!(
                        "nop_invoke `target_class` must be a JVM descriptor like `Lcom/x/Y;`, got `{target_class}`"
                    )));
                }
                if scan_method.is_empty() {
                    return Err(bail(
                        "nop_invoke `scan_method` must not be empty".to_string(),
                    ));
                }
                if parse_method_descriptor(proto).is_none() {
                    return Err(bail(format!("invalid method descriptor `{proto}`")));
                }
                match (anchor_string, anchor_int) {
                    (Some(s), None) => {
                        if s.is_empty() {
                            return Err(bail(
                                "nop_invoke `anchor_string` must not be empty".to_string(),
                            ));
                        }
                    }
                    (None, Some(_)) => {}
                    (None, None) => {
                        return Err(bail(
                            "nop_invoke requires exactly one of `anchor_string` / `anchor_int`"
                                .to_string(),
                        ));
                    }
                    (Some(_), Some(_)) => {
                        return Err(bail(
                            "nop_invoke must set only one of `anchor_string` / `anchor_int`, not both"
                                .to_string(),
                        ));
                    }
                }
            }
            DbpOp::ForceViewGone {
                scan_class,
                scan_method,
                view_ids,
                scratch_reg,
                ..
            } => {
                if !(scan_class.starts_with('L')
                    && scan_class.ends_with(';')
                    && scan_class.len() > 2)
                {
                    return Err(bail(format!(
                        "force_view_gone `scan_class` must be a JVM descriptor like `Lcom/x/Y;`, got `{scan_class}`"
                    )));
                }
                if scan_method.is_empty() {
                    return Err(bail(
                        "force_view_gone `scan_method` must not be empty".to_string(),
                    ));
                }
                if view_ids.is_empty() {
                    return Err(bail(
                        "force_view_gone `view_ids` must not be empty".to_string(),
                    ));
                }
                if *scratch_reg >= 16 {
                    return Err(bail(format!(
                        "force_view_gone `scratch_reg` must be a nibble-encodable register (0..=15), got {scratch_reg}"
                    )));
                }
            }
            DbpOp::RemoteviewsHide {
                scan_class,
                scan_method,
                rv_reg,
                scratch_reg,
                ..
            } => {
                if !(scan_class.starts_with('L')
                    && scan_class.ends_with(';')
                    && scan_class.len() > 2)
                {
                    return Err(bail(format!(
                        "remoteviews_hide `scan_class` must be a JVM descriptor like `Lcom/x/Y;`, got `{scan_class}`"
                    )));
                }
                if scan_method.is_empty() {
                    return Err(bail(
                        "remoteviews_hide `scan_method` must not be empty".to_string(),
                    ));
                }
                if *rv_reg >= 16 || *scratch_reg >= 16 {
                    return Err(bail(
                        "remoteviews_hide `rv_reg` / `scratch_reg` must be nibble-encodable registers (0..=15)"
                            .to_string(),
                    ));
                }
            }
        }
    }
    Ok(doc)
}

fn validate_method_proto(
    proto: &str,
    expected_ret: &str,
    expected_name: &str,
    bail: &dyn Fn(String) -> anyhow::Error,
) -> Result<()> {
    // Reject a mismatched return type up front so a whole `.dbp` is
    // all-or-nothing instead of failing after earlier ops modified images.
    match parse_method_descriptor(proto) {
        Some((ret, _)) if ret == expected_ret => Ok(()),
        Some(_) => Err(bail(format!(
            "op descriptor `{proto}` must return {expected_name}"
        ))),
        None => Err(bail(format!("invalid method descriptor `{proto}`"))),
    }
}

/// Every partition name referenced by the ops across `docs`.
pub fn referenced_partitions<'a>(
    docs: impl IntoIterator<Item = &'a DbpDocument>,
) -> BTreeSet<String> {
    let mut set = BTreeSet::new();
    for doc in docs {
        for op in &doc.ops {
            set.insert(op.partition().to_string());
        }
    }
    set
}

/// Per-file result of applying the ops that targeted one image file.
#[derive(Debug, Clone)]
pub struct DbpFileResult {
    /// Path of the patched file inside the partition image.
    pub file: String,
    /// Number of ops that landed at least one site.
    pub ops_applied: usize,
    /// Number of ops that found no target (skipped, not an error).
    pub ops_skipped: usize,
    /// APK/JAR entry names or raw-file markers that were modified.
    pub patched_entries: Vec<String>,
}

/// Apply every op targeting `partition_name` (across `docs`) inside
/// `image_path`. Ops are grouped by file so each target is opened, patched, and
/// written back once. Returns one result per patched file, or an empty vec when
/// nothing landed (partition left untouched).
pub fn apply_partition_ops(
    image_path: &Path,
    partition_name: &str,
    docs: &[DbpDocument],
) -> Result<Vec<DbpFileResult>> {
    // Group ops by target file (preserving first-seen order).
    let mut files: Vec<String> = Vec::new();
    for doc in docs {
        for op in &doc.ops {
            if op.partition() == partition_name && !files.iter().any(|f| f == op.file()) {
                files.push(op.file().to_string());
            }
        }
    }

    let mut results = Vec::new();
    for file in files {
        let ops: Vec<&DbpOp> = docs
            .iter()
            .flat_map(|d| d.ops.iter())
            .filter(|op| op.partition() == partition_name && op.file() == file)
            .collect();
        if let Some(result) = apply_ops_to_file(image_path, &file, &ops)? {
            results.push(result);
        }
    }
    Ok(results)
}

fn apply_ops_to_file(
    image_path: &Path,
    file: &str,
    ops: &[&DbpOp],
) -> Result<Option<DbpFileResult>> {
    let has_text_ops = ops.iter().any(|op| op.is_text_replace());
    if has_text_ops && !ops.iter().all(|op| op.is_text_replace()) {
        return Err(anyhow!(
            "{file} mixes text_replace with archive patch ops; split them into separate files"
        ));
    }
    if has_text_ops {
        apply_text_ops_to_file(image_path, file, ops)
    } else {
        apply_ops_to_apk(image_path, file, ops)
    }
}

fn read_file_from_ext4(
    image_path: &Path,
    file: &str,
) -> Result<Option<(Vec<u8>, Vec<(u64, u64, u64, bool)>, u64)>> {
    let components: Vec<&str> = file.split('/').filter(|c| !c.is_empty()).collect();
    let mut volume = open_ext4_volume(image_path)?;
    let inode = match lookup_inode_at_path(&mut volume, &components)? {
        Some(i) => i,
        None => return Ok(None),
    };
    if !inode.is_file() {
        return Err(anyhow!(
            "{file} in {} is not a regular file",
            image_path.display()
        ));
    }
    let block_size = volume.block_size;
    let (bytes, extents) = inode
        .open_read_with_extents(&mut volume)
        .map_err(|e| anyhow!("Failed to read {file} from {}: {e}", image_path.display()))?;
    Ok(Some((bytes, extents, block_size)))
}

fn apply_text_ops_to_file(
    image_path: &Path,
    file: &str,
    ops: &[&DbpOp],
) -> Result<Option<DbpFileResult>> {
    let Some((mut bytes, extents, block_size)) = read_file_from_ext4(image_path, file)? else {
        return Ok(None);
    };
    if extents.is_empty() {
        return Ok(None);
    }

    let mut op_landed = vec![false; ops.len()];
    for (i, op) in ops.iter().enumerate() {
        let DbpOp::TextReplace { from, to, all, .. } = op else {
            unreachable!("caller filtered non-text ops");
        };
        if patch_text_replacement(&mut bytes, from.as_bytes(), to.as_bytes(), *all) > 0 {
            op_landed[i] = true;
        }
    }

    let ops_applied = op_landed.iter().filter(|&&b| b).count();
    if ops_applied == 0 {
        return Ok(None);
    }
    write_via_extents(image_path, &bytes, &extents, block_size)?;
    Ok(Some(DbpFileResult {
        file: file.to_string(),
        ops_applied,
        ops_skipped: ops.len() - ops_applied,
        patched_entries: vec!["raw bytes".to_string()],
    }))
}

/// Overwrite `from` with `to` in place (identical byte length, size-preserving)
/// and return how many matches were replaced. Replaces only the first match
/// unless `all` is set, in which case every non-overlapping match is replaced
/// (the scan resumes past each replacement, so a `to` that contains `from` is
/// never re-matched). Returns 0 when nothing matched.
fn patch_text_replacement(bytes: &mut [u8], from: &[u8], to: &[u8], all: bool) -> usize {
    debug_assert!(!from.is_empty());
    debug_assert_eq!(from.len(), to.len());
    let mut count = 0;
    let mut start = 0;
    while let Some(rel) = memmem::find(&bytes[start..], from) {
        let pos = start + rel;
        bytes[pos..pos + to.len()].copy_from_slice(to);
        count += 1;
        start = pos + to.len();
        if !all {
            break;
        }
    }
    count
}

/// Open `file` inside `image_path`, apply `ops` to supported STORED APK
/// entries in place, recompute dex sums / zip CRCs as needed, and write the APK
/// back over its ext4 extents. Returns `None` when the file is absent or no op
/// landed.
fn apply_ops_to_apk(
    image_path: &Path,
    file: &str,
    ops: &[&DbpOp],
) -> Result<Option<DbpFileResult>> {
    let Some((mut apk_bytes, apk_extents, block_size)) = read_file_from_ext4(image_path, file)?
    else {
        return Ok(None);
    };
    if apk_extents.is_empty() {
        return Ok(None);
    }

    let zip = parse_zip_central_directory(&apk_bytes)?;
    let dex_entries: Vec<_> = zip
        .entries
        .iter()
        .filter(|e| e.name.ends_with(".dex"))
        .filter(|e| !(e.compression_method != 0 || e.uses_data_descriptor || e.is_zip64))
        .filter(|e| e.data_start + e.compressed_size <= apk_bytes.len())
        .cloned()
        .collect();
    let resources_arsc = zip.entries.iter().find(|e| {
        e.name == "resources.arsc"
            && e.compression_method == 0
            && !e.uses_data_descriptor
            && !e.is_zip64
            && e.data_start + e.compressed_size <= apk_bytes.len()
    });

    // Track, per op, whether it landed anywhere across the APK's dexes.
    let mut op_landed = vec![false; ops.len()];
    let mut patched_entries: Vec<String> = Vec::new();

    for entry in &dex_entries {
        let dex_off = entry.data_start;
        let dex_end = dex_off + entry.compressed_size;
        let mut dex_modified = false;
        {
            let dex = &mut apk_bytes[dex_off..dex_end];
            if dex.len() < 0x70 {
                continue;
            }
            for (i, op) in ops.iter().enumerate() {
                if apply_one_op(dex, op)? {
                    op_landed[i] = true;
                    dex_modified = true;
                }
            }
        }
        if dex_modified {
            {
                let dex = &mut apk_bytes[dex_off..dex_end];
                recompute_dex_header_sums(dex);
            }
            let new_crc = crc32_ieee(&apk_bytes[dex_off..dex_end]);
            write_u32_le(&mut apk_bytes, entry.local_header_crc_offset, new_crc);
            write_u32_le(&mut apk_bytes, entry.cd_crc_offset, new_crc);
            patched_entries.push(entry.name.clone());
        }
    }

    if let Some(entry) = resources_arsc {
        let arsc_off = entry.data_start;
        let arsc_end = arsc_off + entry.compressed_size;
        let mut arsc_modified = false;
        {
            let arsc = &mut apk_bytes[arsc_off..arsc_end];
            for (i, op) in ops.iter().enumerate() {
                let landed = match op {
                    DbpOp::ResourceBool {
                        resource, value, ..
                    } => patch_resources_arsc_bool(arsc, resource, *value)?,
                    DbpOp::ResourceDimen { resource, dp, .. } => {
                        patch_resources_arsc_dimen(arsc, resource, *dp)?
                    }
                    _ => false,
                };
                if landed {
                    op_landed[i] = true;
                    arsc_modified = true;
                }
            }
        }
        if arsc_modified {
            let new_crc = crc32_ieee(&apk_bytes[arsc_off..arsc_end]);
            write_u32_le(&mut apk_bytes, entry.local_header_crc_offset, new_crc);
            write_u32_le(&mut apk_bytes, entry.cd_crc_offset, new_crc);
            patched_entries.push(entry.name.clone());
        }
    }

    let ops_applied = op_landed.iter().filter(|&&b| b).count();
    if ops_applied == 0 {
        return Ok(None);
    }
    write_via_extents(image_path, &apk_bytes, &apk_extents, block_size)?;
    Ok(Some(DbpFileResult {
        file: file.to_string(),
        ops_applied,
        ops_skipped: ops.len() - ops_applied,
        patched_entries,
    }))
}

/// Apply one op to one dex slice. Returns whether it landed at least one site.
fn apply_one_op(dex: &mut [u8], op: &DbpOp) -> Result<bool> {
    match op {
        DbpOp::MethodConstBool {
            class,
            method,
            proto,
            value,
            ..
        } => {
            let (ret, params) = parse_method_descriptor(proto)
                .ok_or_else(|| anyhow!("invalid descriptor `{proto}`"))?;
            let param_refs: Vec<&str> = params.iter().map(String::as_str).collect();
            force_method_return_bool(dex, class, method, &ret, &param_refs, *value)
        }
        DbpOp::MethodConstInt {
            class,
            method,
            proto,
            value,
            ..
        } => {
            let (ret, params) = parse_method_descriptor(proto)
                .ok_or_else(|| anyhow!("invalid descriptor `{proto}`"))?;
            let param_refs: Vec<&str> = params.iter().map(String::as_str).collect();
            force_method_return_int(dex, class, method, &ret, &param_refs, *value)
        }
        DbpOp::MethodNop {
            class,
            method,
            proto,
            ..
        } => {
            let (ret, params) = parse_method_descriptor(proto)
                .ok_or_else(|| anyhow!("invalid descriptor `{proto}`"))?;
            let param_refs: Vec<&str> = params.iter().map(String::as_str).collect();
            force_method_return_void(dex, class, method, &ret, &param_refs)
        }
        DbpOp::InvokeConstBool {
            scan_class,
            scan_method,
            target_class,
            target_method,
            proto,
            value,
            ..
        } => {
            let (ret, params) = parse_method_descriptor(proto)
                .ok_or_else(|| anyhow!("invalid descriptor `{proto}`"))?;
            let param_refs: Vec<&str> = params.iter().map(String::as_str).collect();
            let sites = force_invoke_const_bool(
                dex,
                scan_class,
                scan_method.as_deref(),
                target_class,
                target_method,
                &ret,
                &param_refs,
                *value,
            )?;
            Ok(sites > 0)
        }
        DbpOp::InvokeConstInt {
            scan_class,
            scan_method,
            target_class,
            target_method,
            proto,
            value,
            ..
        } => {
            let (ret, params) = parse_method_descriptor(proto)
                .ok_or_else(|| anyhow!("invalid descriptor `{proto}`"))?;
            let param_refs: Vec<&str> = params.iter().map(String::as_str).collect();
            let sites = force_invoke_const_int(
                dex,
                scan_class,
                scan_method.as_deref(),
                target_class,
                target_method,
                &ret,
                &param_refs,
                *value,
            )?;
            Ok(sites > 0)
        }
        DbpOp::FieldConstBool {
            scan_class,
            scan_method,
            target_class,
            target_field,
            value,
            ..
        } => {
            let sites = force_field_const_bool(
                dex,
                scan_class,
                scan_method.as_deref(),
                target_class,
                target_field,
                *value,
            )?;
            Ok(sites > 0)
        }
        DbpOp::IntentActionBroadcast {
            from_action,
            to_action,
            ..
        } => Ok(redirect_intent_action_to_broadcast(dex, from_action, to_action)? > 0),
        DbpOp::MethodBroadcastFinish {
            class,
            method,
            proto,
            super_class,
            action,
            ..
        } => {
            let (ret, params) = parse_method_descriptor(proto)
                .ok_or_else(|| anyhow!("invalid descriptor `{proto}`"))?;
            let param_refs: Vec<&str> = params.iter().map(String::as_str).collect();
            force_method_broadcast_finish(
                dex,
                class,
                method,
                &ret,
                &param_refs,
                super_class,
                action,
            )
        }
        DbpOp::FragmentHide {
            class,
            method,
            layout,
            ..
        } => force_fragment_render_gone(dex, class, method, *layout),
        DbpOp::NopInvoke {
            scan_class,
            scan_method,
            target_class,
            target_method,
            proto,
            anchor_string,
            anchor_int,
            ..
        } => {
            let (ret, params) = parse_method_descriptor(proto)
                .ok_or_else(|| anyhow!("invalid descriptor `{proto}`"))?;
            let param_refs: Vec<&str> = params.iter().map(String::as_str).collect();
            let anchor = match (anchor_string.as_deref(), anchor_int) {
                (Some(s), None) => NopAnchor::Str(s),
                (None, Some(v)) => NopAnchor::Int(*v),
                _ => {
                    return Err(anyhow!(
                        "nop_invoke requires exactly one of `anchor_string` / `anchor_int`"
                    ));
                }
            };
            let sites = force_nop_anchored_invoke(
                dex,
                scan_class,
                scan_method,
                target_class,
                target_method,
                &ret,
                &param_refs,
                anchor,
            )?;
            Ok(sites > 0)
        }
        DbpOp::ForceViewGone {
            scan_class,
            scan_method,
            view_ids,
            scratch_reg,
            ..
        } => {
            let hidden = force_view_gone(dex, scan_class, scan_method, view_ids, *scratch_reg)?;
            Ok(hidden > 0)
        }
        DbpOp::RemoteviewsHide {
            scan_class,
            scan_method,
            view_id,
            rv_reg,
            scratch_reg,
            ..
        } => {
            let hit = force_remoteviews_gone(
                dex,
                scan_class,
                scan_method,
                *view_id,
                *rv_reg,
                *scratch_reg,
            )?;
            Ok(hit > 0)
        }
        DbpOp::ResourceBool { .. } | DbpOp::ResourceDimen { .. } => Ok(false),
        DbpOp::TextReplace { .. } => Ok(false),
    }
}

const RES_STRING_POOL_TYPE: u16 = 0x0001;
const RES_TABLE_TYPE: u16 = 0x0002;
const RES_TABLE_PACKAGE_TYPE: u16 = 0x0200;
const RES_TABLE_TYPE_TYPE: u16 = 0x0201;
const RES_TABLE_ENTRY_FLAG_COMPLEX: u16 = 0x0001;
const TYPE_INT_BOOLEAN: u8 = 0x12;
/// `Res_value` data type for a complex dimension (`TYPE_DIMENSION`).
const TYPE_DIMENSION: u8 = 0x05;
/// Complex-dimension unit for density-independent pixels (`COMPLEX_UNIT_DIP`).
const COMPLEX_UNIT_DIP: u32 = 0x0000_0001;
/// Bit shift of the mantissa within a complex value.
const COMPLEX_MANTISSA_SHIFT: u32 = 8;

#[derive(Debug, Clone, Copy)]
struct ChunkHeader {
    ty: u16,
    header_size: usize,
    size: usize,
}

fn read_u16(buf: &[u8], off: usize) -> Result<u16> {
    let bytes = buf
        .get(off..off + 2)
        .ok_or_else(|| anyhow!("resources.arsc is truncated at offset {off}"))?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(buf: &[u8], off: usize) -> Result<u32> {
    let bytes = buf
        .get(off..off + 4)
        .ok_or_else(|| anyhow!("resources.arsc is truncated at offset {off}"))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn write_u32(buf: &mut [u8], off: usize, value: u32) -> Result<()> {
    let bytes = buf
        .get_mut(off..off + 4)
        .ok_or_else(|| anyhow!("resources.arsc is truncated at offset {off}"))?;
    bytes.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn chunk_header(buf: &[u8], off: usize) -> Result<ChunkHeader> {
    let ty = read_u16(buf, off)?;
    let header_size = read_u16(buf, off + 2)? as usize;
    let size = read_u32(buf, off + 4)? as usize;
    if header_size < 8 || size < header_size || off + size > buf.len() {
        return Err(anyhow!(
            "invalid resources.arsc chunk at offset {off}: header_size={header_size}, size={size}"
        ));
    }
    Ok(ChunkHeader {
        ty,
        header_size,
        size,
    })
}

fn read_length8(buf: &[u8], off: &mut usize) -> Result<usize> {
    let first = *buf
        .get(*off)
        .ok_or_else(|| anyhow!("string pool length is truncated"))?;
    *off += 1;
    if first & 0x80 == 0 {
        return Ok(first as usize);
    }
    let second = *buf
        .get(*off)
        .ok_or_else(|| anyhow!("string pool length is truncated"))?;
    *off += 1;
    Ok((((first & 0x7f) as usize) << 8) | second as usize)
}

fn read_length16(buf: &[u8], off: &mut usize) -> Result<usize> {
    let first = read_u16(buf, *off)?;
    *off += 2;
    if first & 0x8000 == 0 {
        return Ok(first as usize);
    }
    let second = read_u16(buf, *off)?;
    *off += 2;
    Ok((((first & 0x7fff) as usize) << 16) | second as usize)
}

fn parse_string_pool(buf: &[u8], off: usize) -> Result<Vec<String>> {
    let header = chunk_header(buf, off)?;
    if header.ty != RES_STRING_POOL_TYPE || header.header_size < 28 {
        return Err(anyhow!(
            "expected string pool at resources.arsc offset {off}"
        ));
    }
    let string_count = read_u32(buf, off + 8)? as usize;
    let flags = read_u32(buf, off + 16)?;
    let strings_start = read_u32(buf, off + 20)? as usize;
    let offsets_start = off + header.header_size;
    let strings_base = off + strings_start;
    if strings_start >= header.size || offsets_start + string_count * 4 > off + header.size {
        return Err(anyhow!(
            "invalid string pool at resources.arsc offset {off}"
        ));
    }
    let utf8 = flags & 0x100 != 0;
    let mut strings = Vec::with_capacity(string_count);
    for i in 0..string_count {
        let rel = read_u32(buf, offsets_start + i * 4)? as usize;
        let mut cursor = strings_base + rel;
        let s = if utf8 {
            let _utf16_len = read_length8(buf, &mut cursor)?;
            let utf8_len = read_length8(buf, &mut cursor)?;
            let bytes = buf
                .get(cursor..cursor + utf8_len)
                .ok_or_else(|| anyhow!("UTF-8 string pool entry is truncated"))?;
            String::from_utf8(bytes.to_vec()).context("invalid UTF-8 string pool entry")?
        } else {
            let utf16_len = read_length16(buf, &mut cursor)?;
            let bytes = buf
                .get(cursor..cursor + utf16_len * 2)
                .ok_or_else(|| anyhow!("UTF-16 string pool entry is truncated"))?;
            let units: Vec<u16> = bytes
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16(&units).context("invalid UTF-16 string pool entry")?
        };
        strings.push(s);
    }
    Ok(strings)
}

#[cfg(test)]
fn read_resources_arsc_bool(arsc: &[u8], resource_name: &str) -> Result<Option<bool>> {
    let mut data = arsc.to_vec();
    let old = find_or_patch_resources_arsc_value(&mut data, resource_name, None)?;
    match old {
        Some((ty, d)) if ty == TYPE_INT_BOOLEAN => Ok(Some(d != 0)),
        Some(_) => Err(anyhow!(
            "resource `{resource_name}` is not a compiled boolean value"
        )),
        None => Ok(None),
    }
}

fn patch_resources_arsc_bool(arsc: &mut [u8], resource_name: &str, value: bool) -> Result<bool> {
    let new = (TYPE_INT_BOOLEAN, if value { u32::MAX } else { 0 });
    match find_or_patch_resources_arsc_value(arsc, resource_name, Some(new))? {
        Some((ty, _)) if ty == TYPE_INT_BOOLEAN => Ok(true),
        // Landed on a value of the wrong type — reject rather than silently
        // rewriting a non-boolean resource.
        Some(_) => Err(anyhow!(
            "resource `{resource_name}` is not a compiled boolean value"
        )),
        None => Ok(false),
    }
}

/// Encode an integer `dp` value as an Android complex dimension `Res_value`
/// data word: mantissa in the integer (23p0) radix, `COMPLEX_UNIT_DIP` unit.
fn encode_dimension_dp(dp: i32) -> Result<u32> {
    if !(0..=0x00ff_ffff).contains(&dp) {
        return Err(anyhow!("dimension {dp}dp out of range (0..=16777215)"));
    }
    Ok(((dp as u32) << COMPLEX_MANTISSA_SHIFT) | COMPLEX_UNIT_DIP)
}

fn patch_resources_arsc_dimen(arsc: &mut [u8], resource_name: &str, dp: i32) -> Result<bool> {
    let new = (TYPE_DIMENSION, encode_dimension_dp(dp)?);
    match find_or_patch_resources_arsc_value(arsc, resource_name, Some(new))? {
        Some((ty, _)) if ty == TYPE_DIMENSION => Ok(true),
        Some(_) => Err(anyhow!(
            "resource `{resource_name}` is not a compiled dimension value"
        )),
        None => Ok(false),
    }
}

/// Walk `resources.arsc` for the resource entry keyed `resource_name`. Returns
/// its current `(data_type, data)` `Res_value`. When `new` is set, rewrites the
/// value in place (same 8-byte `Res_value`, size-preserving) *only if the entry
/// already has `new.0`'s type* — a type mismatch leaves the buffer untouched so
/// the caller can reject it. Returns `None` when the key isn't found.
fn find_or_patch_resources_arsc_value(
    arsc: &mut [u8],
    resource_name: &str,
    new: Option<(u8, u32)>,
) -> Result<Option<(u8, u32)>> {
    let table = chunk_header(arsc, 0)?;
    if table.ty != RES_TABLE_TYPE || table.header_size < 12 {
        return Err(anyhow!(
            "resources.arsc does not start with a resource table"
        ));
    }
    let mut off = table.header_size;
    while off < table.size {
        let chunk = chunk_header(arsc, off)?;
        if chunk.ty == RES_TABLE_PACKAGE_TYPE {
            if let Some(value) = find_or_patch_package_value(arsc, off, chunk, resource_name, new)?
            {
                return Ok(Some(value));
            }
        }
        off += chunk.size;
    }
    Ok(None)
}

fn find_or_patch_package_value(
    arsc: &mut [u8],
    package_off: usize,
    package: ChunkHeader,
    resource_name: &str,
    new: Option<(u8, u32)>,
) -> Result<Option<(u8, u32)>> {
    if package.header_size < 288 {
        return Err(anyhow!(
            "resource table package at offset {package_off} has unsupported header size {}",
            package.header_size
        ));
    }
    let key_strings_off = read_u32(arsc, package_off + 276)? as usize;
    let key_strings = parse_string_pool(arsc, package_off + key_strings_off)?;
    let mut off = package_off + package.header_size;
    let package_end = package_off + package.size;
    while off < package_end {
        let chunk = chunk_header(arsc, off)?;
        if chunk.ty == RES_TABLE_TYPE_TYPE {
            if let Some(value) =
                find_or_patch_type_value(arsc, off, chunk, &key_strings, resource_name, new)?
            {
                return Ok(Some(value));
            }
        }
        off += chunk.size;
    }
    Ok(None)
}

fn find_or_patch_type_value(
    arsc: &mut [u8],
    type_off: usize,
    type_chunk: ChunkHeader,
    key_strings: &[String],
    resource_name: &str,
    new: Option<(u8, u32)>,
) -> Result<Option<(u8, u32)>> {
    if type_chunk.header_size < 20 {
        return Err(anyhow!(
            "resource type chunk at offset {type_off} has unsupported header size {}",
            type_chunk.header_size
        ));
    }
    let entry_count = read_u32(arsc, type_off + 12)? as usize;
    let entries_start = read_u32(arsc, type_off + 16)? as usize;
    let offsets_start = type_off + type_chunk.header_size;
    if offsets_start + entry_count * 4 > type_off + type_chunk.size
        || entries_start >= type_chunk.size
    {
        return Err(anyhow!("invalid resource type chunk at offset {type_off}"));
    }
    for idx in 0..entry_count {
        let entry_rel = read_u32(arsc, offsets_start + idx * 4)?;
        if entry_rel == u32::MAX {
            continue;
        }
        let entry_off = type_off + entries_start + entry_rel as usize;
        let entry_size = read_u16(arsc, entry_off)? as usize;
        let flags = read_u16(arsc, entry_off + 2)?;
        let key_idx = read_u32(arsc, entry_off + 4)? as usize;
        if flags & RES_TABLE_ENTRY_FLAG_COMPLEX != 0 {
            continue;
        }
        if key_strings.get(key_idx).map(String::as_str) != Some(resource_name) {
            continue;
        }
        let value_off = entry_off + entry_size;
        let value_size = read_u16(arsc, value_off)?;
        if value_size < 8 {
            return Err(anyhow!(
                "resource `{resource_name}` has an unexpectedly small Res_value"
            ));
        }
        let data_type = *arsc
            .get(value_off + 3)
            .ok_or_else(|| anyhow!("resource value is truncated at offset {value_off}"))?;
        let data_off = value_off + 4;
        let old = (data_type, read_u32(arsc, data_off)?);
        if let Some((new_type, new_data)) = new {
            // Only rewrite when the existing value already has the requested
            // type: patches are size- and type-preserving, and a caller that
            // targeted the wrong resource type must see the mismatch with the
            // buffer left untouched (never punned to a different type).
            if data_type == new_type {
                write_u32(arsc, data_off, new_data)?;
            }
        }
        return Ok(Some(old));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_method_const_op() {
        let doc: DbpDocument = toml::from_str(
            r#"
name = "t"
[[op]]
kind = "method_const_bool"
partition = "system"
file = "system/priv-app/X/X.apk"
class = "Lcom/x/Y;"
method = "isZuiRow"
value = true
"#,
        )
        .unwrap();
        assert_eq!(doc.ops.len(), 1);
        match &doc.ops[0] {
            DbpOp::MethodConstBool {
                proto,
                value,
                method,
                ..
            } => {
                assert_eq!(proto, "()Z"); // defaulted
                assert!(*value);
                assert_eq!(method, "isZuiRow");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn parse_method_nop_op() {
        let doc: DbpDocument = toml::from_str(
            r#"
name = "t"
[[op]]
kind = "method_nop"
partition = "system"
file = "system/priv-app/X/X.apk"
class = "Lcom/x/Y;"
method = "initTMSApplication"
proto = "(Landroid/content/Context;Z)V"
"#,
        )
        .unwrap();
        match &doc.ops[0] {
            DbpOp::MethodNop {
                class,
                method,
                proto,
                ..
            } => {
                assert_eq!(class, "Lcom/x/Y;");
                assert_eq!(method, "initTMSApplication");
                assert_eq!(proto, "(Landroid/content/Context;Z)V");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn method_nop_requires_void_proto() {
        let doc: DbpDocument = toml::from_str(
            r#"
name = "t"
[[op]]
kind = "method_nop"
partition = "system"
file = "system/priv-app/X/X.apk"
class = "Lcom/x/Y;"
method = "foo"
proto = "()I"
"#,
        )
        .unwrap();
        // Parses, but load-time validation rejects a non-void proto. Exercise
        // the validator via a temp file.
        let dir = std::env::temp_dir().join(format!("dbp_mnop_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("t.dbp");
        std::fs::write(
            &p,
            r#"name = "t"
[[op]]
kind = "method_nop"
partition = "system"
file = "system/priv-app/X/X.apk"
class = "Lcom/x/Y;"
method = "foo"
proto = "()I"
"#,
        )
        .unwrap();
        assert!(load_dbp(&p).is_err(), "non-void proto must be rejected");
        let _ = doc; // parsed form is fine; validation is the gate
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parse_invoke_op_with_scan_method() {
        let doc: DbpDocument = toml::from_str(
            r#"
name = "t"
[[op]]
kind = "invoke_const_bool"
partition = "system"
file = "system/priv-app/X/X.apk"
scan_class = "Lcom/x/Scan;"
scan_method = "getChangedName"
target_class = "Lcom/x/Utils;"
target_method = "isRowVersion"
value = true
"#,
        )
        .unwrap();
        match &doc.ops[0] {
            DbpOp::InvokeConstBool {
                scan_method, value, ..
            } => {
                assert_eq!(scan_method.as_deref(), Some("getChangedName"));
                assert!(*value);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn parse_nop_invoke_op() {
        let doc: DbpDocument = toml::from_str(
            r#"
name = "t"
[[op]]
kind = "nop_invoke"
partition = "system"
file = "system/priv-app/X/X.apk"
scan_class = "Lcom/x/Scan;"
scan_method = "<init>"
target_class = "Ljava/util/List;"
target_method = "add"
proto = "(Ljava/lang/Object;)Z"
anchor_int = 0x7f12006d
"#,
        )
        .unwrap();
        match &doc.ops[0] {
            DbpOp::NopInvoke {
                scan_class,
                scan_method,
                target_class,
                target_method,
                proto,
                anchor_string,
                anchor_int,
                ..
            } => {
                assert_eq!(scan_class, "Lcom/x/Scan;");
                assert_eq!(scan_method, "<init>");
                assert_eq!(target_class, "Ljava/util/List;");
                assert_eq!(target_method, "add");
                assert_eq!(proto, "(Ljava/lang/Object;)Z");
                assert_eq!(anchor_string, &None);
                assert_eq!(anchor_int, &Some(0x7f12006d));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn parse_force_view_gone_op() {
        let doc: DbpDocument = toml::from_str(
            r#"
name = "t"
[[op]]
kind = "force_view_gone"
partition = "system"
file = "system/priv-app/X/X.apk"
scan_class = "Lcom/x/MainActivity;"
scan_method = "initView"
view_ids = [0x7f0903f1, 0x7f0903d7]
scratch_reg = 1
"#,
        )
        .unwrap();
        match &doc.ops[0] {
            DbpOp::ForceViewGone {
                scan_class,
                scan_method,
                view_ids,
                scratch_reg,
                ..
            } => {
                assert_eq!(scan_class, "Lcom/x/MainActivity;");
                assert_eq!(scan_method, "initView");
                assert_eq!(view_ids, &vec![0x7f0903f1, 0x7f0903d7]);
                assert_eq!(*scratch_reg, 1);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn parse_remoteviews_hide_op() {
        let doc: DbpDocument = toml::from_str(
            r#"
name = "t"
[[op]]
kind = "remoteviews_hide"
partition = "system"
file = "system/priv-app/X/X.apk"
scan_class = "Lcom/x/Widget;"
scan_method = "refreshWidget"
view_id = 0x7f09009e
rv_reg = 8
scratch_reg = 1
"#,
        )
        .unwrap();
        match &doc.ops[0] {
            DbpOp::RemoteviewsHide {
                scan_class,
                scan_method,
                view_id,
                rv_reg,
                scratch_reg,
                ..
            } => {
                assert_eq!(scan_class, "Lcom/x/Widget;");
                assert_eq!(scan_method, "refreshWidget");
                assert_eq!(*view_id, 0x7f09009e);
                assert_eq!(*rv_reg, 8);
                assert_eq!(*scratch_reg, 1);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn parse_resource_bool_op() {
        let doc: DbpDocument = toml::from_str(
            r#"
name = "resource-bool"
[[op]]
kind = "resource_bool"
partition = "product"
file = "app/Config.apk"
resource = "feature_enabled"
value = false
"#,
        )
        .unwrap();
        match &doc.ops[0] {
            DbpOp::ResourceBool {
                partition,
                file,
                resource,
                value,
            } => {
                assert_eq!(partition, "product");
                assert_eq!(file, "app/Config.apk");
                assert_eq!(resource, "feature_enabled");
                assert!(!*value);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn parse_text_replace_op() {
        let doc: DbpDocument = toml::from_str(
            r#"
name = "unlock-wifi"
[[op]]
kind = "text_replace"
partition = "system"
file = "system/build.prop"
from = "ro.config.zui.education=true\n"
to = "ro.product.countrycode=US\n##\n"
"#,
        )
        .unwrap();
        match &doc.ops[0] {
            DbpOp::TextReplace {
                partition,
                file,
                from,
                to,
                ..
            } => {
                assert_eq!(partition, "system");
                assert_eq!(file, "system/build.prop");
                assert_eq!(from.len(), to.len());
                assert_eq!(to, "ro.product.countrycode=US\n##\n");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn text_replace_rewrites_first_match_only() {
        let mut bytes =
            b"a=1\nro.config.zui.education=true\nb=2\nro.config.zui.education=true\n".to_vec();
        let landed = patch_text_replacement(
            &mut bytes,
            b"ro.config.zui.education=true\n",
            b"ro.product.countrycode=US\n##\n",
            false,
        );

        assert_eq!(landed, 1);
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            "a=1\nro.product.countrycode=US\n##\nb=2\nro.config.zui.education=true\n"
        );
    }

    #[test]
    fn text_replace_all_rewrites_every_match() {
        // Mirrors ZuiMemCleanerConfig.xml: the same size-preserving swap on
        // every occurrence, absorbing true->false (+1) into the trailing space.
        let line = |v: &str| {
            format!(
                "<Prop Name=\"zuimemory.use_quick_kill\" Value=\"{v}\"{}/>\n",
                if v == "true" { " " } else { "" }
            )
        };
        let mut bytes =
            format!("{}x=1\n{}{}", line("true"), line("true"), line("true")).into_bytes();
        let count = patch_text_replacement(
            &mut bytes,
            b"use_quick_kill\" Value=\"true\" />",
            b"use_quick_kill\" Value=\"false\"/>",
            true,
        );
        assert_eq!(count, 3);
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            format!("{}x=1\n{}{}", line("false"), line("false"), line("false"))
        );
    }

    #[test]
    fn resource_bool_rewrites_named_arsc_value_only() {
        let mut arsc = synthetic_bool_arsc(&[("feature_enabled", true), ("feature_gate", true)]);

        assert!(patch_resources_arsc_bool(&mut arsc, "feature_gate", false).unwrap());
        assert_eq!(
            arsc_bool_value(&arsc, "feature_enabled").unwrap(),
            Some(true)
        );
        assert_eq!(arsc_bool_value(&arsc, "feature_gate").unwrap(), Some(false));
    }

    #[test]
    fn encode_dimension_dp_packs_integer_dip() {
        // data = (dp << 8) | COMPLEX_UNIT_DIP; radix 23p0 (bits 4..8 = 0).
        assert_eq!(encode_dimension_dp(0).unwrap(), 0x0000_0001);
        assert_eq!(encode_dimension_dp(9).unwrap(), 0x0000_0901);
        assert_eq!(encode_dimension_dp(28).unwrap(), 0x0000_1c01);
        assert_eq!(encode_dimension_dp(0x00ff_ffff).unwrap(), 0xffff_ff01);
        assert!(encode_dimension_dp(-1).is_err());
        assert!(encode_dimension_dp(0x0100_0000).is_err());
    }

    #[test]
    fn resource_dimen_rewrites_named_dimension_only() {
        // Two dimension entries; only the named one is rewritten to 9dp.
        let mut arsc = synthetic_value_arsc(&[
            ("pad_a", TYPE_DIMENSION, encode_dimension_dp(2).unwrap()),
            ("pad_b", TYPE_DIMENSION, encode_dimension_dp(4).unwrap()),
        ]);

        assert!(patch_resources_arsc_dimen(&mut arsc, "pad_b", 9).unwrap());
        assert_eq!(
            arsc_raw_value(&arsc, "pad_a").unwrap(),
            Some((TYPE_DIMENSION, encode_dimension_dp(2).unwrap()))
        );
        assert_eq!(
            arsc_raw_value(&arsc, "pad_b").unwrap(),
            Some((TYPE_DIMENSION, 0x0000_0901))
        );
    }

    #[test]
    fn resource_dimen_rejects_wrong_value_type() {
        // Targeting a boolean entry as a dimension must be refused, not coerced.
        let mut arsc = synthetic_bool_arsc(&[("feature_gate", true)]);
        assert!(patch_resources_arsc_dimen(&mut arsc, "feature_gate", 9).is_err());
        // And the boolean stays intact.
        assert_eq!(arsc_bool_value(&arsc, "feature_gate").unwrap(), Some(true));
    }

    #[test]
    fn resource_dimen_missing_resource_reports_not_found() {
        let mut arsc = synthetic_value_arsc(&[("pad_a", TYPE_DIMENSION, 0x0000_0201)]);
        assert!(!patch_resources_arsc_dimen(&mut arsc, "nope", 9).unwrap());
    }

    #[test]
    fn referenced_partitions_dedups() {
        let doc: DbpDocument = toml::from_str(
            r#"
name = "t"
[[op]]
kind = "method_const_bool"
partition = "system"
file = "a"
class = "L;"
method = "m"
value = true
[[op]]
kind = "method_const_bool"
partition = "system"
file = "b"
class = "L;"
method = "m"
value = false
"#,
        )
        .unwrap();
        let parts = referenced_partitions([&doc]);
        assert_eq!(parts.len(), 1);
        assert!(parts.contains("system"));
    }

    fn patches_dir() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../patches")
    }

    #[test]
    fn bundled_dbp_files_parse() {
        let cl =
            load_dbp(&patches_dir().join("debloat-launcher.dbp")).expect("debloat-launcher.dbp");
        assert_eq!(cl.name, "debloat-launcher");
        assert_eq!(cl.ops.len(), 3);
        let zs = load_dbp(&patches_dir().join("unlock-locale.dbp")).expect("unlock-locale.dbp");
        assert_eq!(zs.name, "unlock-locale");
        assert_eq!(zs.ops.len(), 22);
        let wu = load_dbp(&patches_dir().join("unlock-wifi.dbp")).expect("unlock-wifi.dbp");
        assert_eq!(wu.name, "unlock-wifi");
        assert_eq!(wu.ops.len(), 2);
        match &wu.ops[0] {
            DbpOp::TextReplace {
                partition,
                file,
                from,
                to,
                ..
            } => {
                assert_eq!(partition, "system");
                assert_eq!(file, "system/build.prop");
                assert_eq!(from, "ro.config.zui.education=true\n");
                assert_eq!(to, "ro.product.countrycode=US\n##\n");
                assert_eq!(from.len(), to.len());
            }
            _ => panic!("unlock-wifi first op must pin system build.prop"),
        }
        match &wu.ops[1] {
            DbpOp::TextReplace {
                partition,
                file,
                from,
                to,
                ..
            } => {
                assert_eq!(partition, "system");
                assert_eq!(file, "system/bin/init");
                assert_eq!(from, "ro.product.countrycode");
                assert_eq!(to, "ro.product.countrycodE");
                assert_eq!(from.len(), to.len());
            }
            _ => panic!("unlock-wifi second op must neutralize Lenovo init country mapping"),
        }
        let gs = load_dbp(&patches_dir().join("show-google-services.dbp"))
            .expect("show-google-services.dbp");
        assert_eq!(gs.name, "show-google-services");
        assert_eq!(gs.ops.len(), 1);
        match &gs.ops[0] {
            DbpOp::MethodConstInt {
                partition,
                file,
                class,
                method,
                proto,
                value,
            } => {
                assert_eq!(partition, "system");
                assert_eq!(file, "system/priv-app/ZuiSettings/ZuiSettings.apk");
                assert_eq!(
                    class,
                    "Lcom/lenovo/settings/applications/GoogleServicesPreferenceController;"
                );
                assert_eq!(method, "getAvailabilityStatus");
                assert_eq!(proto, "()I");
                assert_eq!(*value, 0);
            }
            _ => panic!("show-google-services must use method_const_int"),
        }
        let sw = load_dbp(&patches_dir().join("debloat-setupwizard.dbp"))
            .expect("debloat-setupwizard.dbp");
        assert_eq!(sw.name, "debloat-setupwizard");
        assert_eq!(sw.ops.len(), 7);
        let mut cloud_offline = false;
        let mut cloud_completed = false;
        let mut fixed_complete = false;
        let mut forced_network_avail = false;
        let mut forced_non_commercial = false;
        let mut redirected_easysync = false;
        let mut skipped_lenovoid_entry = false;
        for op in &sw.ops {
            match op {
                // The cloud/Lenovo-ID gate: both forced so
                // ZuiUtils.getCloudActivityAction returns null (step skipped).
                DbpOp::InvokeConstBool {
                    scan_class,
                    scan_method,
                    target_method,
                    value,
                    ..
                } if scan_class.contains("ZuiUtils") => {
                    assert_eq!(
                        op.file(),
                        "system/priv-app/ZUISetupWizardExtPRC/ZUISetupWizardExtPRC.apk"
                    );
                    assert_eq!(scan_method.as_deref(), Some("getCloudActivityAction"));
                    match target_method.as_str() {
                        "isOnline" => {
                            assert!(!*value, "must force isOnline -> false");
                            cloud_offline = true;
                        }
                        "isCloudRestoreCompleted" => {
                            assert!(*value, "must force isCloudRestoreCompleted -> true");
                            cloud_completed = true;
                        }
                        other => panic!("unexpected ZuiUtils target {other}"),
                    }
                }
                // Complete screen: keep btn_next visible when the debloated
                // Vantage widget has no rectangle to animate toward.
                DbpOp::InvokeConstBool {
                    scan_class,
                    scan_method,
                    target_class,
                    target_method,
                    value,
                    ..
                } if scan_class.contains("CompleteLandActivity") => {
                    assert_eq!(
                        op.file(),
                        "system/priv-app/ZUISetupWizardExtPRC/ZUISetupWizardExtPRC.apk"
                    );
                    assert_eq!(scan_class, "Lcom/zui/setupwizard/CompleteLandActivity;");
                    assert_eq!(scan_method.as_deref(), Some("onCreate"));
                    assert_eq!(target_class, "Lcom/zui/setupwizard/common/AppHelper;");
                    assert_eq!(target_method, "isSupportCCS");
                    assert!(
                        *value,
                        "complete-screen gate must force isSupportCCS -> true"
                    );
                    fixed_complete = true;
                }
                // Wi-Fi activation: force the network gate true so Next / Set up
                // later always take the Lenovo ID branch when combined with
                // isPrcCommercial -> false.
                DbpOp::FieldConstBool {
                    scan_class,
                    scan_method,
                    target_class,
                    target_field,
                    value,
                    ..
                } => {
                    assert_eq!(op.file(), "system/priv-app/ZuiSettings/ZuiSettings.apk");
                    assert_eq!(
                        scan_class,
                        "Lcom/lenovo/settings/wifi/DeviceActivationForWifiActivity;"
                    );
                    assert_eq!(scan_method.as_deref(), Some("startPrivacySettingsActivity"));
                    assert_eq!(
                        target_class,
                        "Lcom/lenovo/settings/wifi/DeviceActivationForWifiActivity;"
                    );
                    assert_eq!(target_field, "isNetworkAvail");
                    assert!(*value, "network gate must force isNetworkAvail -> true");
                    forced_network_avail = true;
                }
                DbpOp::InvokeConstBool {
                    scan_class,
                    scan_method,
                    target_class,
                    target_method,
                    value,
                    ..
                } if scan_class.contains("DeviceActivationForWifiActivity") => {
                    assert_eq!(op.file(), "system/priv-app/ZuiSettings/ZuiSettings.apk");
                    assert_eq!(scan_method.as_deref(), Some("startPrivacySettingsActivity"));
                    assert_eq!(
                        target_class,
                        "Lcom/lenovo/settings/wifi/DeviceActivationForWifiActivity;"
                    );
                    assert_eq!(target_method, "isPrcCommercial");
                    assert!(!*value, "must force isPrcCommercial -> false");
                    forced_non_commercial = true;
                }
                // Post-login EasySync launches become CLOUD_SKIP broadcasts.
                DbpOp::IntentActionBroadcast {
                    from_action,
                    to_action,
                    ..
                } => {
                    assert_eq!(op.file(), "system/priv-app/LenovoID/LenovoID.apk");
                    assert_eq!(
                        from_action,
                        "com.zui.cloudservice.intent.action.GUIDE_DATA_RESTORE_FROM_PRIVACY"
                    );
                    assert_eq!(to_action, "com.zui.setupwizard.action.CLOUD_SKIP");
                    redirected_easysync = true;
                }
                // Skip the Lenovo ID entry Activity before it draws.
                DbpOp::MethodBroadcastFinish {
                    class,
                    method,
                    proto,
                    super_class,
                    action,
                    ..
                } => {
                    assert_eq!(op.file(), "system/priv-app/LenovoID/LenovoID.apk");
                    assert_eq!(class, "Lcom/lenovo/lsf/lenovoid/ui/PsLoginWizardActivity;");
                    assert_eq!(method, "onCreate");
                    assert_eq!(proto, "(Landroid/os/Bundle;)V");
                    assert_eq!(
                        super_class,
                        "Lcom/lenovo/lsf/lenovoid/ui/BaseWizardActivity;"
                    );
                    assert_eq!(action, "com.zui.setupwizard.action.CLOUD_SKIP");
                    skipped_lenovoid_entry = true;
                }
                _ => panic!("unexpected op in debloat-setupwizard"),
            }
        }
        assert!(
            cloud_offline
                && cloud_completed
                && fixed_complete
                && forced_network_avail
                && forced_non_commercial
                && redirected_easysync
                && skipped_lenovoid_entry,
            "all seven setup-wizard ops must parse"
        );
        let gl =
            load_dbp(&patches_dir().join("show-google-lens.dbp")).expect("show-google-lens.dbp");
        assert_eq!(gl.name, "show-google-lens");
        assert_eq!(gl.ops.len(), 3);
        match &gl.ops[2] {
            DbpOp::ResourceDimen {
                file, resource, dp, ..
            } => {
                assert_eq!(file, "system/priv-app/ZuiCamera/ZuiCamera.apk");
                assert_eq!(resource, "google_lens_button_padding");
                assert_eq!(*dp, 9);
            }
            _ => panic!("show-google-lens op[2] must be resource_dimen"),
        }
        match &gl.ops[0] {
            DbpOp::InvokeConstBool {
                scan_class,
                scan_method,
                target_class,
                target_method,
                value,
                ..
            } => {
                assert_eq!(scan_class, "Lcom/zui/camera/module/capture/CaptureModule;");
                assert_eq!(scan_method.as_deref(), Some("getUISpec"));
                assert_eq!(target_class, "Lcom/zui/camera/developer/common/ApiHelper;");
                assert_eq!(target_method, "isRow");
                assert!(*value);
            }
            _ => panic!("show-google-lens must use invoke_const_bool"),
        }
        let ds2 =
            load_dbp(&patches_dir().join("debloat-settings.dbp")).expect("debloat-settings.dbp");
        assert_eq!(ds2.name, "debloat-settings");
        assert_eq!(ds2.ops.len(), 4);
        let mut hide = false;
        let mut show = false;
        let mut hotline_prc = false;
        let mut hotline_row = false;
        for op in &ds2.ops {
            match op {
                DbpOp::MethodConstInt {
                    file,
                    class,
                    method,
                    proto,
                    value,
                    ..
                } => {
                    assert_eq!(file, "system/priv-app/ZuiSettings/ZuiSettings.apk");
                    assert_eq!(method, "getAvailabilityStatus");
                    assert_eq!(proto, "()I");
                    if class.contains("TopLevelLenovoAccountPreferenceController") && *value == 3 {
                        hide = true;
                    }
                    if class.contains("TopLevelAccountEntryPreferenceController") && *value == 0 {
                        show = true;
                    }
                }
                DbpOp::InvokeConstBool {
                    scan_class,
                    target_method,
                    value,
                    ..
                } => {
                    assert!(scan_class.contains("LenovoServicePreferenceController"));
                    if target_method == "isPrcVersion" && !*value {
                        hotline_prc = true;
                    }
                    if target_method == "isRowVersion" && *value {
                        hotline_row = true;
                    }
                }
                _ => panic!("unexpected op in debloat-settings"),
            }
        }
        assert!(hide, "must hide the LeCloud tile (-> 3)");
        assert!(show, "must show the Accounts & sync entry (-> 0)");
        assert!(
            hotline_prc && hotline_row,
            "must flip the hotline region gate to ROW (isPrcVersion->false, isRowVersion->true)"
        );

        let qk = load_dbp(&patches_dir().join("disable-quick-kill.dbp"))
            .expect("disable-quick-kill.dbp");
        assert_eq!(qk.name, "disable-quick-kill");
        assert_eq!(qk.ops.len(), 1);
        match &qk.ops[0] {
            DbpOp::TextReplace {
                file,
                from,
                to,
                all,
                ..
            } => {
                assert_eq!(file, "system/etc/ZuiMemCleanerConfig.xml");
                assert_eq!(from, "use_quick_kill\" Value=\"true\" />");
                assert_eq!(to, "use_quick_kill\" Value=\"false\"/>");
                assert_eq!(from.len(), to.len(), "must stay size-preserving");
                assert!(*all, "must replace every occurrence");
            }
            _ => panic!("disable-quick-kill must use a text_replace op"),
        }

        // The merged security patch (former antivirus / autostart /
        // permission-manager / url-security / app-recommendation patches).
        let ds =
            load_dbp(&patches_dir().join("debloat-security.dbp")).expect("debloat-security.dbp");
        assert_eq!(ds.name, "debloat-security");
        assert_eq!(ds.ops.len(), 17);
        let mut av_nops = 0usize; // AntiVirusInterface hub method_nops
        let mut got_getrecommendapp_nop = false;
        let mut got_install_scan = false; // invoke_const_int getInt -> 0
        let mut got_apprec_hide = false; // isRowVersion in ZuiEmergencyDashboardFragment.onCreate
        let mut got_perm_route = false; // isRowVersion in AppPermissionPreferenceController
        let mut got_perm_viewgone = false;
        let mut got_url_security = false;
        let mut nop_invokes = 0usize;
        let mut const_int_hides = 0usize;
        let mut fragment_hides = 0usize;
        let mut remoteviews_hides = 0usize;
        for op in &ds.ops {
            match op {
                DbpOp::MethodNop {
                    class,
                    method,
                    proto,
                    ..
                } => {
                    assert!(
                        proto.ends_with(")V"),
                        "method_nop must target a void method"
                    );
                    if class.contains("AntiVirusInterface") {
                        av_nops += 1;
                    } else if method == "getRecommendApp" {
                        assert!(class.contains("InstallInstallingExtra"));
                        got_getrecommendapp_nop = true;
                    } else {
                        panic!("unexpected method_nop target {class}->{method}");
                    }
                }
                DbpOp::InvokeConstInt {
                    file,
                    scan_class,
                    target_class,
                    target_method,
                    value,
                    ..
                } => {
                    assert_eq!(
                        file,
                        "system/priv-app/ZuiPackageInstaller/ZuiPackageInstaller.apk"
                    );
                    assert!(scan_class.contains("PackageInstallerActivityExtra"));
                    assert_eq!(target_class, "Landroid/provider/Settings$Global;");
                    assert_eq!(target_method, "getInt");
                    assert_eq!(*value, 0, "force safeInstallEnable -> false");
                    got_install_scan = true;
                }
                DbpOp::InvokeConstBool {
                    scan_class,
                    scan_method,
                    target_method,
                    value,
                    ..
                } => {
                    assert_eq!(target_method, "isRowVersion");
                    assert!(*value);
                    if scan_class.contains("ZuiEmergencyDashboardFragment") {
                        assert_eq!(scan_method.as_deref(), Some("onCreate"));
                        got_apprec_hide = true;
                    } else if scan_class.contains("AppPermissionPreferenceController") {
                        got_perm_route = true;
                    } else {
                        panic!("unexpected invoke_const_bool scan_class {scan_class}");
                    }
                }
                DbpOp::ForceViewGone {
                    scan_class,
                    view_ids,
                    ..
                } => {
                    assert!(scan_class.contains("MainNavigationActivity"));
                    assert_eq!(view_ids, &vec![0x7f0903f1, 0x7f090406, 0x7f0903d7]);
                    got_perm_viewgone = true;
                }
                DbpOp::TextReplace { file, from, to, .. } => {
                    assert_eq!(file, "system/build.prop");
                    assert_eq!(from, "ro.zui.software.safeurl=true");
                    assert_eq!(from.len(), to.len(), "must stay size-preserving");
                    got_url_security = true;
                }
                DbpOp::NopInvoke { .. } => nop_invokes += 1,
                DbpOp::MethodConstInt { method, value, .. } => {
                    assert_eq!(method, "getAvailabilityStatus");
                    assert_eq!(*value, 3);
                    const_int_hides += 1;
                }
                DbpOp::FragmentHide { .. } => fragment_hides += 1,
                DbpOp::RemoteviewsHide { .. } => remoteviews_hides += 1,
                _ => panic!("unexpected op kind in debloat-security"),
            }
        }
        assert_eq!(av_nops, 3, "3 AntiVirusInterface hub method_nops");
        assert_eq!(nop_invokes, 3, "antivirus item + 2 autostart nop_invokes");
        assert_eq!(
            const_int_hides, 3,
            "KillVirus + AppInstallationGuard + SelfStart -> 3"
        );
        assert_eq!(fragment_hides, 1);
        assert_eq!(remoteviews_hides, 1);
        assert!(
            got_getrecommendapp_nop
                && got_install_scan
                && got_apprec_hide
                && got_perm_route
                && got_perm_viewgone
                && got_url_security,
            "all new/key debloat-security ops must be present"
        );

        let cts = load_dbp(&patches_dir().join("enable-circle-to-search.dbp"))
            .expect("enable-circle-to-search.dbp");
        assert_eq!(cts.name, "enable-circle-to-search");
        assert_eq!(cts.ops.len(), 3);
        let mut sysui = false;
        let mut settings = false;
        let mut features = false;
        for op in &cts.ops {
            match op {
                DbpOp::InvokeConstBool {
                    scan_class,
                    target_method,
                    value,
                    ..
                } if scan_class.contains("AssistManager") => {
                    assert_eq!(target_method, "isDeviceRow");
                    assert!(*value);
                    sysui = true;
                }
                DbpOp::InvokeConstBool {
                    scan_method,
                    target_method,
                    value,
                    ..
                } => {
                    assert_eq!(scan_method.as_deref(), Some("isCircleToSearchEnable"));
                    assert_eq!(target_method, "isPrcVersion");
                    assert!(!*value);
                    settings = true;
                }
                DbpOp::TextReplace {
                    partition,
                    file,
                    from,
                    to,
                    ..
                } => {
                    assert_eq!(partition, "product");
                    assert_eq!(file, "etc/sysconfig/google.xml");
                    assert_eq!(
                        from.len(),
                        to.len(),
                        "google.xml swap must be size-preserving"
                    );
                    assert!(to.contains("CONTEXTUAL_SEARCH") && to.contains("GEMINI_EXPERIENCE"));
                    features = true;
                }
                _ => panic!("unexpected op in enable-circle-to-search"),
            }
        }
        assert!(
            sysui && settings && features,
            "all three CtS ops must parse"
        );

        let pgs = load_dbp(&patches_dir().join("show-power-gesture.dbp"))
            .expect("show-power-gesture.dbp");
        assert_eq!(pgs.name, "show-power-gesture");
        assert_eq!(pgs.ops.len(), 1);
        match &pgs.ops[0] {
            DbpOp::InvokeConstBool {
                file,
                scan_class,
                target_class,
                target_method,
                value,
                ..
            } => {
                assert_eq!(file, "system/priv-app/ZuiSettings/ZuiSettings.apk");
                assert!(scan_class.contains("PowerMenuPreferenceController"));
                assert_eq!(target_class, "Lcom/lenovo/common/utils/LenovoUtils;");
                assert_eq!(target_method, "isRowVersion");
                assert!(*value, "must force isRowVersion -> true");
            }
            _ => panic!("show-power-gesture must use invoke_const_bool"),
        }
    }

    /// Apply the bundled debloat-settings ops to the real ZuiSettings dexes.
    /// Set `DYNOBOX_ZUISETTINGS_DEX_DIR`; optionally
    /// `DYNOBOX_ZUISETTINGS_DEX_OUT` to dump patched dexes for disassembly.
    #[test]
    fn bundled_debloat_settings_land_on_real_dex() {
        let Ok(dir) = std::env::var("DYNOBOX_ZUISETTINGS_DEX_DIR") else {
            return;
        };
        let doc = load_dbp(&patches_dir().join("debloat-settings.dbp")).unwrap();
        let dir = std::path::Path::new(&dir);
        let mut landed = 0usize;
        for name in [
            "classes.dex",
            "classes2.dex",
            "classes3.dex",
            "classes4.dex",
            "classes5.dex",
            "classes6.dex",
        ] {
            let Ok(mut dex) = std::fs::read(dir.join(name)) else {
                continue;
            };
            let mut modified = false;
            for op in &doc.ops {
                if apply_one_op(&mut dex, op).unwrap() {
                    landed += 1;
                    modified = true;
                }
            }
            if modified {
                crate::fuck_lgsi::recompute_dex_header_sums(&mut dex);
                if let Ok(out) = std::env::var("DYNOBOX_ZUISETTINGS_DEX_OUT") {
                    std::fs::write(std::path::Path::new(&out).join(name), &dex).unwrap();
                }
            }
        }
        assert_eq!(landed, 4, "all four debloat-settings ops should land");
    }

    /// The deduplicated-code-item guard: forcing the "Service hotline"
    /// `LenovoServicePreferenceController.getAvailabilityStatus()` (a trivial
    /// `return 0` R8-shared with `ImmutableMap.isHashCodeFast():Z`) must be
    /// REFUSED, not corrupt the shared item. Set `DYNOBOX_ZUISETTINGS_APK`.
    #[test]
    fn shared_code_item_guard_refuses_deduped_getavailability() {
        let Ok(path) = std::env::var("DYNOBOX_ZUISETTINGS_APK") else {
            return;
        };
        let op = DbpOp::MethodConstInt {
            partition: "system".into(),
            file: "system/priv-app/ZuiSettings/ZuiSettings.apk".into(),
            class: "Lcom/lenovo/settings/deviceinfo/controller/LenovoServicePreferenceController;"
                .into(),
            method: "getAvailabilityStatus".into(),
            proto: "()I".into(),
            value: 3,
        };
        let apk = std::fs::read(&path).expect("read apk");
        let zip = crate::fuck_lgsi::parse_zip_central_directory(&apk).expect("zip");
        let mut hits = 0usize;
        for e in zip.entries.iter().filter(|e| {
            e.name.ends_with(".dex")
                && e.compression_method == 0
                && !e.uses_data_descriptor
                && !e.is_zip64
                && e.data_start + e.compressed_size <= apk.len()
        }) {
            let mut dex = apk[e.data_start..e.data_start + e.compressed_size].to_vec();
            if apply_one_op(&mut dex, &op).unwrap() {
                hits += 1;
            }
        }
        assert_eq!(hits, 0, "a shared/deduped code item must not be rewritten");
    }

    /// Apply the bundled show-google-lens dex ops to the real ZuiCamera
    /// dexes. Set `DYNOBOX_ZUICAMERA_DEX_DIR`; optionally
    /// `DYNOBOX_ZUICAMERA_DEX_OUT` to dump patched dexes for disassembly.
    /// The third op (`resource_dimen`) targets resources.arsc, not a dex, so
    /// it is a no-op here and covered by the arsc test below.
    #[test]
    fn bundled_show_google_lens_lands_on_real_dex() {
        let Ok(dir) = std::env::var("DYNOBOX_ZUICAMERA_DEX_DIR") else {
            return;
        };
        let doc = load_dbp(&patches_dir().join("show-google-lens.dbp")).unwrap();
        let dir = std::path::Path::new(&dir);
        let mut landed = 0usize;
        for name in ["classes.dex", "classes2.dex", "classes3.dex"] {
            let Ok(mut dex) = std::fs::read(dir.join(name)) else {
                continue;
            };
            let mut modified = false;
            for op in &doc.ops {
                if apply_one_op(&mut dex, op).unwrap() {
                    landed += 1;
                    modified = true;
                }
            }
            if modified {
                crate::fuck_lgsi::recompute_dex_header_sums(&mut dex);
                if let Ok(out) = std::env::var("DYNOBOX_ZUICAMERA_DEX_OUT") {
                    std::fs::write(std::path::Path::new(&out).join(name), &dex).unwrap();
                }
            }
        }
        assert_eq!(landed, 2, "both show-google-lens dex ops should land");
    }

    /// Apply the show-google-lens `resource_dimen` op to a real ZuiCamera
    /// `resources.arsc` (STORED APK entry, extract it verbatim). Set
    /// `DYNOBOX_ZUICAMERA_ARSC`; optionally `DYNOBOX_ZUICAMERA_ARSC_OUT` to
    /// dump the patched arsc.
    #[test]
    fn bundled_show_google_lens_dimen_lands_on_real_arsc() {
        let Ok(path) = std::env::var("DYNOBOX_ZUICAMERA_ARSC") else {
            return;
        };
        let mut arsc = std::fs::read(&path).unwrap();
        // Stock value is 2.25dp — a compiled dimension (fractional, radix != 0).
        let before = arsc_raw_value(&arsc, "google_lens_button_padding")
            .unwrap()
            .expect("google_lens_button_padding must exist");
        assert_eq!(before.0, TYPE_DIMENSION, "stock value must be a dimension");
        assert!(
            patch_resources_arsc_dimen(&mut arsc, "google_lens_button_padding", 9).unwrap(),
            "resource_dimen op should land"
        );
        // 9dp integer dimension = (9 << 8) | COMPLEX_UNIT_DIP.
        assert_eq!(
            arsc_raw_value(&arsc, "google_lens_button_padding").unwrap(),
            Some((TYPE_DIMENSION, 0x0000_0901))
        );
        if let Ok(out) = std::env::var("DYNOBOX_ZUICAMERA_ARSC_OUT") {
            std::fs::write(&out, &arsc).unwrap();
        }
    }

    /// Apply the bundled disable-quick-kill op to the real ZuiMemCleanerConfig
    /// XML. Set `DYNOBOX_ZMC_XML` to the extracted file path.
    #[test]
    fn bundled_disable_quick_kill_lands_on_real_xml() {
        let Ok(path) = std::env::var("DYNOBOX_ZMC_XML") else {
            return;
        };
        let doc = load_dbp(&patches_dir().join("disable-quick-kill.dbp")).unwrap();
        let DbpOp::TextReplace { from, to, all, .. } = &doc.ops[0] else {
            panic!("disable-quick-kill op[0] must be text_replace");
        };
        let mut bytes = std::fs::read(&path).unwrap();
        let before_len = bytes.len();
        let occurrences = bytes
            .windows(from.len())
            .filter(|w| *w == from.as_bytes())
            .count();
        let count = patch_text_replacement(&mut bytes, from.as_bytes(), to.as_bytes(), *all);
        assert_eq!(count, occurrences, "must replace every match");
        assert_eq!(
            count, 10,
            "TB322 ZuiMemCleanerConfig has 10 use_quick_kill blocks"
        );
        assert_eq!(bytes.len(), before_len, "swap must be size-preserving");
        assert!(
            memmem::find(&bytes, from.as_bytes()).is_none(),
            "no Value=\"true\" occurrence should remain"
        );
    }

    /// Apply the debloat-security `fragment_hide` op to the real ZuiSecurity
    /// dexes. Set `DYNOBOX_ZUISECURITY_DEX_DIR`; optionally
    /// `DYNOBOX_ZUISECURITY_DEX_OUT` to dump patched dexes for disassembly.
    #[test]
    fn bundled_fragment_hide_lands_on_real_dex() {
        let Ok(dir) = std::env::var("DYNOBOX_ZUISECURITY_DEX_DIR") else {
            return;
        };
        let doc = load_dbp(&patches_dir().join("debloat-security.dbp")).unwrap();
        let op = doc
            .ops
            .iter()
            .find(|o| matches!(o, DbpOp::FragmentHide { .. }))
            .expect("fragment_hide op");
        let dir = std::path::Path::new(&dir);
        let mut landed = 0usize;
        for name in [
            "classes.dex",
            "classes2.dex",
            "classes3.dex",
            "classes4.dex",
        ] {
            let Ok(mut dex) = std::fs::read(dir.join(name)) else {
                continue;
            };
            if apply_one_op(&mut dex, op).unwrap() {
                landed += 1;
                crate::fuck_lgsi::recompute_dex_header_sums(&mut dex);
                if let Ok(out) = std::env::var("DYNOBOX_ZUISECURITY_DEX_OUT") {
                    std::fs::write(std::path::Path::new(&out).join(name), &dex).unwrap();
                }
            }
        }
        assert_eq!(landed, 1, "fragment_hide should land in exactly one dex");
    }

    /// Every debloat-setupwizard op lands in exactly one dex of its real APK;
    /// the LenovoID redirect covers all ten EasySync launch continuations
    /// (nine source-action loads, with one shared across two branches). Set
    /// `DYNOBOX_ZUISETUPWIZARD_APK`, `DYNOBOX_ZUISETTINGS_APK`, and/or
    /// `DYNOBOX_LENOVOID_APK` to exercise the corresponding target.
    #[test]

    fn debloat_setupwizard_ops_land_on_real_apk() {
        let doc = load_dbp(&patches_dir().join("debloat-setupwizard.dbp")).unwrap();
        let targets = [
            (
                "system/priv-app/ZUISetupWizardExtPRC/ZUISetupWizardExtPRC.apk",
                "DYNOBOX_ZUISETUPWIZARD_APK",
            ),
            (
                "system/priv-app/ZuiSettings/ZuiSettings.apk",
                "DYNOBOX_ZUISETTINGS_APK",
            ),
            (
                "system/priv-app/LenovoID/LenovoID.apk",
                "DYNOBOX_LENOVOID_APK",
            ),
        ];

        for (file, env_name) in targets {
            let Ok(path) = std::env::var(env_name) else {
                continue;
            };
            let apk = std::fs::read(&path).expect("read apk");
            let zip = crate::fuck_lgsi::parse_zip_central_directory(&apk).expect("zip");
            let dex_entries: Vec<_> = zip
                .entries
                .iter()
                .filter(|e| {
                    e.name.ends_with(".dex")
                        && e.compression_method == 0
                        && !e.uses_data_descriptor
                        && !e.is_zip64
                        && e.data_start + e.compressed_size <= apk.len()
                })
                .collect();
            let ops: Vec<_> = doc.ops.iter().filter(|op| op.file() == file).collect();
            assert!(!ops.is_empty(), "{file} must have bundled ops");
            for op in ops {
                let mut dex_hits = 0usize;
                let mut redirect_sites = 0usize;
                let mut field_sites = 0usize;
                let mut entry_skip_sites = 0usize;
                for e in &dex_entries {
                    let original = &apk[e.data_start..e.data_start + e.compressed_size];
                    let mut dex = original.to_vec();
                    if apply_one_op(&mut dex, op).unwrap() {
                        dex_hits += 1;
                    }
                    if let DbpOp::IntentActionBroadcast {
                        from_action,
                        to_action,
                        ..
                    } = op
                    {
                        let mut count_dex = original.to_vec();
                        redirect_sites += redirect_intent_action_to_broadcast(
                            &mut count_dex,
                            from_action,
                            to_action,
                        )
                        .unwrap();
                        assert_eq!(
                            redirect_intent_action_to_broadcast(
                                &mut count_dex,
                                from_action,
                                to_action,
                            )
                            .unwrap(),
                            0,
                            "redirect must be idempotent"
                        );
                    }
                    if let DbpOp::FieldConstBool {
                        scan_class,
                        scan_method,
                        target_class,
                        target_field,
                        value,
                        ..
                    } = op
                    {
                        let mut count_dex = original.to_vec();
                        field_sites += force_field_const_bool(
                            &mut count_dex,
                            scan_class,
                            scan_method.as_deref(),
                            target_class,
                            target_field,
                            *value,
                        )
                        .unwrap();
                    }
                    if let DbpOp::MethodBroadcastFinish {
                        class,
                        method,
                        proto,
                        super_class,
                        action,
                        ..
                    } = op
                    {
                        let (ret, params) = parse_method_descriptor(proto).unwrap();
                        let param_refs: Vec<&str> = params.iter().map(String::as_str).collect();
                        let mut count_dex = original.to_vec();
                        if force_method_broadcast_finish(
                            &mut count_dex,
                            class,
                            method,
                            &ret,
                            &param_refs,
                            super_class,
                            action,
                        )
                        .unwrap()
                        {
                            entry_skip_sites += 1;
                        }
                        // idempotent-ish: second apply should still succeed (rewrites same body)
                        assert!(
                            force_method_broadcast_finish(
                                &mut count_dex,
                                class,
                                method,
                                &ret,
                                &param_refs,
                                super_class,
                                action,
                            )
                            .unwrap()
                        );
                    }
                }
                assert_eq!(
                    dex_hits, 1,
                    "{file} op must land in exactly one dex: {op:?}"
                );
                if matches!(op, DbpOp::IntentActionBroadcast { .. }) {
                    assert_eq!(
                        redirect_sites, 10,
                        "all LenovoID EasySync launches redirect"
                    );
                }
                if matches!(op, DbpOp::FieldConstBool { .. }) {
                    assert_eq!(field_sites, 1, "the Wi-Fi network gate has one field read");
                }
                if matches!(op, DbpOp::MethodBroadcastFinish { .. }) {
                    assert_eq!(
                        entry_skip_sites, 1,
                        "PsLoginWizardActivity.onCreate rewrites once"
                    );
                }
            }
        }
    }

    /// Land the three new debloat-security ops (app-recommendation hide +
    /// disable, install-scan disable) on the real apks. Set
    /// `DYNOBOX_ZUISETTINGS_APK` and/or `DYNOBOX_ZUIPACKAGEINSTALLER_APK`.
    #[test]
    fn debloat_security_new_ops_land_on_real_apks() {
        fn land(apk_path: &str, op: &DbpOp) -> usize {
            let apk = std::fs::read(apk_path).expect("read apk");
            let zip = crate::fuck_lgsi::parse_zip_central_directory(&apk).expect("zip");
            let mut hits = 0usize;
            for e in zip.entries.iter().filter(|e| {
                e.name.ends_with(".dex")
                    && e.compression_method == 0
                    && !e.uses_data_descriptor
                    && !e.is_zip64
                    && e.data_start + e.compressed_size <= apk.len()
            }) {
                let mut dex = apk[e.data_start..e.data_start + e.compressed_size].to_vec();
                if apply_one_op(&mut dex, op).unwrap() {
                    hits += 1;
                }
            }
            hits
        }
        let doc = load_dbp(&patches_dir().join("debloat-security.dbp")).unwrap();

        if let Ok(p) = std::env::var("DYNOBOX_ZUISETTINGS_APK") {
            let hide = doc
                .ops
                .iter()
                .find(|o| matches!(o, DbpOp::InvokeConstBool { scan_class, .. } if scan_class.contains("ZuiEmergencyDashboardFragment")))
                .expect("app-recommendation hide op");
            assert_eq!(
                land(&p, hide),
                1,
                "app-recommendation hide should land once"
            );
            let guard = doc
                .ops
                .iter()
                .find(|o| matches!(o, DbpOp::MethodConstInt { class, .. } if class.contains("AppInstallationGuardPreferenceController")))
                .expect("app-installation-guard hide op");
            assert_eq!(
                land(&p, guard),
                1,
                "app-installation-guard hide should land"
            );
        }

        if let Ok(p) = std::env::var("DYNOBOX_ZUISECURITY_APK") {
            let nav = doc
                .ops
                .iter()
                .find(|o| matches!(o, DbpOp::ForceViewGone { scan_class, .. } if scan_class.contains("MainNavigationActivity")))
                .expect("nav force_view_gone op");
            assert_eq!(land(&p, nav), 1, "nav row hide should land in one dex");
            // Emit the ZuiSecurity dex with the nav op applied for dexdump check
            // (permission + antivirus + autostart rows -> 3 setVisibility(GONE)).
            if let Ok(out) = std::env::var("DYNOBOX_ZUISECURITY_NAV_DEX_OUT") {
                let apk = std::fs::read(&p).expect("read apk");
                let zip = crate::fuck_lgsi::parse_zip_central_directory(&apk).expect("zip");
                for e in zip
                    .entries
                    .iter()
                    .filter(|e| e.name.ends_with(".dex") && e.compression_method == 0)
                {
                    let mut dex = apk[e.data_start..e.data_start + e.compressed_size].to_vec();
                    if apply_one_op(&mut dex, nav).unwrap() {
                        crate::fuck_lgsi::recompute_dex_header_sums(&mut dex);
                        std::fs::write(std::path::Path::new(&out).join(&e.name), &dex).unwrap();
                    }
                }
            }
        }

        if let Ok(p) = std::env::var("DYNOBOX_ZUIPACKAGEINSTALLER_APK") {
            let rec = doc
                .ops
                .iter()
                .find(
                    |o| matches!(o, DbpOp::MethodNop { method, .. } if method == "getRecommendApp"),
                )
                .expect("getRecommendApp nop op");
            assert_eq!(land(&p, rec), 1, "getRecommendApp nop should land once");
            let scan = doc
                .ops
                .iter()
                .find(|o| matches!(o, DbpOp::InvokeConstInt { .. }))
                .expect("install-scan op");
            assert_eq!(land(&p, scan), 1, "install-scan getInt force should land");

            // Optionally emit the classes.dex with BOTH installer ops applied
            // (sums recomputed) for structural validation via dexdump.
            if let Ok(out) = std::env::var("DYNOBOX_ZUIPACKAGEINSTALLER_DEX_OUT") {
                let apk = std::fs::read(&p).expect("read apk");
                let zip = crate::fuck_lgsi::parse_zip_central_directory(&apk).expect("zip");
                let e = zip
                    .entries
                    .iter()
                    .find(|e| e.name == "classes.dex" && e.compression_method == 0)
                    .expect("classes.dex");
                let mut dex = apk[e.data_start..e.data_start + e.compressed_size].to_vec();
                assert!(apply_one_op(&mut dex, rec).unwrap());
                assert!(apply_one_op(&mut dex, scan).unwrap());
                crate::fuck_lgsi::recompute_dex_header_sums(&mut dex);
                std::fs::write(std::path::Path::new(&out).join("classes.dex"), &dex).unwrap();
            }
        }
    }

    /// Apply the enable-circle-to-search dex ops to the real apks. Set
    /// `DYNOBOX_ZUISYSTEMUI_DEX_DIR` (AssistManager op) and/or
    /// `DYNOBOX_ZUISETTINGS_DEX_DIR` (isCircleToSearchEnable op); optionally the
    /// matching `*_OUT` dirs to dump patched dexes for disassembly.
    #[test]
    fn bundled_enable_circle_to_search_lands_on_real_dex() {
        let doc = load_dbp(&patches_dir().join("enable-circle-to-search.dbp")).unwrap();
        let sysui_op = doc
            .ops
            .iter()
            .find(|o| matches!(o, DbpOp::InvokeConstBool { scan_class, .. } if scan_class.contains("AssistManager")))
            .expect("AssistManager op");
        let settings_op = doc
            .ops
            .iter()
            .find(|o| matches!(o, DbpOp::InvokeConstBool { scan_method: Some(m), .. } if m == "isCircleToSearchEnable"))
            .expect("isCircleToSearchEnable op");

        let apply_dir = |env_dir: &str, env_out: &str, op: &DbpOp| {
            let Ok(dir) = std::env::var(env_dir) else {
                return None;
            };
            let dir = std::path::Path::new(&dir);
            let mut landed = 0usize;
            for n in 1..=9 {
                let name = if n == 1 {
                    "classes.dex".to_string()
                } else {
                    format!("classes{n}.dex")
                };
                let Ok(mut dex) = std::fs::read(dir.join(&name)) else {
                    continue;
                };
                if apply_one_op(&mut dex, op).unwrap() {
                    landed += 1;
                    crate::fuck_lgsi::recompute_dex_header_sums(&mut dex);
                    if let Ok(out) = std::env::var(env_out) {
                        std::fs::write(std::path::Path::new(&out).join(&name), &dex).unwrap();
                    }
                }
            }
            Some(landed)
        };

        if let Some(landed) = apply_dir(
            "DYNOBOX_ZUISYSTEMUI_DEX_DIR",
            "DYNOBOX_ZUISYSTEMUI_DEX_OUT",
            sysui_op,
        ) {
            assert_eq!(
                landed, 1,
                "AssistManager isDeviceRow op should land in one dex"
            );
        }
        if let Some(landed) = apply_dir(
            "DYNOBOX_ZUISETTINGS_DEX_DIR",
            "DYNOBOX_ZUISETTINGS_DEX_OUT",
            settings_op,
        ) {
            assert_eq!(
                landed, 1,
                "isCircleToSearchEnable op should land in one dex"
            );
        }
    }

    /// Apply the bundled show-google-services op to the real ZuiSettings dexes.
    /// Set `DYNOBOX_ZUISETTINGS_DEX_DIR`.
    #[test]
    fn bundled_show_google_services_lands_on_real_dex() {
        let Ok(dir) = std::env::var("DYNOBOX_ZUISETTINGS_DEX_DIR") else {
            return;
        };
        let doc = load_dbp(&patches_dir().join("show-google-services.dbp")).unwrap();
        let dir = std::path::Path::new(&dir);
        let mut landed = 0usize;
        for name in [
            "classes.dex",
            "classes2.dex",
            "classes3.dex",
            "classes4.dex",
            "classes5.dex",
            "classes6.dex",
        ] {
            let Ok(mut dex) = std::fs::read(dir.join(name)) else {
                continue;
            };
            for op in &doc.ops {
                if apply_one_op(&mut dex, op).unwrap() {
                    landed += 1;
                }
            }
        }
        assert_eq!(
            landed, 1,
            "show-google-services op should land exactly once"
        );
    }

    /// Apply the bundled debloat-launcher ops to the real ZuiLauncher dexes.
    /// Set `DYNOBOX_ZUILAUNCHER_DEX_DIR`.
    #[test]
    fn bundled_debloat_launcher_lands_on_real_dex() {
        let Ok(dir) = std::env::var("DYNOBOX_ZUILAUNCHER_DEX_DIR") else {
            return;
        };
        let doc = load_dbp(&patches_dir().join("debloat-launcher.dbp")).unwrap();
        let dir = std::path::Path::new(&dir);
        let mut landed = 0usize;
        for name in ["classes.dex", "classes2.dex", "classes3.dex"] {
            let Ok(mut dex) = std::fs::read(dir.join(name)) else {
                continue;
            };
            for op in &doc.ops {
                if apply_one_op(&mut dex, op).unwrap() {
                    landed += 1;
                }
            }
        }
        assert_eq!(landed, 3, "all three debloat-launcher ops should land");
    }

    /// Apply the bundled ZuiSettings ops to the real ZuiSettings dexes.
    /// Set `DYNOBOX_ZUISETTINGS_DEX_DIR`.
    #[test]
    fn bundled_unlock_locale_lands_on_real_dex() {
        let Ok(dir) = std::env::var("DYNOBOX_ZUISETTINGS_DEX_DIR") else {
            return;
        };
        let doc = load_dbp(&patches_dir().join("unlock-locale.dbp")).unwrap();
        let dir = std::path::Path::new(&dir);
        let mut landed = 0usize;
        for name in [
            "classes.dex",
            "classes2.dex",
            "classes3.dex",
            "classes4.dex",
            "classes5.dex",
            "classes6.dex",
        ] {
            let Ok(mut dex) = std::fs::read(dir.join(name)) else {
                continue;
            };
            for op in &doc.ops {
                if apply_one_op(&mut dex, op).unwrap() {
                    landed += 1;
                }
            }
        }
        assert!(
            landed >= 10,
            "expected most ZuiSettings ops to land, got {landed}"
        );
    }

    #[test]
    fn partition_name_safety() {
        assert!(partition_name_is_safe("system"));
        assert!(partition_name_is_safe("vbmeta_system"));
        assert!(!partition_name_is_safe(""));
        assert!(!partition_name_is_safe("../input/system"));
        assert!(!partition_name_is_safe("a/b"));
        assert!(!partition_name_is_safe(".."));
        assert!(!partition_name_is_safe("C:system"));
    }

    #[test]
    fn file_path_safety() {
        assert!(file_path_is_safe("system/priv-app/X/X.apk"));
        assert!(!file_path_is_safe(""));
        assert!(!file_path_is_safe("/etc/passwd"));
        assert!(!file_path_is_safe("\\abs"));
        assert!(!file_path_is_safe("system/../../escape"));
        assert!(!file_path_is_safe("C:/x"));
    }

    fn write_temp_dbp(body: &str) -> tempfile::NamedTempFile {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(body.as_bytes()).unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn load_rejects_non_boolean_proto() {
        let f = write_temp_dbp(
            r#"
name = "t"
[[op]]
kind = "method_const_bool"
partition = "system"
file = "system/x.apk"
class = "L;"
method = "m"
proto = "()V"
value = true
"#,
        );
        let err = load_dbp(f.path()).unwrap_err().to_string();
        assert!(err.contains("boolean"), "got: {err}");
    }

    #[test]
    fn load_rejects_non_integer_proto_for_method_const_int() {
        let f = write_temp_dbp(
            r#"
name = "t"
[[op]]
kind = "method_const_int"
partition = "system"
file = "system/framework/services.jar"
class = "Lcom/android/server/policy/PhoneWindowManager;"
method = "getResolvedLongPressOnPowerBehavior"
proto = "()Z"
value = 1
"#,
        );
        let err = load_dbp(f.path()).unwrap_err().to_string();
        assert!(err.contains("integer"), "got: {err}");
    }

    #[test]
    fn load_rejects_unsafe_resource_name_for_resource_bool() {
        let f = write_temp_dbp(
            r#"
name = "t"
[[op]]
kind = "resource_bool"
partition = "product"
file = "app/Config.apk"
resource = "../escape"
value = false
"#,
        );
        let err = load_dbp(f.path()).unwrap_err().to_string();
        assert!(err.contains("unsafe resource"), "got: {err}");
    }

    #[test]
    fn load_rejects_unequal_text_replace_lengths() {
        let f = write_temp_dbp(
            r#"
name = "t"
[[op]]
kind = "text_replace"
partition = "system"
file = "system/build.prop"
from = "short"
to = "longer"
"#,
        );
        let err = load_dbp(f.path()).unwrap_err().to_string();
        assert!(err.contains("identical byte length"), "got: {err}");
    }

    #[test]
    fn load_rejects_unsafe_partition() {
        let f = write_temp_dbp(
            r#"
name = "t"
[[op]]
kind = "method_const_bool"
partition = "../input/system"
file = "system/x.apk"
class = "L;"
method = "m"
value = true
"#,
        );
        let err = load_dbp(f.path()).unwrap_err().to_string();
        assert!(err.contains("unsafe partition"), "got: {err}");
    }

    #[test]
    fn unknown_field_rejected() {
        let err = toml::from_str::<DbpDocument>(
            r#"
name = "t"
[[op]]
kind = "method_const_bool"
partition = "system"
file = "a"
class = "L;"
method = "m"
value = true
bogus = 1
"#,
        );
        assert!(err.is_err());
    }

    fn put_u32(buf: &mut [u8], off: usize, value: u32) {
        buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn push_chunk_header(buf: &mut Vec<u8>, ty: u16, header_size: u16) -> usize {
        let off = buf.len();
        buf.extend_from_slice(&ty.to_le_bytes());
        buf.extend_from_slice(&header_size.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        off
    }

    fn finish_chunk(buf: &mut [u8], off: usize) {
        put_u32(buf, off + 4, (buf.len() - off) as u32);
    }

    fn encode_len8(out: &mut Vec<u8>, len: usize) {
        assert!(len < 0x80);
        out.push(len as u8);
    }

    fn string_pool(strings: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        let header = push_chunk_header(&mut out, 0x0001, 28);
        out.extend_from_slice(&(strings.len() as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // styleCount
        out.extend_from_slice(&0x100u32.to_le_bytes()); // UTF-8
        out.extend_from_slice(&((28 + strings.len() * 4) as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // stylesStart
        let mut data = Vec::new();
        for s in strings {
            out.extend_from_slice(&(data.len() as u32).to_le_bytes());
            encode_len8(&mut data, s.chars().count());
            encode_len8(&mut data, s.len());
            data.extend_from_slice(s.as_bytes());
            data.push(0);
        }
        out.extend_from_slice(&data);
        while out.len() % 4 != 0 {
            out.push(0);
        }
        finish_chunk(&mut out, header);
        out
    }

    fn synthetic_bool_arsc(entries: &[(&str, bool)]) -> Vec<u8> {
        let mapped: Vec<(&str, u8, u32)> = entries
            .iter()
            .map(|(name, value)| (*name, 0x12u8, if *value { u32::MAX } else { 0 }))
            .collect();
        synthetic_value_arsc(&mapped)
    }

    /// Build a minimal single-package `resources.arsc` whose entries carry an
    /// arbitrary `Res_value` `(data_type, data)` each, keyed by name.
    fn synthetic_value_arsc(entries: &[(&str, u8, u32)]) -> Vec<u8> {
        let mut out = Vec::new();
        let table = push_chunk_header(&mut out, 0x0002, 12);
        out.extend_from_slice(&1u32.to_le_bytes()); // package count
        out.extend_from_slice(&string_pool(&[]));

        let package = out.len();
        out.extend_from_slice(&0x0200u16.to_le_bytes());
        out.extend_from_slice(&288u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0x7fu32.to_le_bytes());
        let mut package_name = vec![0u8; 256];
        for (i, u) in "synthetic.overlay".encode_utf16().enumerate() {
            package_name[i * 2..i * 2 + 2].copy_from_slice(&u.to_le_bytes());
        }
        out.extend_from_slice(&package_name);
        out.extend_from_slice(&288u32.to_le_bytes()); // typeStrings
        out.extend_from_slice(&0u32.to_le_bytes()); // lastPublicType
        let key_strings_off = 288 + string_pool(&["bool"]).len();
        out.extend_from_slice(&(key_strings_off as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // lastPublicKey
        out.extend_from_slice(&0u32.to_le_bytes()); // typeIdOffset

        out.extend_from_slice(&string_pool(&["bool"]));
        let key_names: Vec<&str> = entries.iter().map(|(name, _, _)| *name).collect();
        out.extend_from_slice(&string_pool(&key_names));

        let type_spec = push_chunk_header(&mut out, 0x0202, 16);
        out.push(1); // type id: bool
        out.push(0);
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
        for _ in entries {
            out.extend_from_slice(&0u32.to_le_bytes());
        }
        finish_chunk(&mut out, type_spec);

        let ty = push_chunk_header(&mut out, 0x0201, 0x34);
        out.push(1); // type id: bool
        out.push(0);
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
        let entries_start = 0x34 + entries.len() * 4;
        out.extend_from_slice(&(entries_start as u32).to_le_bytes());
        out.extend_from_slice(&0x20u32.to_le_bytes()); // ResTable_config size
        out.resize(ty + 0x34, 0);
        for (i, _) in entries.iter().enumerate() {
            out.extend_from_slice(&((i * 16) as u32).to_le_bytes());
        }
        for (i, (_, data_type, data)) in entries.iter().enumerate() {
            out.extend_from_slice(&8u16.to_le_bytes()); // ResTable_entry size
            out.extend_from_slice(&0u16.to_le_bytes());
            out.extend_from_slice(&(i as u32).to_le_bytes());
            out.extend_from_slice(&8u16.to_le_bytes()); // Res_value size
            out.push(0);
            out.push(*data_type);
            out.extend_from_slice(&data.to_le_bytes());
        }
        finish_chunk(&mut out, ty);
        finish_chunk(&mut out, package);
        finish_chunk(&mut out, table);
        out
    }

    fn arsc_bool_value(arsc: &[u8], resource: &str) -> Result<Option<bool>> {
        read_resources_arsc_bool(arsc, resource)
    }

    /// Read the raw `(data_type, data)` of a resource entry without mutating it.
    fn arsc_raw_value(arsc: &[u8], resource: &str) -> Result<Option<(u8, u32)>> {
        let mut data = arsc.to_vec();
        find_or_patch_resources_arsc_value(&mut data, resource, None)
    }
}
