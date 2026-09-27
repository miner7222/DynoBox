//! `.dbp` (DynoBox Patch) files: external, user-authorable TOML patches
//! applied to APKs inside partition images during resign (`--plus`).
//!
//! A `.dbp` document names a set of size-preserving patch ops. Archive ops
//! target one APK/JAR inside one partition image and rewrite a method, invocation
//! result, field read, Intent launch, or compiled resource in place. Text ops
//! replace one exact byte string inside a regular file with another same-length
//! string. Zip ops swap the data of STORED entries inside any zip archive
//! (APK or otherwise) with a fixed payload, zero-padding to the original
//! entry length. Dex rewrites use the [`crate::dex_patch`] primitives. This is how DynoBox ships
//! the former built-in launcher and ZuiSettings locale patches as data
//! instead of code.
//!
//! Example:
//!
//! ```toml
//! name = "debloat-common"
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

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{Context, Result, anyhow};
use memchr::memmem;
use serde::Deserialize;

use crate::byte_io::write_u32_le;
use crate::dex_patch::{
    DexMethodRef, DexPoolSymbol, DexPoolSymbolKind, MethodCodeReplacement, MethodCodeTemplateSlot,
    NopAnchor, force_axml_background, force_axml_collapse, force_field_const_bool,
    force_fragment_render_gone, force_invoke_const_bool, force_invoke_const_bool_at,
    force_invoke_const_int, force_method_broadcast_finish, force_method_return_bool,
    force_method_return_const_string, force_method_return_int, force_method_return_void,
    force_nop_anchored_invoke, force_preference_controller_hidden, force_remoteviews_gone,
    force_view_gone, force_zip_entry_replace, parse_method_descriptor, patch_method_code,
    redirect_intent_action_to_broadcast, redirect_method_code, resolve_dex_pool_symbol,
    validate_method_code_template_slots,
};
use crate::dex_util::recompute_dex_header_sums;
use crate::ext4_helpers::{lookup_inode_at_path, open_ext4_volume, write_via_extents};
use crate::ext4_reader::ExtentRun;
use crate::zip_util::{crc32_ieee, parse_zip_central_directory};

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

fn default_string_proto() -> String {
    "()Ljava/lang/String;".to_string()
}

fn default_on_create_bundle_proto() -> String {
    "(Landroid/os/Bundle;)V".to_string()
}

fn default_on_create_view() -> String {
    "onCreateView".to_string()
}

fn default_expected_matches() -> usize {
    1
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DbpCodeReplacement {
    pub from: String,
    pub to: String,
    #[serde(default = "default_expected_matches")]
    pub expected: usize,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DbpCodeSymbol {
    String {
        name: String,
        value: String,
    },
    Type {
        name: String,
        descriptor: String,
    },
    Field {
        name: String,
        class: String,
        field: String,
        ty: String,
    },
    Method {
        name: String,
        class: String,
        method: String,
        proto: String,
    },
}

impl DbpCodeSymbol {
    fn name(&self) -> &str {
        match self {
            Self::String { name, .. }
            | Self::Type { name, .. }
            | Self::Field { name, .. }
            | Self::Method { name, .. } => name,
        }
    }

    fn kind(&self) -> DexPoolSymbolKind {
        match self {
            Self::String { .. } => DexPoolSymbolKind::String,
            Self::Type { .. } => DexPoolSymbolKind::Type,
            Self::Field { .. } => DexPoolSymbolKind::Field,
            Self::Method { .. } => DexPoolSymbolKind::Method,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DbpCodeTemplateSlot {
    name: String,
    offset: usize,
    width: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DbpCodeTemplate {
    bytes: Vec<u8>,
    slots: Vec<DbpCodeTemplateSlot>,
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
    /// Force a `Ljava/lang/String;`-returning method body to an existing
    /// constant string for every caller. The string must already be in the
    /// dex string pool, so no DEX id is added.
    MethodConstString {
        partition: String,
        file: String,
        class: String,
        method: String,
        #[serde(default = "default_string_proto")]
        proto: String,
        value: String,
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
    /// Apply an ordered, atomic set of same-length instruction-byte
    /// replacements inside one fully-qualified method body. Named symbols may
    /// materialize existing DEX pool indexes before exact matching.
    MethodCodePatch {
        partition: String,
        file: String,
        class: String,
        method: String,
        proto: String,
        #[serde(default, rename = "symbol")]
        symbols: Vec<DbpCodeSymbol>,
        #[serde(default, rename = "replacement")]
        replacements: Vec<DbpCodeReplacement>,
    },
    /// Redirect one encoded method's `code_off` to the existing code item of
    /// another symbolically selected, shape-compatible method.
    MethodCodeRedirect {
        partition: String,
        file: String,
        class: String,
        method: String,
        proto: String,
        donor_class: String,
        donor_method: String,
        donor_proto: String,
    },
    /// Hide one exact field-backed SwitchPreference controller entry by
    /// rewriting its `displayPreference(PreferenceScreen)` body in place.
    PreferenceControllerHide {
        partition: String,
        file: String,
        class: String,
        preference_key: String,
        preference_field: String,
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
    /// Replace an `otacerts.zip` with one that trusts only `cert` (a PEM or DER
    /// X.509 certificate; a relative path resolves against the `.dbp` file),
    /// rebuilt at the original byte size. update_engine, recovery and the
    /// framework's `RecoverySystem` then accept only OTAs signed with that
    /// certificate's key.
    OtaCert {
        partition: String,
        file: String,
        cert: String,
    },
    /// Replace the data of STORED zip entries with `payload` (whitespace-
    /// separated hex bytes), zero-padding to each entry's original data
    /// length, and fix the CRC32 in both headers. All `entries` must resolve
    /// or nothing is written. Size-preserving: the payload must fit inside
    /// every listed entry. Intended for neutralizing asset frames (e.g. boot
    /// animation PNGs) that have no code gate.
    ZipEntryReplace {
        partition: String,
        file: String,
        entries: Vec<String>,
        payload: String,
    },
    /// Collapse layout nodes with `android:id == node_id` inside `.xml`
    /// entries of a zip archive: `layout_height` (or `layout_weight`) goes
    /// to zero plus any vertical margins, so the node takes no space.
    /// Exactly `expected` nodes must be patched or nothing is written.
    /// Size-preserving: recompressed entries absorb slack in the local extra
    /// field, so the file length never changes.
    LayoutCollapse {
        partition: String,
        file: String,
        node_id: i32,
        #[serde(default = "default_expected_matches")]
        expected: usize,
    },
    /// Swap the `android:background` reference of layout nodes with
    /// `android:id == node_id` to `drawable`. Same size-preserving machinery
    /// as [`DbpOp::LayoutCollapse`]; exactly `expected` nodes must be patched.
    LayoutBackground {
        partition: String,
        file: String,
        node_id: i32,
        drawable: i32,
        #[serde(default = "default_expected_matches")]
        expected: usize,
    },
    /// Force `invoke-static target_class.target_method()Z` results to `value`
    /// inside `scan_class` (optionally one `scan_method` and zero-based site).
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
        #[serde(default)]
        site_index: Option<usize>,
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
            | DbpOp::MethodConstString { partition, .. }
            | DbpOp::MethodNop { partition, .. }
            | DbpOp::MethodCodePatch { partition, .. }
            | DbpOp::MethodCodeRedirect { partition, .. }
            | DbpOp::PreferenceControllerHide { partition, .. }
            | DbpOp::ResourceBool { partition, .. }
            | DbpOp::ResourceDimen { partition, .. }
            | DbpOp::TextReplace { partition, .. }
            | DbpOp::OtaCert { partition, .. }
            | DbpOp::ZipEntryReplace { partition, .. }
            | DbpOp::LayoutCollapse { partition, .. }
            | DbpOp::LayoutBackground { partition, .. }
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
            | DbpOp::MethodConstString { file, .. }
            | DbpOp::MethodNop { file, .. }
            | DbpOp::MethodCodePatch { file, .. }
            | DbpOp::MethodCodeRedirect { file, .. }
            | DbpOp::PreferenceControllerHide { file, .. }
            | DbpOp::ResourceBool { file, .. }
            | DbpOp::ResourceDimen { file, .. }
            | DbpOp::TextReplace { file, .. }
            | DbpOp::OtaCert { file, .. }
            | DbpOp::ZipEntryReplace { file, .. }
            | DbpOp::LayoutCollapse { file, .. }
            | DbpOp::LayoutBackground { file, .. }
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

    /// Ops that rewrite a regular file's bytes rather than an archive entry.
    fn is_raw_file_op(&self) -> bool {
        matches!(self, DbpOp::TextReplace { .. } | DbpOp::OtaCert { .. })
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
    let mut doc: DbpDocument =
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
            DbpOp::MethodConstString { proto, value, .. } => {
                validate_method_proto(
                    proto,
                    "Ljava/lang/String;",
                    "string (`Ljava/lang/String;`)",
                    &bail,
                )?;
                if value.is_empty() {
                    return Err(bail(
                        "method_const_string `value` must not be empty".to_string(),
                    ));
                }
            }
            DbpOp::MethodNop { proto, .. } => {
                validate_method_proto(proto, "V", "void (`V`)", &bail)?;
            }
            DbpOp::MethodCodePatch {
                class,
                method,
                proto,
                symbols,
                replacements,
                ..
            } => {
                if !class_descriptor_is_valid(class) {
                    return Err(bail(format!(
                        "method_code_patch `class` must be a JVM descriptor like `Lcom/x/Y;`, got `{class}`"
                    )));
                }
                if method.is_empty() {
                    return Err(bail(
                        "method_code_patch `method` must not be empty".to_string(),
                    ));
                }
                if !full_method_descriptor_is_valid(proto) {
                    return Err(bail(format!(
                        "method_code_patch `proto` is not a valid JVM descriptor: `{proto}`"
                    )));
                }
                if replacements.is_empty() {
                    return Err(bail(
                        "method_code_patch requires at least one `replacement`".to_string(),
                    ));
                }

                let mut symbol_by_name = BTreeMap::new();
                for symbol in symbols {
                    if !symbol_name_is_valid(symbol.name()) {
                        return Err(bail(format!(
                            "method_code_patch has invalid symbol name `{}`",
                            symbol.name()
                        )));
                    }
                    if symbol_by_name.insert(symbol.name(), symbol).is_some() {
                        return Err(bail(format!(
                            "method_code_patch has duplicate symbol `{}`",
                            symbol.name()
                        )));
                    }
                    match symbol {
                        DbpCodeSymbol::String { value, .. } => {
                            if value.contains('\0') {
                                return Err(bail(format!(
                                    "method_code_patch symbol `{}` contains an unsupported NUL",
                                    symbol.name()
                                )));
                            }
                        }
                        DbpCodeSymbol::Type { descriptor, .. } => {
                            if !field_descriptor_is_valid(descriptor) {
                                return Err(bail(format!(
                                    "method_code_patch symbol `{}` has invalid type descriptor `{descriptor}`",
                                    symbol.name()
                                )));
                            }
                        }
                        DbpCodeSymbol::Field {
                            class, field, ty, ..
                        } => {
                            if !class_descriptor_is_valid(class)
                                || field.is_empty()
                                || !field_descriptor_is_valid(ty)
                            {
                                return Err(bail(format!(
                                    "method_code_patch symbol `{}` has an invalid field descriptor",
                                    symbol.name()
                                )));
                            }
                        }
                        DbpCodeSymbol::Method {
                            class,
                            method,
                            proto,
                            ..
                        } => {
                            if !class_descriptor_is_valid(class)
                                || method.is_empty()
                                || !full_method_descriptor_is_valid(proto)
                            {
                                return Err(bail(format!(
                                    "method_code_patch symbol `{}` has an invalid method descriptor",
                                    symbol.name()
                                )));
                            }
                        }
                    }
                }

                let mut used_symbols = BTreeSet::new();
                for (index, replacement) in replacements.iter().enumerate() {
                    let from = parse_code_template(&replacement.from).map_err(|message| {
                        bail(format!(
                            "method_code_patch replacement {} `from`: {message}",
                            index + 1
                        ))
                    })?;
                    let to = parse_code_template(&replacement.to).map_err(|message| {
                        bail(format!(
                            "method_code_patch replacement {} `to`: {message}",
                            index + 1
                        ))
                    })?;
                    if replacement.expected == 0 {
                        return Err(bail(format!(
                            "method_code_patch replacement {} `expected` must be non-zero",
                            index + 1
                        )));
                    }
                    if from.bytes.is_empty()
                        || from.bytes.len() % 2 != 0
                        || from.bytes.len() != to.bytes.len()
                    {
                        return Err(bail(format!(
                            "method_code_patch replacement {} must be non-empty, code-unit aligned, and size-preserving ({} != {})",
                            index + 1,
                            from.bytes.len(),
                            to.bytes.len()
                        )));
                    }
                    if from == to {
                        return Err(bail(format!(
                            "method_code_patch replacement {} must change at least one byte",
                            index + 1
                        )));
                    }
                    for template in [&from, &to] {
                        let mut slots = Vec::with_capacity(template.slots.len());
                        for slot in &template.slots {
                            let Some(symbol) = symbol_by_name.get(slot.name.as_str()) else {
                                return Err(bail(format!(
                                    "method_code_patch replacement {} references undefined symbol `{}`",
                                    index + 1,
                                    slot.name
                                )));
                            };
                            used_symbols.insert(slot.name.clone());
                            slots.push(MethodCodeTemplateSlot {
                                offset: slot.offset,
                                width: slot.width,
                                kind: symbol.kind(),
                            });
                        }
                        validate_method_code_template_slots(&template.bytes, &slots).map_err(
                            |error| {
                                bail(format!(
                                    "method_code_patch replacement {}: {error}",
                                    index + 1
                                ))
                            },
                        )?;
                    }
                }
                for symbol in symbols {
                    if !used_symbols.contains(symbol.name()) {
                        return Err(bail(format!(
                            "method_code_patch has unused symbol `{}`",
                            symbol.name()
                        )));
                    }
                }
            }
            DbpOp::MethodCodeRedirect {
                class,
                method,
                proto,
                donor_class,
                donor_method,
                donor_proto,
                ..
            } => {
                for (label, class_name, method_name, method_proto) in [
                    ("target", class, method, proto),
                    ("donor", donor_class, donor_method, donor_proto),
                ] {
                    if !class_descriptor_is_valid(class_name)
                        || method_name.is_empty()
                        || !full_method_descriptor_is_valid(method_proto)
                    {
                        return Err(bail(format!(
                            "method_code_redirect `{label}` must specify a valid class, method, and prototype"
                        )));
                    }
                }
                let target_ret = parse_method_descriptor(proto)
                    .map(|(ret, _)| ret)
                    .ok_or_else(|| bail("invalid method_code_redirect target prototype".into()))?;
                let donor_ret = parse_method_descriptor(donor_proto)
                    .map(|(ret, _)| ret)
                    .ok_or_else(|| bail("invalid method_code_redirect donor prototype".into()))?;
                if target_ret != donor_ret {
                    return Err(bail(format!(
                        "method_code_redirect target and donor return types must match (`{target_ret}` != `{donor_ret}`)"
                    )));
                }
                if class == donor_class && method == donor_method && proto == donor_proto {
                    return Err(bail(
                        "method_code_redirect target and donor must be different methods".into(),
                    ));
                }
            }
            DbpOp::PreferenceControllerHide {
                class,
                preference_key,
                preference_field,
                ..
            } => {
                if !class_descriptor_is_valid(class) {
                    return Err(bail(format!(
                        "preference_controller_hide `class` must be a JVM descriptor like `Lcom/x/Y;`, got `{class}`"
                    )));
                }
                if preference_key.is_empty() || preference_key.contains('\0') {
                    return Err(bail(
                        "preference_controller_hide `preference_key` must be a non-empty DEX string"
                            .to_string(),
                    ));
                }
                if preference_field.is_empty() {
                    return Err(bail(
                        "preference_controller_hide `preference_field` must not be empty"
                            .to_string(),
                    ));
                }
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
            DbpOp::OtaCert { cert, .. } => {
                if cert.trim().is_empty() {
                    return Err(bail(
                        "ota_cert `cert` must name a certificate file".to_string(),
                    ));
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
            DbpOp::ZipEntryReplace {
                entries, payload, ..
            } => {
                if entries.is_empty() {
                    return Err(bail(
                        "zip_entry_replace `entries` must not be empty".to_string(),
                    ));
                }
                let mut seen = BTreeSet::new();
                for entry in entries {
                    if entry.is_empty() || entry.contains('\0') {
                        return Err(bail(
                            "zip_entry_replace `entries` must be non-empty zip paths".to_string(),
                        ));
                    }
                    if !seen.insert(entry) {
                        return Err(bail(format!(
                            "zip_entry_replace lists duplicate entry `{entry}`"
                        )));
                    }
                }
                let parsed = parse_code_template(payload)
                    .map_err(|message| bail(format!("zip_entry_replace `payload`: {message}")))?;
                if !parsed.slots.is_empty() {
                    return Err(bail(
                        "zip_entry_replace `payload` must be plain hex bytes (no ${slots})"
                            .to_string(),
                    ));
                }
                if parsed.bytes.is_empty() {
                    return Err(bail(
                        "zip_entry_replace `payload` must not be empty".to_string(),
                    ));
                }
            }
            DbpOp::LayoutCollapse {
                node_id, expected, ..
            } => {
                if *node_id <= 0 {
                    return Err(bail(
                        "layout_collapse `node_id` must be a positive resource id".to_string(),
                    ));
                }
                if *expected == 0 {
                    return Err(bail(
                        "layout_collapse `expected` must be non-zero".to_string(),
                    ));
                }
            }
            DbpOp::LayoutBackground {
                node_id,
                drawable,
                expected,
                ..
            } => {
                if *node_id <= 0 {
                    return Err(bail(
                        "layout_background `node_id` must be a positive resource id".to_string(),
                    ));
                }
                if *drawable <= 0 {
                    return Err(bail(
                        "layout_background `drawable` must be a positive resource id".to_string(),
                    ));
                }
                if *expected == 0 {
                    return Err(bail(
                        "layout_background `expected` must be non-zero".to_string(),
                    ));
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
    resolve_ota_certs(path, &mut doc)?;
    Ok(doc)
}

/// Resolve each `ota_cert` path against the `.dbp` file's directory and check
/// it parses, so a bad certificate fails before any image is touched.
fn resolve_ota_certs(dbp_path: &Path, doc: &mut DbpDocument) -> Result<()> {
    let base = dbp_path.parent().unwrap_or(Path::new(""));
    for op in &mut doc.ops {
        let DbpOp::OtaCert { cert, .. } = op else {
            continue;
        };
        let resolved = base.join(&*cert);
        dynobox_ota::Certificate::load(&resolved).with_context(|| {
            format!(
                "{}: patch `{}`: ota_cert `cert`",
                dbp_path.display(),
                doc.name
            )
        })?;
        *cert = resolved.to_string_lossy().into_owned();
    }
    Ok(())
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

fn parse_code_template(value: &str) -> std::result::Result<DbpCodeTemplate, String> {
    let mut bytes = Vec::new();
    let mut slots = Vec::new();
    for token in value.split_ascii_whitespace() {
        if let Some(body) = token
            .strip_prefix("${")
            .and_then(|body| body.strip_suffix('}'))
        {
            let Some((name, width)) = body.split_once(':') else {
                return Err(format!(
                    "invalid symbol placeholder `{token}` (expected `${{name:u16}}` or `${{name:u32}}`)"
                ));
            };
            if !symbol_name_is_valid(name) {
                return Err(format!(
                    "invalid symbol name `{name}` in placeholder `{token}`"
                ));
            }
            let width = match width {
                "u16" => 2,
                "u32" => 4,
                _ => {
                    return Err(format!(
                        "invalid symbol width in `{token}` (expected u16 or u32)"
                    ));
                }
            };
            slots.push(DbpCodeTemplateSlot {
                name: name.to_string(),
                offset: bytes.len(),
                width,
            });
            bytes.resize(bytes.len() + width, 0);
        } else {
            if token.len() != 2 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(format!(
                    "invalid byte `{token}` (expected two hexadecimal digits or a symbol placeholder)"
                ));
            }
            bytes.push(
                u8::from_str_radix(token, 16)
                    .map_err(|_| format!("invalid hexadecimal byte `{token}`"))?,
            );
        }
    }
    Ok(DbpCodeTemplate { bytes, slots })
}

fn symbol_name_is_valid(name: &str) -> bool {
    let mut bytes = name.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z' | b'A'..=b'Z' | b'_'))
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn class_descriptor_is_valid(descriptor: &str) -> bool {
    descriptor.starts_with('L')
        && descriptor.ends_with(';')
        && descriptor.len() > 2
        && !descriptor.bytes().any(|byte| byte.is_ascii_whitespace())
}

fn field_descriptor_is_valid(descriptor: &str) -> bool {
    parse_method_descriptor(&format!("({descriptor})V"))
        .is_some_and(|(ret, params)| ret == "V" && params == [descriptor])
}

fn full_method_descriptor_is_valid(descriptor: &str) -> bool {
    parse_method_descriptor(descriptor).is_some_and(|(ret, params)| {
        (ret == "V" || field_descriptor_is_valid(&ret))
            && params.iter().all(|param| field_descriptor_is_valid(param))
    })
}

fn resolve_code_symbol(dex: &[u8], symbol: &DbpCodeSymbol) -> Result<Option<u32>> {
    match symbol {
        DbpCodeSymbol::String { value, .. } => {
            resolve_dex_pool_symbol(dex, DexPoolSymbol::String(value))
        }
        DbpCodeSymbol::Type { descriptor, .. } => {
            resolve_dex_pool_symbol(dex, DexPoolSymbol::Type(descriptor))
        }
        DbpCodeSymbol::Field {
            class, field, ty, ..
        } => resolve_dex_pool_symbol(
            dex,
            DexPoolSymbol::Field {
                class,
                name: field,
                ty,
            },
        ),
        DbpCodeSymbol::Method {
            class,
            method,
            proto,
            ..
        } => {
            let (ret, params) = parse_method_descriptor(proto)
                .ok_or_else(|| anyhow!("invalid descriptor `{proto}`"))?;
            let param_refs: Vec<&str> = params.iter().map(String::as_str).collect();
            resolve_dex_pool_symbol(
                dex,
                DexPoolSymbol::Method {
                    class,
                    name: method,
                    ret: &ret,
                    params: &param_refs,
                },
            )
        }
    }
}

fn materialize_code_template(
    template: &DbpCodeTemplate,
    symbols: &BTreeMap<String, u32>,
) -> Result<Option<Vec<u8>>> {
    let mut bytes = template.bytes.clone();
    for slot in &template.slots {
        let Some(&index) = symbols.get(&slot.name) else {
            return Err(anyhow!("unresolved method-code symbol `{}`", slot.name));
        };
        match slot.width {
            2 => {
                let Ok(index) = u16::try_from(index) else {
                    return Ok(None);
                };
                bytes[slot.offset..slot.offset + 2].copy_from_slice(&index.to_le_bytes());
            }
            4 => {
                bytes[slot.offset..slot.offset + 4].copy_from_slice(&index.to_le_bytes());
            }
            width => return Err(anyhow!("unsupported method-code symbol width {width}")),
        }
    }
    Ok(Some(bytes))
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
    /// Whether the declared path exists as a regular file in the partition.
    pub target_found: bool,
    /// Number of ops that landed at least one site.
    pub ops_applied: usize,
    /// Number of ops that found no target (skipped, not an error).
    pub ops_skipped: usize,
    /// APK/JAR entry names or raw-file markers that were modified.
    pub patched_entries: Vec<String>,
}

/// Apply every op targeting `partition_name` (across `docs`) inside
/// `image_path`. Ops are grouped by file so each target is opened, patched, and
/// written back once. Returns one result per declared target so callers can
/// distinguish a missing image path from a present file whose size-preserving
/// operations did not land.
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
        let result = apply_ops_to_file(image_path, &file, &ops)?.unwrap_or(DbpFileResult {
            file,
            target_found: false,
            ops_applied: 0,
            ops_skipped: ops.len(),
            patched_entries: Vec::new(),
        });
        results.push(result);
    }
    Ok(results)
}

fn apply_ops_to_file(
    image_path: &Path,
    file: &str,
    ops: &[&DbpOp],
) -> Result<Option<DbpFileResult>> {
    if crate::bootimg::is_boot_image(image_path)? {
        return apply_boot_image_ops(image_path, file, ops);
    }
    let has_raw_ops = ops.iter().any(|op| op.is_raw_file_op());
    if has_raw_ops && !ops.iter().all(|op| op.is_raw_file_op()) {
        return Err(anyhow!(
            "{file} mixes raw-file ops (text_replace, ota_cert) with archive patch ops; \
             split them into separate files"
        ));
    }
    if has_raw_ops {
        apply_raw_file_ops(image_path, file, ops)
    } else {
        apply_ops_to_apk(image_path, file, ops)
    }
}

/// File bytes, their extent runs, and the volume block size.
type Ext4FileContents = (Vec<u8>, Vec<ExtentRun>, u64);

fn read_file_from_ext4(image_path: &Path, file: &str) -> Result<Option<Ext4FileContents>> {
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

fn apply_raw_file_ops(
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

    let original = bytes.clone();
    let mut op_landed = vec![false; ops.len()];
    for (i, op) in ops.iter().enumerate() {
        op_landed[i] = match op {
            DbpOp::TextReplace { from, to, all, .. } => {
                patch_text_replacement(&mut bytes, from.as_bytes(), to.as_bytes(), *all) > 0
            }
            DbpOp::OtaCert { cert, .. } => {
                replace_otacerts(&mut bytes, Path::new(cert))
                    .with_context(|| format!("ota_cert on {file}"))?;
                true
            }
            _ => unreachable!("caller filtered archive ops"),
        };
    }

    let ops_applied = op_landed.iter().filter(|&&b| b).count();
    if bytes != original {
        write_via_extents(image_path, &bytes, &extents, block_size)?;
    }
    Ok(Some(DbpFileResult {
        file: file.to_string(),
        target_found: true,
        ops_applied,
        ops_skipped: ops.len() - ops_applied,
        patched_entries: if ops_applied > 0 {
            vec!["raw bytes".to_string()]
        } else {
            Vec::new()
        },
    }))
}

/// `ota_cert` on a boot image (e.g. `recovery`): rewrite the bundle inside
/// its ramdisk, which recovery uses to verify sideloaded OTAs.
fn apply_boot_image_ops(
    image_path: &Path,
    file: &str,
    ops: &[&DbpOp],
) -> Result<Option<DbpFileResult>> {
    if ops.iter().any(|op| !matches!(op, DbpOp::OtaCert { .. })) {
        return Err(anyhow!(
            "{}: only ota_cert can patch a file inside a boot image ramdisk",
            image_path.display()
        ));
    }
    let found = crate::bootimg::edit_ramdisk_file(image_path, file, |bytes| {
        for op in ops {
            if let DbpOp::OtaCert { cert, .. } = op {
                replace_otacerts(bytes, Path::new(cert))
                    .with_context(|| format!("ota_cert on ramdisk {file}"))?;
            }
        }
        Ok(())
    })?;
    if !found {
        return Ok(None);
    }
    Ok(Some(DbpFileResult {
        file: file.to_string(),
        target_found: true,
        ops_applied: ops.len(),
        ops_skipped: 0,
        patched_entries: vec!["ramdisk".to_string()],
    }))
}

/// Rebuild `bytes` (an existing `otacerts.zip`) as a same-size bundle that
/// trusts only the certificate at `cert_path`. Refuses a file that is not a
/// certificate bundle, so a mistyped `file` cannot clobber unrelated data.
fn replace_otacerts(bytes: &mut Vec<u8>, cert_path: &Path) -> Result<()> {
    dynobox_ota::otacerts::read_certificates(bytes)
        .context("target is not an otacerts.zip certificate bundle")?;
    let cert = dynobox_ota::Certificate::load(cert_path)?;
    *bytes = dynobox_ota::otacerts::build_with_size(&cert, bytes.len())?;
    Ok(())
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
        .filter(|e| e.is_classes_dex())
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

    // Whole-archive zip ops run against the full file bytes rather than
    // individual dex slices.
    for (i, op) in ops.iter().enumerate() {
        let DbpOp::ZipEntryReplace {
            entries, payload, ..
        } = op
        else {
            continue;
        };
        let template = parse_code_template(payload)
            .map_err(|message| anyhow!("zip_entry_replace `payload`: {message}"))?;
        if force_zip_entry_replace(&mut apk_bytes, entries, &template.bytes)? {
            op_landed[i] = true;
            patched_entries.extend(entries.iter().cloned());
        }
    }

    // Binary-XML layout ops run against the same whole-archive bytes.
    for (i, op) in ops.iter().enumerate() {
        let (landed, label) = match op {
            DbpOp::LayoutCollapse {
                node_id, expected, ..
            } => (
                force_axml_collapse(&mut apk_bytes, *node_id as u32, *expected)?,
                format!("axml-collapse:{node_id:#x}"),
            ),
            DbpOp::LayoutBackground {
                node_id,
                drawable,
                expected,
                ..
            } => (
                force_axml_background(
                    &mut apk_bytes,
                    *node_id as u32,
                    *drawable as u32,
                    *expected,
                )?,
                format!("axml-background:{node_id:#x}"),
            ),
            _ => (false, String::new()),
        };
        if landed {
            op_landed[i] = true;
            patched_entries.push(label);
        }
    }

    let ops_applied = op_landed.iter().filter(|&&b| b).count();
    if ops_applied > 0 {
        write_via_extents(image_path, &apk_bytes, &apk_extents, block_size)?;
    }
    Ok(Some(DbpFileResult {
        file: file.to_string(),
        target_found: true,
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
        DbpOp::MethodConstString {
            class,
            method,
            proto,
            value,
            ..
        } => {
            let (ret, params) = parse_method_descriptor(proto)
                .ok_or_else(|| anyhow!("invalid descriptor `{proto}`"))?;
            let param_refs: Vec<&str> = params.iter().map(String::as_str).collect();
            force_method_return_const_string(dex, class, method, &ret, &param_refs, value)
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
        DbpOp::MethodCodePatch {
            class,
            method,
            proto,
            symbols,
            replacements,
            ..
        } => {
            let (ret, params) = parse_method_descriptor(proto)
                .ok_or_else(|| anyhow!("invalid descriptor `{proto}`"))?;
            let param_refs: Vec<&str> = params.iter().map(String::as_str).collect();
            let mut resolved_symbols = BTreeMap::new();
            for symbol in symbols {
                let Some(index) = resolve_code_symbol(dex, symbol)? else {
                    return Ok(false);
                };
                resolved_symbols.insert(symbol.name().to_string(), index);
            }
            let mut decoded = Vec::with_capacity(replacements.len());
            for replacement in replacements {
                let from = parse_code_template(&replacement.from).map_err(anyhow::Error::msg)?;
                let to = parse_code_template(&replacement.to).map_err(anyhow::Error::msg)?;
                let Some(from) = materialize_code_template(&from, &resolved_symbols)? else {
                    return Ok(false);
                };
                let Some(to) = materialize_code_template(&to, &resolved_symbols)? else {
                    return Ok(false);
                };
                decoded.push((from, to, replacement.expected));
            }
            let code_replacements: Vec<MethodCodeReplacement<'_>> = decoded
                .iter()
                .map(|(from, to, expected)| MethodCodeReplacement {
                    from,
                    to,
                    expected: *expected,
                })
                .collect();
            patch_method_code(dex, class, method, &ret, &param_refs, &code_replacements)
        }
        DbpOp::MethodCodeRedirect {
            class,
            method,
            proto,
            donor_class,
            donor_method,
            donor_proto,
            ..
        } => {
            let (target_ret, target_params) = parse_method_descriptor(proto)
                .ok_or_else(|| anyhow!("invalid descriptor `{proto}`"))?;
            let (donor_ret, donor_params) = parse_method_descriptor(donor_proto)
                .ok_or_else(|| anyhow!("invalid descriptor `{donor_proto}`"))?;
            let target_param_refs: Vec<&str> = target_params.iter().map(String::as_str).collect();
            let donor_param_refs: Vec<&str> = donor_params.iter().map(String::as_str).collect();
            redirect_method_code(
                dex,
                DexMethodRef {
                    class,
                    name: method,
                    ret: &target_ret,
                    params: &target_param_refs,
                },
                DexMethodRef {
                    class: donor_class,
                    name: donor_method,
                    ret: &donor_ret,
                    params: &donor_param_refs,
                },
            )
        }
        DbpOp::PreferenceControllerHide {
            class,
            preference_key,
            preference_field,
            ..
        } => force_preference_controller_hidden(dex, class, preference_key, preference_field),
        DbpOp::InvokeConstBool {
            scan_class,
            scan_method,
            target_class,
            target_method,
            proto,
            site_index,
            value,
            ..
        } => {
            let (ret, params) = parse_method_descriptor(proto)
                .ok_or_else(|| anyhow!("invalid descriptor `{proto}`"))?;
            let param_refs: Vec<&str> = params.iter().map(String::as_str).collect();
            let sites = if let Some(site_index) = site_index {
                force_invoke_const_bool_at(
                    dex,
                    scan_class,
                    scan_method.as_deref(),
                    target_class,
                    target_method,
                    &ret,
                    &param_refs,
                    *value,
                    *site_index,
                )?
            } else {
                force_invoke_const_bool(
                    dex,
                    scan_class,
                    scan_method.as_deref(),
                    target_class,
                    target_method,
                    &ret,
                    &param_refs,
                    *value,
                )?
            };
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
        DbpOp::TextReplace { .. } | DbpOp::OtaCert { .. } => Ok(false),
        // File-level ops: handled against whole-archive bytes in
        // `apply_ops_to_apk`, never against a dex slice.
        DbpOp::ZipEntryReplace { .. } => Ok(false),
        DbpOp::LayoutCollapse { .. } | DbpOp::LayoutBackground { .. } => Ok(false),
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
#[path = "dbp_tests.rs"]
mod tests;
