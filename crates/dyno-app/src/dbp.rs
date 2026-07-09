//! `.dbp` (DynoBox Patch) files: external, user-authorable TOML patches
//! applied to APKs inside partition images during resign (`--plus`).
//!
//! A `.dbp` document names a set of size-preserving Dalvik bytecode ops.
//! Each op targets one archive inside one partition image and forces a method
//! or invocation result to a constant, using the [`crate::dex_patch`]
//! primitives. This is how DynoBox ships the former built-in "clean-launcher"
//! and ZuiSettings locale patches as data instead of code.
//!
//! Example:
//!
//! ```toml
//! name = "clean-launcher"
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
use serde::Deserialize;

use crate::dex_patch::{
    force_invoke_const_bool, force_method_return_bool, force_method_return_int,
    parse_method_descriptor,
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

/// A parsed `.dbp` document.
#[derive(Debug, Clone, Deserialize)]
pub struct DbpDocument {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default, rename = "op")]
    pub ops: Vec<DbpOp>,
}

/// One patch operation. `kind` selects the dex-patch primitive.
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
}

impl DbpOp {
    pub fn partition(&self) -> &str {
        match self {
            DbpOp::MethodConstBool { partition, .. }
            | DbpOp::MethodConstInt { partition, .. }
            | DbpOp::InvokeConstBool { partition, .. } => partition,
        }
    }

    pub fn file(&self) -> &str {
        match self {
            DbpOp::MethodConstBool { file, .. }
            | DbpOp::MethodConstInt { file, .. }
            | DbpOp::InvokeConstBool { file, .. } => file,
        }
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
        let (proto, expected_ret, expected_name) = match op {
            DbpOp::MethodConstBool { proto, .. } | DbpOp::InvokeConstBool { proto, .. } => {
                (proto, "Z", "boolean (`Z`)")
            }
            DbpOp::MethodConstInt { proto, .. } => (proto, "I", "integer (`I`)"),
        };
        // Reject a mismatched return type up front so a whole `.dbp` is
        // all-or-nothing instead of failing after earlier ops modified images.
        match parse_method_descriptor(proto) {
            Some((ret, _)) if ret == expected_ret => {}
            Some(_) => {
                return Err(bail(format!(
                    "op descriptor `{proto}` must return {expected_name}"
                )));
            }
            None => {
                return Err(bail(format!("invalid method descriptor `{proto}`")));
            }
        }
    }
    Ok(doc)
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

/// Per-file result of applying the ops that targeted one APK.
#[derive(Debug, Clone)]
pub struct DbpFileResult {
    /// Path of the APK inside the partition image.
    pub file: String,
    /// Number of ops that landed at least one site.
    pub ops_applied: usize,
    /// Number of ops that found no target (skipped, not an error).
    pub ops_skipped: usize,
    /// `classes*.dex` entry names that were modified.
    pub dex_entries: Vec<String>,
}

/// Apply every op targeting `partition_name` (across `docs`) to its APK
/// inside `image_path`. Ops are grouped by file so each APK is opened,
/// patched, and written back once. Returns one result per patched file, or an
/// empty vec when nothing landed (partition left untouched).
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
        if let Some(result) = apply_ops_to_apk(image_path, &file, &ops)? {
            results.push(result);
        }
    }
    Ok(results)
}

/// Open `file` inside `image_path`, apply `ops` to its STORED `classes*.dex`
/// entries in place, recompute dex sums + zip CRC, and write the APK back over
/// its ext4 extents. Returns `None` when the file is absent or no op landed.
fn apply_ops_to_apk(
    image_path: &Path,
    file: &str,
    ops: &[&DbpOp],
) -> Result<Option<DbpFileResult>> {
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
    let (mut apk_bytes, apk_extents) = inode
        .open_read_with_extents(&mut volume)
        .map_err(|e| anyhow!("Failed to read {file} from {}: {e}", image_path.display()))?;
    let block_size = volume.block_size;
    drop(volume);
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

    // Track, per op, whether it landed anywhere across the APK's dexes.
    let mut op_landed = vec![false; ops.len()];
    let mut patched_dex_entries: Vec<String> = Vec::new();

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
            patched_dex_entries.push(entry.name.clone());
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
        dex_entries: patched_dex_entries,
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
    }
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
        let cl = load_dbp(&patches_dir().join("clean-launcher.dbp")).expect("clean-launcher.dbp");
        assert_eq!(cl.name, "clean-launcher");
        assert_eq!(cl.ops.len(), 3);
        let zs = load_dbp(&patches_dir().join("zuisettings-locale.dbp"))
            .expect("zuisettings-locale.dbp");
        assert_eq!(zs.name, "zuisettings-locale");
        assert_eq!(zs.ops.len(), 22);
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
                assert_eq!(class, "Lcom/android/server/policy/PhoneWindowManager;");
                assert_eq!(method, "getResolvedLongPressOnPowerBehavior");
                assert_eq!(proto, "()I");
                assert_eq!(*value, 1);
            }
            _ => panic!("power-menu must use method_const_int"),
        }
    }

    /// Apply the bundled clean-launcher ops to the real ZuiLauncher dexes.
    /// Set `DYNOBOX_ZUILAUNCHER_DEX_DIR`.
    #[test]
    fn bundled_clean_launcher_lands_on_real_dex() {
        let Ok(dir) = std::env::var("DYNOBOX_ZUILAUNCHER_DEX_DIR") else {
            return;
        };
        let doc = load_dbp(&patches_dir().join("clean-launcher.dbp")).unwrap();
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
        assert_eq!(landed, 3, "all three clean-launcher ops should land");
    }

    /// Apply the bundled ZuiSettings ops to the real ZuiSettings dexes.
    /// Set `DYNOBOX_ZUISETTINGS_DEX_DIR`.
    #[test]
    fn bundled_zuisettings_lands_on_real_dex() {
        let Ok(dir) = std::env::var("DYNOBOX_ZUISETTINGS_DEX_DIR") else {
            return;
        };
        let doc = load_dbp(&patches_dir().join("zuisettings-locale.dbp")).unwrap();
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

    /// Apply the bundled power-menu op to a real services.jar/APK dump.
    /// Set `DYNOBOX_SERVICES_ARCHIVE`.
    #[test]
    fn bundled_power_menu_lands_on_real_services() {
        let Ok(path) = std::env::var("DYNOBOX_SERVICES_ARCHIVE") else {
            return;
        };
        let archive = std::fs::read(path).expect("read services archive");
        let zip = parse_zip_central_directory(&archive).expect("parse services archive");
        let doc = load_dbp(&patches_dir().join("power-menu.dbp")).unwrap();
        let mut landed = 0usize;
        for entry in zip.entries.iter().filter(|entry| {
            entry.name.ends_with(".dex")
                && entry.compression_method == 0
                && !entry.uses_data_descriptor
                && !entry.is_zip64
                && entry.data_start + entry.compressed_size <= archive.len()
        }) {
            let mut dex =
                archive[entry.data_start..entry.data_start + entry.compressed_size].to_vec();
            for op in &doc.ops {
                if apply_one_op(&mut dex, op).unwrap() {
                    landed += 1;
                }
            }
        }
        assert_eq!(
            landed, 1,
            "the power-menu method rewrite should land exactly once"
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
}
