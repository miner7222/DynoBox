//! Per-feature toggle for Lenovo's LGSI feature flags inside `system.img`.
//!
//! Lenovo's `com/lgsi/config/LgsiFeatures.<clinit>` registers each LGSI
//! feature by constructing a `LgsiFeatureInfo(name, mIsRoot, mIsActive)`
//! and stuffing it into a registry. The on-disk Dalvik encoding for each
//! registration is a `const-string` followed immediately by an
//! `invoke-direct {v1, v2, vE, vF}` against `LgsiFeatureInfo.<init>`,
//! where `vE` and `vF` are the boolean register fields. With the
//! constructor pinned to `(Ljava/lang/String;ZZ)V` the two boolean
//! arguments map to the F|E nibble pair of the invoke-direct opcode.
//! Toggling a feature on or off is a single-nibble byte rewrite at that
//! position, swapping the bool register from the false-holding register
//! to the true-holding one (or vice versa).
//!
//! `--fuck-as` shipped this concept for a single hard-coded feature
//! (`ZuiAntiCrossSell`). `--fuck-lgsi` generalises it: the OEM ships a
//! human-readable manifest at `product.img/etc/lgsi_build_info.html`
//! listing every feature with its current `Enabled` state. We extract
//! that html, render its feature list as a tiny JSON object the user
//! can hand-edit, then patch only the deltas back into the dex.
//!
//! End-to-end (interactive mode):
//!   1. ext4-walk `system.img` -> `/system/framework/framework.jar`.
//!   2. ext4-walk `product.img` -> `/etc/lgsi_build_info.html`.
//!   3. Parse the HTML's `featureData` JS array into
//!      `[(name, enabled), ...]`.
//!   4. Walk each `classes*.dex` inside the jar; locate the dex that
//!      carries `Lcom/lgsi/config/LgsiFeatures;`, find its `<clinit>`,
//!      and scan its bytecode for every
//!      `invoke-direct {…}, LgsiFeatureInfo.<init>` site.
//!   5. Walk `<clinit>` linearly with a register tracker that records
//!      `const/4` / `const/16` / `const` writes producing 0 or 1, and
//!      invalidates entries on any other write to a tracked register.
//!      For every invoke-direct site, snapshot the E and F nibble
//!      registers and the bool currently held in each.
//!   6. Cross-reference the dex E-bool / F-bool against the HTML
//!      `enabled` column for the same feature. The position where the
//!      bool consistently matches the HTML state is the "Enabled" nibble.
//!      Require ≥90 % match across ≥8 cross-referable features; smaller
//!      or more ambiguous samples bail loud.
//!   7. Write the workspace artifacts under `<out>`:
//!        - `lgsi_features.json` — `{name -> enabled}` object map in
//!          HTML order, generated from the HTML.
//!        - `lgsi_build_info.html` — verbatim copy of the file pulled
//!          from product.img, kept as the human-readable reference.
//!   8. Print the absolute paths and "Edit JSON, then press Enter to
//!      continue (Ctrl-C to abort)". Block on stdin.
//!   9. Re-read the JSON. JSON parse error -> print and re-prompt; loop
//!      until valid.
//!  10. Diff against the original HTML state. 0 changes -> return
//!      `NotApplicable` (skip dex patch + verity regen).
//!  11. For each changed feature, patch the F|E byte's "Enabled" nibble
//!      from the current bool register's number to the opposite bool
//!      register's number, in the in-memory `jar_bytes` buffer.
//!  12. Recompute the dex header SHA-1 (covers bytes 32..) and Adler-32
//!      (covers bytes 12..); recompute jar CRC32 (LFH + CD).
//!  13. write_via_extents the patched jar back to system.img.
//!  14. Regenerate dm-verity hash tree on system.img; patch the
//!      Hashtree descriptor's `root_digest` on system.img and
//!      vbmeta_system.img. Resign loop refreshes the vbmeta signature.
//!  15. Optionally remove the workspace files (`--fuck-lgsi-cleanup`).
//!
//! Scripted mode (`--fuck-lgsi-config <path>`) skips steps 7–9: the
//! caller-supplied JSON is read from the given path. Steps 1–6 still run
//! so we know the dex layout + cross-ref. Steps 10–14 still run.
//!
//! FEC blocks on `system.img` are intentionally untouched — same
//! trade-off as `vendor_spl` and the previous `--fuck-as`. dm-verity
//! validates against `root_digest`; FEC is an optional recovery code
//! and stale FEC does not break boot.

use std::collections::HashMap;
use std::io::{self, IsTerminal, Read as _};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use memchr::memmem;

use crate::avb_descriptor::{
    SHA256_DIGEST_SIZE, VerityProgressCallback, hex_encode, patch_hashtree_root_digest,
    read_hashtree_params, regenerate_hashtree_with_progress,
};
use crate::ext4_helpers::{lookup_inode_at_path, open_ext4_volume, write_via_extents};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const LGSI_FEATURES_CLASS: &str = "Lcom/lgsi/config/LgsiFeatures;";
const LGSI_FEATURE_INFO_CLASS: &str = "Lcom/lgsi/config/LgsiFeatureInfo;";
const LGSI_FEATURE_INFO_INIT_NAME: &str = "<init>";
const LGSI_FEATURE_INFO_INIT_PROTO: &str = "(Ljava/lang/String;ZZ)V";

const SYSTEM_PARTITION: &str = "system";
const FRAMEWORK_JAR_PATH: &[&str] = &["system", "framework", "framework.jar"];
const PRODUCT_HTML_PATH: &[&str] = &["etc", "lgsi_build_info.html"];

pub const WORKSPACE_JSON_NAME: &str = "lgsi_features.json";
pub const WORKSPACE_HTML_NAME: &str = "lgsi_build_info.html";

/// Minimum cross-referable features required before the E-vs-F nibble
/// vote is allowed to run. Smaller samples bail with "too few cross
/// referable features".
const CROSS_REF_MIN_FEATURES: usize = 8;

/// Required match ratio for the winning nibble (E or F) against HTML's
/// `enabled` column.
const CROSS_REF_MATCH_RATIO: f64 = 0.90;

// ---------------------------------------------------------------------------
// Public surface
// ---------------------------------------------------------------------------

/// Outcome of an attempted `--fuck-lgsi` pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FuckLgsiOutcome {
    /// One or more features were patched. `system.img` and
    /// `vbmeta_system.img` were updated. Caller (resign loop) must
    /// re-sign vbmeta_system.
    Patched {
        applied: Vec<LgsiFeatureChange>,
        skipped: Vec<LgsiFeatureSkip>,
        old_root_digest: String,
        new_root_digest: String,
    },
    /// 0 features changed (user made no edits, framework.jar was
    /// missing, or all candidates were skipped). `system.img` /
    /// `vbmeta_system.img` were not touched.
    NotApplicable { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LgsiFeatureChange {
    pub name: String,
    pub from: bool,
    pub to: bool,
    /// JAR-relative byte offset of the patched invoke-direct opcode.
    pub invoke_direct_offset_in_jar: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LgsiFeatureSkip {
    pub name: String,
    pub reason: SkipReason,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SkipReason {
    /// JSON entry's name wasn't in the dex.
    NotInDex,
    /// HTML entry's name wasn't in the dex (no patch attempted).
    NotInDexFromHtml,
    /// Dex entry's name wasn't in the HTML (no JSON entry to compare).
    NotInHtml,
    /// Dex entry's E and F bool tracker came up unknown — couldn't
    /// safely flip a nibble.
    UnknownDexBool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FuckLgsiMode {
    /// Write workspace files, block on stdin Enter, re-read JSON.
    Interactive,
    /// Read pre-edited JSON from this path; no pause.
    Config(PathBuf),
}

pub struct FuckLgsiInput<'a> {
    pub system_image: &'a Path,
    pub vbmeta_system_image: &'a Path,
    pub product_image: &'a Path,
    pub workspace_dir: &'a Path,
    pub mode: FuckLgsiMode,
}

/// Apply `--fuck-lgsi` to a freshly unpacked `system.img` and propagate
/// the new dm-verity root digest to `vbmeta_system.img`.
///
/// Equivalent to [`apply_fuck_lgsi_with_progress`] called with
/// `verity_progress = None`.
pub fn apply_fuck_lgsi(input: &FuckLgsiInput<'_>) -> Result<FuckLgsiOutcome> {
    apply_fuck_lgsi_with_progress(input, None)
}

/// Like [`apply_fuck_lgsi`] but invokes `verity_progress` with
/// per-leaf-block delta byte counts during dm-verity regeneration on
/// `system.img`. The other phases (ext4 walks, JAR byte patches, AVB
/// descriptor rewrites) all run sub-second; only the SHA-256 walk over a
/// ~12 GiB system.img is long enough to need a progress bar.
pub fn apply_fuck_lgsi_with_progress(
    input: &FuckLgsiInput<'_>,
    verity_progress: Option<VerityProgressCallback>,
) -> Result<FuckLgsiOutcome> {
    // 1. Read framework.jar (with extents) from system.img.
    let mut volume = open_ext4_volume(input.system_image)?;
    let inode = match lookup_inode_at_path(&mut volume, FRAMEWORK_JAR_PATH)? {
        Some(i) => i,
        None => {
            return Ok(FuckLgsiOutcome::NotApplicable {
                reason: "/system/framework/framework.jar not found in system.img".to_string(),
            });
        }
    };
    if !inode.is_file() {
        return Err(anyhow!(
            "system.img /system/framework/framework.jar is not a regular file"
        ));
    }
    let (mut jar_bytes, jar_extents) = inode
        .open_read_with_extents(&mut volume)
        .map_err(|e| anyhow!("Failed to read framework.jar from system.img: {e}"))?;
    let block_size = volume.block_size;
    drop(volume);
    if jar_extents.is_empty() {
        return Err(anyhow!(
            "framework.jar has no extents (inline data not supported here)"
        ));
    }

    // 2. Read /etc/lgsi_build_info.html from product.img.
    let html_bytes = read_lgsi_build_info_html(input.product_image)?;

    // 3. Parse HTML feature list.
    let html_features = html_parser::parse_lgsi_html(&html_bytes)
        .context("failed to parse lgsi_build_info.html")?;

    // 4. Locate framework.jar dex carrying the LgsiFeatures *class
    //    definition* + the registration sites. Multiple dexes may
    //    reference `Lcom/lgsi/config/LgsiFeatures;` as a type without
    //    actually defining it (other classes call into LgsiFeatures);
    //    only one dex carries the class_def + the populated `<clinit>`.
    //    Iterate every dex that mentions the descriptor string and pick
    //    the first one whose dex walker returns a non-empty feature
    //    list.
    let zip = parse_zip_central_directory(&jar_bytes)?;
    let candidate_dex_entries = collect_lgsi_features_candidate_dexes(&jar_bytes, &zip)?;
    if candidate_dex_entries.is_empty() {
        return Ok(FuckLgsiOutcome::NotApplicable {
            reason: format!(
                "no `{LGSI_FEATURES_CLASS}` class found in framework.jar; \
                 different ROM build or refactored class"
            ),
        });
    }

    let mut chosen: Option<(ZipEntry, Vec<dex_walker::DexFeature>)> = None;
    let mut per_dex_diagnostics: Vec<String> = Vec::with_capacity(candidate_dex_entries.len());
    for entry in &candidate_dex_entries {
        let dex_data_end = entry.data_start + entry.compressed_size;
        let dex_bytes = &jar_bytes[entry.data_start..dex_data_end];
        match dex_walker::extract_lgsi_features(dex_bytes)? {
            dex_walker::DexExtractOutcome::Found(features) => {
                chosen = Some((entry.clone(), features));
                break;
            }
            dex_walker::DexExtractOutcome::NotApplicable(reason) => {
                per_dex_diagnostics.push(format!("{}: {reason}", entry.name));
            }
        }
    }
    let Some((target_entry, dex_features)) = chosen else {
        let diag = per_dex_diagnostics.join("; ");
        return Ok(FuckLgsiOutcome::NotApplicable {
            reason: format!(
                "found {LGSI_FEATURES_CLASS} string in {} dex(es) but none carry \
                 the class definition with registrations; different ROM build or \
                 refactored class. Per-dex diagnostics: {diag}",
                candidate_dex_entries.len()
            ),
        });
    };
    let dex_data_off = target_entry.data_start;
    let dex_data_end = dex_data_off + target_entry.compressed_size;

    // 6. Cross-reference: pick which nibble (E or F) holds Enabled.
    let enabled_nibble = cross_ref::determine_enabled_nibble(&html_features, &dex_features)?;

    // 7. Workspace + user state.
    let user_state = match &input.mode {
        FuckLgsiMode::Interactive => {
            workspace::write_workspace(input.workspace_dir, &html_features, &html_bytes)?;
            workspace::interactive_collect_edited_state(input.workspace_dir)?
        }
        FuckLgsiMode::Config(path) => workspace::read_user_json(path)?,
    };

    // 8. Diff against HTML baseline (current on-disk state).
    let html_state: HashMap<String, bool> = html_features
        .iter()
        .map(|f| (f.name.clone(), f.enabled))
        .collect();
    let dex_index: HashMap<&str, &dex_walker::DexFeature> =
        dex_features.iter().map(|f| (f.name.as_str(), f)).collect();
    let mut applied: Vec<LgsiFeatureChange> = Vec::new();
    let mut skipped: Vec<LgsiFeatureSkip> = Vec::new();

    // Walk the user's JSON entries (in JSON insertion order, preserved
    // by serde_json's `preserve_order` feature); for each, determine
    // whether the requested state differs from HTML and whether the dex
    // carries a patchable site.
    for (name, requested) in &user_state {
        let baseline = match html_state.get(name) {
            Some(b) => *b,
            None => {
                // JSON entry that wasn't in the HTML — typo or stale.
                if !dex_index.contains_key(name.as_str()) {
                    skipped.push(LgsiFeatureSkip {
                        name: name.clone(),
                        reason: SkipReason::NotInDex,
                    });
                    continue;
                }
                // Dex has it but HTML doesn't — treat as untoggled "we
                // don't know baseline". Skip rather than guess.
                skipped.push(LgsiFeatureSkip {
                    name: name.clone(),
                    reason: SkipReason::NotInHtml,
                });
                continue;
            }
        };
        if *requested == baseline {
            // No change requested for this feature.
            continue;
        }
        let Some(dex_feat) = dex_index.get(name.as_str()) else {
            skipped.push(LgsiFeatureSkip {
                name: name.clone(),
                reason: SkipReason::NotInDex,
            });
            continue;
        };
        // We need the bool registers (true and false) so we can flip the
        // chosen nibble's register number from one to the other.
        let (e_bool, f_bool) = match (dex_feat.e_bool, dex_feat.f_bool) {
            (Some(e), Some(f)) => (e, f),
            _ => {
                skipped.push(LgsiFeatureSkip {
                    name: name.clone(),
                    reason: SkipReason::UnknownDexBool,
                });
                continue;
            }
        };
        applied.push(LgsiFeatureChange {
            name: name.clone(),
            from: baseline,
            to: *requested,
            invoke_direct_offset_in_jar: (dex_data_off + dex_feat.invoke_direct_off_in_dex) as u64,
        });
        // The actual byte rewrite happens in the patch loop below; we
        // captured what's needed (e_bool/f_bool/e_reg/f_reg/nibble) in
        // dex_feat + enabled_nibble for the loop to consume.
        let _ = (e_bool, f_bool); // silence unused warning; loop uses dex_feat directly
    }

    // Surface HTML-only and dex-only mismatches as warnings.
    for hf in &html_features {
        if !dex_index.contains_key(hf.name.as_str()) {
            skipped.push(LgsiFeatureSkip {
                name: hf.name.clone(),
                reason: SkipReason::NotInDexFromHtml,
            });
        }
    }
    for df in &dex_features {
        if !html_state.contains_key(&df.name) {
            skipped.push(LgsiFeatureSkip {
                name: df.name.clone(),
                reason: SkipReason::NotInHtml,
            });
        }
    }

    if applied.is_empty() {
        // Interactive mode wrote `lgsi_features.json` + the html copy
        // into `workspace_dir`. Clean them up now that the patch is a
        // no-op — `report.html` carries the audit trail.
        if matches!(input.mode, FuckLgsiMode::Interactive) {
            let _ = workspace::cleanup(input.workspace_dir);
        }
        return Ok(FuckLgsiOutcome::NotApplicable {
            reason: "no patchable diffs after edit".to_string(),
        });
    }

    // 9. Apply per-feature byte patches inside the jar buffer.
    {
        let dex_slice = &mut jar_bytes[dex_data_off..dex_data_end];
        if dex_slice.len() < 0x70 {
            return Err(anyhow!(
                "dex slice too small ({} bytes) to recompute header sums",
                dex_slice.len()
            ));
        }
        for change in &applied {
            let dex_feat = dex_index
                .get(change.name.as_str())
                .expect("change.name was sourced from dex_index");
            patch::apply_change(dex_slice, dex_feat, enabled_nibble, change.to)?;
        }
        recompute_dex_header_sums(dex_slice);
    }

    // 10. Recompute jar CRC32 over the patched dex slice.
    let new_crc = crc32_ieee(&jar_bytes[dex_data_off..dex_data_end]);
    write_u32_le(
        &mut jar_bytes,
        target_entry.local_header_crc_offset,
        new_crc,
    );
    write_u32_le(&mut jar_bytes, target_entry.cd_crc_offset, new_crc);

    // 11. Write rewritten jar back to system.img.
    write_via_extents(input.system_image, &jar_bytes, &jar_extents, block_size)?;

    // 12. Regenerate dm-verity hash tree.
    let hashtree = read_hashtree_params(input.system_image, SYSTEM_PARTITION)?
        .ok_or_else(|| anyhow!("system.img has no Hashtree descriptor for `system`"))?;
    let old_root_digest = hashtree.root_digest.clone();
    let new_root_digest =
        regenerate_hashtree_with_progress(input.system_image, &hashtree, verity_progress)?;
    if new_root_digest.len() != SHA256_DIGEST_SIZE {
        return Err(anyhow!(
            "Regenerated hash tree returned unexpected root_digest length {}",
            new_root_digest.len()
        ));
    }

    // 13. Patch system.img + vbmeta_system.img Hashtree descriptors.
    patch_hashtree_root_digest(input.system_image, SYSTEM_PARTITION, &new_root_digest)?;
    patch_hashtree_root_digest(
        input.vbmeta_system_image,
        SYSTEM_PARTITION,
        &new_root_digest,
    )?;

    // 14. Cleanup workspace files in interactive mode now that the
    //     patch is committed. report.html (written later by the resign
    //     stage) carries the human-readable audit trail.
    if matches!(input.mode, FuckLgsiMode::Interactive) {
        let _ = workspace::cleanup(input.workspace_dir);
    }

    Ok(FuckLgsiOutcome::Patched {
        applied,
        skipped,
        old_root_digest: hex_encode(&old_root_digest),
        new_root_digest: hex_encode(&new_root_digest),
    })
}

// ---------------------------------------------------------------------------
// product.img html extraction
// ---------------------------------------------------------------------------

fn read_lgsi_build_info_html(product_image: &Path) -> Result<Vec<u8>> {
    let mut volume = open_ext4_volume(product_image)?;
    let inode = match lookup_inode_at_path(&mut volume, PRODUCT_HTML_PATH)? {
        Some(i) => i,
        None => bail!(
            "product.img missing /etc/lgsi_build_info.html; --fuck-lgsi cannot continue without it"
        ),
    };
    if !inode.is_file() {
        bail!("product.img /etc/lgsi_build_info.html is not a regular file");
    }
    let (bytes, _) = inode
        .open_read_with_extents(&mut volume)
        .map_err(|e| anyhow!("Failed to read /etc/lgsi_build_info.html from product.img: {e}"))?;
    Ok(bytes)
}

// ---------------------------------------------------------------------------
// HTML parser
// ---------------------------------------------------------------------------

mod html_parser {
    //! Extract the `featureData` JS array from `lgsi_build_info.html`
    //! and pull out the per-feature `(name, enabled)` pairs.
    //!
    //! The HTML's JS literal is auto-generated by `buildinfo.py` and is
    //! near-JSON: double-quoted strings, square brackets, occasional
    //! nested arrays in the Require Features column, and `// ...` line
    //! comments interleaved with the rows. We strip the comments + any
    //! trailing commas and parse the cleaned array as JSON.

    use anyhow::{Context, Result, anyhow, bail};

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct HtmlFeature {
        pub name: String,
        pub enabled: bool,
    }

    /// Index of the "Enabled State" column inside each row of
    /// `featureData`. The 0-based layout shipped by buildinfo.py is:
    /// `[Name, Owner, Description, Porting State, Enabled State,
    /// Writable State, Require Features, Auto Enabled By, Source File&Line]`.
    const ENABLED_STATE_COLUMN: usize = 4;
    const NAME_COLUMN: usize = 0;

    pub fn parse_lgsi_html(html: &[u8]) -> Result<Vec<HtmlFeature>> {
        let html_str =
            std::str::from_utf8(html).context("lgsi_build_info.html is not valid UTF-8")?;
        let array_text = extract_feature_data_array(html_str)?;
        let cleaned = strip_js_comments_and_trailing_commas(array_text);
        let rows: Vec<Vec<serde_json::Value>> = serde_json::from_slice(&cleaned)
            .context("failed to parse featureData array as JSON after cleanup")?;
        if rows.is_empty() {
            bail!("featureData array is empty");
        }
        // Row 0 is the header.
        let mut out = Vec::with_capacity(rows.len().saturating_sub(1));
        for (i, row) in rows.iter().enumerate().skip(1) {
            if row.len() <= ENABLED_STATE_COLUMN {
                bail!(
                    "featureData row {i} has only {} columns, expected at least {}",
                    row.len(),
                    ENABLED_STATE_COLUMN + 1
                );
            }
            let name = row[NAME_COLUMN]
                .as_str()
                .ok_or_else(|| anyhow!("featureData row {i} Name is not a string"))?
                .to_string();
            let enabled_str = row[ENABLED_STATE_COLUMN]
                .as_str()
                .ok_or_else(|| anyhow!("featureData row {i} Enabled State is not a string"))?;
            let enabled = match enabled_str {
                "Enabled" => true,
                "Disabled" => false,
                other => bail!(
                    "featureData row {i} ({name}) Enabled State `{other}` is neither \
                     `Enabled` nor `Disabled`"
                ),
            };
            out.push(HtmlFeature { name, enabled });
        }
        Ok(out)
    }

    fn extract_feature_data_array(html: &str) -> Result<&str> {
        // Locate `const featureData = [`. Use a substring search rather
        // than regex to keep the dependency surface minimal.
        let needle = "const featureData = [";
        let start = html
            .find(needle)
            .ok_or_else(|| anyhow!("`const featureData = [` not found in HTML"))?;
        let array_start = start + needle.len() - 1; // include opening `[`
        // Walk forward from `array_start` matching brackets, skipping
        // characters inside string literals (handles strings containing
        // `[` / `]`).
        let bytes = html.as_bytes();
        let mut depth = 0i32;
        let mut i = array_start;
        let mut in_string = false;
        let mut prev_backslash = false;
        while i < bytes.len() {
            let b = bytes[i];
            if in_string {
                if b == b'\\' && !prev_backslash {
                    prev_backslash = true;
                } else {
                    if b == b'"' && !prev_backslash {
                        in_string = false;
                    }
                    prev_backslash = false;
                }
            } else if b == b'"' {
                in_string = true;
                prev_backslash = false;
            } else if b == b'[' {
                depth += 1;
            } else if b == b']' {
                depth -= 1;
                if depth == 0 {
                    return Ok(&html[array_start..=i]);
                }
            }
            i += 1;
        }
        bail!("featureData array not closed; HTML truncated?")
    }

    /// Strip JS comments and trailing commas from the `featureData`
    /// literal so what remains parses as JSON. Operates on bytes (not
    /// `String`) so non-ASCII characters in feature descriptions stay
    /// intact through the cleanup pass — the stripped output is
    /// re-parsed by `serde_json::from_slice` directly.
    ///
    /// Also fixes JS-but-not-JSON escapes: `featureData` strings
    /// occasionally carry stray backslashes (real-world example:
    /// `"… platforms such as CMS\UPE, …"`). JS treats an unknown
    /// `\X` as a literal `X`; JSON rejects it as an "invalid escape".
    /// We escape any backslash whose next byte isn't a valid JSON
    /// escape character (`"`, `\`, `/`, `b`, `f`, `n`, `r`, `t`, `u`)
    /// by doubling it, so JSON sees a literal `\X`.
    fn strip_js_comments_and_trailing_commas(input: &str) -> Vec<u8> {
        let bytes = input.as_bytes();
        let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
        let mut i = 0;
        let mut in_string = false;
        let mut prev_backslash = false;
        while i < bytes.len() {
            let b = bytes[i];
            if in_string {
                if b == b'\\' && !prev_backslash {
                    let next = bytes.get(i + 1).copied();
                    let valid_json_escape = matches!(
                        next,
                        Some(b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' | b'u')
                    );
                    if valid_json_escape {
                        out.push(b'\\');
                    } else {
                        // Stray backslash before non-escape char (e.g.
                        // `\U`); double it so JSON sees a literal `\`.
                        out.extend_from_slice(b"\\\\");
                    }
                    prev_backslash = true;
                    i += 1;
                    continue;
                }
                out.push(b);
                if b == b'"' && !prev_backslash {
                    in_string = false;
                }
                prev_backslash = false;
                i += 1;
                continue;
            }
            if b == b'"' {
                in_string = true;
                prev_backslash = false;
                out.push(b'"');
                i += 1;
                continue;
            }
            // `// …` to end of line
            if b == b'/' && bytes.get(i + 1) == Some(&b'/') {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
                continue;
            }
            // `/* … */`
            if b == b'/' && bytes.get(i + 1) == Some(&b'*') {
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                if i + 1 < bytes.len() {
                    i += 2;
                }
                continue;
            }
            out.push(b);
            i += 1;
        }
        // Strip trailing commas inside `[…]` and `{…}`: ", ]" -> "]",
        // ", }" -> "}". Single byte-level pass; only ASCII whitespace
        // (space / tab / CR / LF) counts as a separator here, which
        // matches what JS source emits.
        let mut cleaned: Vec<u8> = Vec::with_capacity(out.len());
        let mut j = 0;
        while j < out.len() {
            if out[j] == b',' {
                let mut k = j + 1;
                while k < out.len() && matches!(out[k], b' ' | b'\t' | b'\n' | b'\r') {
                    k += 1;
                }
                if k < out.len() && (out[k] == b']' || out[k] == b'}') {
                    // Skip the trailing comma; whitespace stays so the
                    // bracket lands on the right line.
                    j += 1;
                    continue;
                }
            }
            cleaned.push(out[j]);
            j += 1;
        }
        cleaned
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn parse_lgsi_html_extracts_feature_states() {
            let html = r#"<html><script>
const featureData = [
  ["Name", "Owner", "Desc", "Porting State", "Enabled State", "Writable State", "Req", "Auto", "Src"],
  // auto generated
  ["AdobeExpress", "magx1", "stub.", "Ported", "Disabled", "Readonly", "", "", "x.xml:1"],
  ["ZuiAntiCrossSell", "lenovo", "anti cross sell.", "Ported", "Enabled", "Readonly", "", "", "y.xml:42"],
];
</script></html>"#;
            let out = parse_lgsi_html(html.as_bytes()).expect("parse ok");
            assert_eq!(
                out,
                vec![
                    HtmlFeature {
                        name: "AdobeExpress".to_string(),
                        enabled: false,
                    },
                    HtmlFeature {
                        name: "ZuiAntiCrossSell".to_string(),
                        enabled: true,
                    },
                ]
            );
        }

        #[test]
        fn parse_lgsi_html_rejects_unknown_state() {
            let html = r#"<html><script>
const featureData = [
  ["Name", "Owner", "Desc", "Porting State", "Enabled State"],
  ["X", "y", "z", "Ported", "Maybe"],
];
</script></html>"#;
            assert!(parse_lgsi_html(html.as_bytes()).is_err());
        }

        /// Smoke test against a real TB322 `lgsi_build_info.html` if
        /// available locally. Gated on the dump path; CI environments
        /// without the dump silently no-op.
        #[test]
        fn parse_real_tb322_html_when_available() {
            let path = std::path::Path::new(
                r"D:\Git\Project-DeZUX\dump\TB322_ZUXOS_1.5.10.183_resigned\system\product\etc\lgsi_build_info.html",
            );
            let Ok(bytes) = std::fs::read(path) else {
                return;
            };
            let features = parse_lgsi_html(&bytes).expect("real OEM html must parse");
            assert!(
                features.len() > 50,
                "expected >50 features, got {}",
                features.len()
            );
            assert!(
                features.iter().any(|f| f.name == "ZuiAntiCrossSell"),
                "ZuiAntiCrossSell not found in parsed feature list"
            );
        }

        /// Regression: real-world `lgsi_build_info.html` rows include
        /// strings like `"… platforms such as CMS\UPE, …"` where a
        /// stray backslash precedes a non-JSON-escape character. JS
        /// treats `\U` as literal `U`; JSON would reject it as an
        /// "invalid escape". The cleaner must double-escape such
        /// backslashes so the cleaned blob still parses.
        #[test]
        fn parse_lgsi_html_handles_stray_backslash_in_strings() {
            let html = r#"<html><script>
const featureData = [
  ["Name", "Owner", "Desc", "Porting State", "Enabled State", "Writable State", "Req", "Auto", "Src"],
  ["TabletVantage", "x", "uses CMS\UPE, NPS, etc.", "Ported", "Enabled", "Readonly", "", "", "f.xml:1"],
  ["Other", "y", "with a real \"quote\" inside", "Ported", "Disabled", "Readonly", "", "", "f.xml:2"],
];
</script></html>"#;
            let out = parse_lgsi_html(html.as_bytes()).expect("stray backslash must round-trip");
            assert_eq!(out.len(), 2);
            assert_eq!(out[0].name, "TabletVantage");
            assert!(out[0].enabled);
            assert_eq!(out[1].name, "Other");
            assert!(!out[1].enabled);
        }
    }
}

// ---------------------------------------------------------------------------
// DEX walker
// ---------------------------------------------------------------------------

mod dex_walker {
    //! Walk a dex to find `LgsiFeatures.<clinit>`'s `invoke-direct
    //! LgsiFeatureInfo.<init>` sites and snapshot each registration's
    //! E and F nibble registers + their tracked bool values.

    use super::*;

    #[derive(Debug, Clone)]
    pub struct DexFeature {
        pub name: String,
        /// Byte offset of the `invoke-direct` opcode (`0x70`) inside the
        /// dex (== inside the JAR-relative dex slice). The patched byte
        /// sits at `invoke_direct_off_in_dex + 5` (the F|E nibble pair).
        pub invoke_direct_off_in_dex: usize,
        /// Register number encoded by the E nibble of the F|E byte
        /// (low nibble at byte offset +5).
        pub e_reg: u16,
        /// Register number encoded by the F nibble (high nibble).
        pub f_reg: u16,
        /// Bool currently held in `e_reg` per the const-tracker, if
        /// known. `None` when the tracker lost track of it before this
        /// invoke-direct.
        pub e_bool: Option<bool>,
        /// Bool currently held in `f_reg` per the const-tracker, if
        /// known.
        pub f_bool: Option<bool>,
    }

    /// Result of an extract pass over a single dex. `Found` carries the
    /// per-feature registration list; `NotApplicable` carries a string
    /// identifying which lookup step bailed (so the orchestrator can
    /// surface a useful diagnostic when *no* candidate dex resolves).
    pub enum DexExtractOutcome {
        Found(Vec<DexFeature>),
        NotApplicable(String),
    }

    pub fn extract_lgsi_features(dex: &[u8]) -> Result<DexExtractOutcome> {
        // Header layout (subset) — see dex format spec.
        if dex.len() < 0x70 {
            bail!("dex truncated below header size");
        }
        let string_ids_size = read_u32_le(dex, 0x38) as usize;
        let string_ids_off = read_u32_le(dex, 0x3C) as usize;
        let type_ids_size = read_u32_le(dex, 0x40) as usize;
        let type_ids_off = read_u32_le(dex, 0x44) as usize;
        let proto_ids_size = read_u32_le(dex, 0x48) as usize;
        let proto_ids_off = read_u32_le(dex, 0x4C) as usize;
        let method_ids_size = read_u32_le(dex, 0x58) as usize;
        let method_ids_off = read_u32_le(dex, 0x5C) as usize;
        let class_defs_size = read_u32_le(dex, 0x60) as usize;
        let class_defs_off = read_u32_le(dex, 0x64) as usize;

        // 1. Find the type_idx of LgsiFeatures.
        let lgsi_features_type_idx = find_type_idx(
            dex,
            string_ids_size,
            string_ids_off,
            type_ids_size,
            type_ids_off,
            LGSI_FEATURES_CLASS,
        )?;
        let Some(lgsi_features_type_idx) = lgsi_features_type_idx else {
            return Ok(DexExtractOutcome::NotApplicable(
                "no LgsiFeatures type idx in this dex".to_string(),
            ));
        };
        // 2. Find the type_idx of LgsiFeatureInfo (target of <init>).
        let lgsi_feature_info_type_idx = find_type_idx(
            dex,
            string_ids_size,
            string_ids_off,
            type_ids_size,
            type_ids_off,
            LGSI_FEATURE_INFO_CLASS,
        )?;
        let Some(lgsi_feature_info_type_idx) = lgsi_feature_info_type_idx else {
            return Ok(DexExtractOutcome::NotApplicable(
                "no LgsiFeatureInfo type idx in this dex".to_string(),
            ));
        };
        // 3. Find the string_idx of "<init>". The full proto descriptor
        //    `(Ljava/lang/String;ZZ)V` is *not* stored as a single
        //    string in the dex string pool — protos are composed at
        //    runtime from `shorty_idx`, `return_type_idx`, and a
        //    `type_list` reached through `parameters_off`. So we only
        //    look up the method *name* string here, and reconstruct the
        //    proto match in step 4 from type_ids + the parameters
        //    type_list.
        let init_name_string_idx = find_string_idx_strict(
            dex,
            string_ids_size,
            string_ids_off,
            LGSI_FEATURE_INFO_INIT_NAME,
        )?;
        let Some(init_name_string_idx) = init_name_string_idx else {
            return Ok(DexExtractOutcome::NotApplicable(
                "no `<init>` string idx in this dex".to_string(),
            ));
        };
        // 4. Find the proto_idx for `(Ljava/lang/String;ZZ)V` by walking
        //    proto_ids and matching return-type + parameters.
        let target_proto_idx = find_proto_idx_for_init(
            dex,
            string_ids_size,
            string_ids_off,
            type_ids_size,
            type_ids_off,
            proto_ids_size,
            proto_ids_off,
        )?;
        let Some(target_proto_idx) = target_proto_idx else {
            return Ok(DexExtractOutcome::NotApplicable(format!(
                "no proto matching `{LGSI_FEATURE_INFO_INIT_PROTO}` in this dex"
            )));
        };
        // 5. Find the method_id matching (LgsiFeatureInfo, <init>, target_proto).
        let target_method_idx = find_method_idx(
            dex,
            method_ids_size,
            method_ids_off,
            lgsi_feature_info_type_idx,
            init_name_string_idx,
            target_proto_idx,
        )?;
        let Some(target_method_idx) = target_method_idx else {
            return Ok(DexExtractOutcome::NotApplicable(format!(
                "no method_id matching {LGSI_FEATURE_INFO_CLASS}-><init>{LGSI_FEATURE_INFO_INIT_PROTO} in this dex"
            )));
        };
        // 6. Find LgsiFeatures' class_def, then its <clinit> code_off.
        let class_data_off =
            find_class_data_off(dex, class_defs_size, class_defs_off, lgsi_features_type_idx)?;
        let Some(class_data_off) = class_data_off else {
            return Ok(DexExtractOutcome::NotApplicable(
                "no class_def for LgsiFeatures (referenced as type but not defined here)"
                    .to_string(),
            ));
        };
        let clinit_code_off = find_clinit_code_off(
            dex,
            class_data_off,
            method_ids_size,
            method_ids_off,
            string_ids_size,
            string_ids_off,
        )?;
        let Some(clinit_code_off) = clinit_code_off else {
            return Ok(DexExtractOutcome::NotApplicable(
                "LgsiFeatures class_def has no <clinit> direct method".to_string(),
            ));
        };
        // 7. Walk <clinit>'s insns; find every invoke-direct against
        //    target_method_idx + decode the const-string anchoring it.
        let registrations = walk_clinit_for_features(dex, clinit_code_off, target_method_idx)?;
        if registrations.is_empty() {
            return Ok(DexExtractOutcome::NotApplicable(format!(
                "<clinit> walked but found 0 invoke-direct against method_idx {target_method_idx} (LgsiFeatureInfo.<init>); class_data_off={class_data_off:#x}, clinit_code_off={clinit_code_off:#x}"
            )));
        }
        // 8. Resolve each feature's name string.
        let mut out = Vec::with_capacity(registrations.len());
        for reg in registrations {
            let name =
                read_string_at_idx(dex, string_ids_size, string_ids_off, reg.name_string_idx)?;
            let Some(name) = name else { continue };
            out.push(DexFeature {
                name,
                invoke_direct_off_in_dex: reg.invoke_direct_off_in_dex,
                e_reg: reg.e_reg,
                f_reg: reg.f_reg,
                e_bool: reg.e_bool,
                f_bool: reg.f_bool,
            });
        }
        if out.is_empty() {
            return Ok(DexExtractOutcome::NotApplicable(
                "all invoke-direct registrations resolved to non-UTF-8 feature names; cannot continue".to_string(),
            ));
        }
        Ok(DexExtractOutcome::Found(out))
    }

    /// Result of scanning <clinit> for one feature registration. Holds
    /// the raw indices/registers; the public DexFeature wraps it with
    /// the resolved name string.
    struct RawRegistration {
        invoke_direct_off_in_dex: usize,
        name_string_idx: u32,
        e_reg: u16,
        f_reg: u16,
        e_bool: Option<bool>,
        f_bool: Option<bool>,
    }

    fn walk_clinit_for_features(
        dex: &[u8],
        code_off: usize,
        target_method_idx: u32,
    ) -> Result<Vec<RawRegistration>> {
        // code_item header: u16 registers_size, u16 ins_size, u16 outs_size,
        // u16 tries_size, u32 debug_info_off, u32 insns_size, then insns.
        if code_off + 16 > dex.len() {
            bail!("dex code_item header out of bounds at offset {code_off}");
        }
        let registers_size = read_u16_le(dex, code_off) as usize;
        let insns_size = read_u32_le(dex, code_off + 12) as usize;
        let insns_off = code_off + 16;
        let insns_end = insns_off
            .checked_add(
                insns_size
                    .checked_mul(2)
                    .ok_or_else(|| anyhow!("dex insns size overflow"))?,
            )
            .ok_or_else(|| anyhow!("dex insns range overflow"))?;
        if insns_end > dex.len() {
            bail!(
                "dex insns out of bounds: end {insns_end} exceeds dex size {}",
                dex.len()
            );
        }
        let insns = &dex[insns_off..insns_end];

        // Track:
        //   * tracker[reg] = Option<bool> — known boolean constant.
        //   * last_const_string_string_idx — the string idx loaded into
        //     a const-string most recently before each invoke-direct.
        //     We only need the string idx, not the register; the smali
        //     pattern is `const-string vN, "Feature"; invoke-direct
        //     {... vN ...}, ...<init>` so we don't have to track which
        //     reg holds it. Since the same vN slot may be reused for
        //     successive features, a simple "last seen" stash works.
        let mut tracker: Vec<Option<bool>> = vec![None; registers_size];
        let mut last_string_idx: Option<u32> = None;
        let mut out: Vec<RawRegistration> = Vec::new();

        let mut pc = 0usize;
        while pc < insns.len() {
            let opcode = insns[pc];
            let width_units = DEX_INSN_WIDTH_UNITS[opcode as usize] as usize;
            if width_units == 0 {
                // Unknown / unused opcode. Bail rather than mis-stride.
                bail!(
                    "dex <clinit>: unsupported opcode {opcode:#04x} at insn offset {pc}; \
                     register tracker cannot continue safely"
                );
            }
            let width = width_units * 2;
            if pc + width > insns.len() {
                bail!(
                    "dex <clinit>: opcode {opcode:#04x} at offset {pc} declares width {width} \
                     bytes but only {} remain",
                    insns.len() - pc
                );
            }
            let insn = &insns[pc..pc + width];

            // Update tracker / capture string idx based on opcode.
            if let Some((reg, b)) = insn_const_bool(insn) {
                if (reg as usize) < tracker.len() {
                    tracker[reg as usize] = Some(b);
                }
            } else {
                for reg in insn_destination_regs(insn) {
                    if (reg as usize) < tracker.len() {
                        tracker[reg as usize] = None;
                    }
                }
            }

            match opcode {
                0x1A => {
                    // const-string vAA, string@BBBB (fmt 21c)
                    let string_idx = read_u16_le(insn, 2) as u32;
                    last_string_idx = Some(string_idx);
                }
                0x1B => {
                    // const-string/jumbo vAA, string@BBBBBBBB (fmt 31c)
                    let string_idx = read_u32_le(insn, 2);
                    last_string_idx = Some(string_idx);
                }
                0x70 => {
                    // invoke-direct {vC, vD, vE, vF, vG}, method@BBBB (fmt 35c)
                    let method_idx = read_u16_le(insn, 2) as u32;
                    if method_idx == target_method_idx {
                        let arg_count = (insn[1] >> 4) & 0x0F;
                        if arg_count == 4 {
                            // F|E byte at insn[5]; D|C at insn[4].
                            let e_reg = (insn[5] & 0x0F) as u16;
                            let f_reg = ((insn[5] >> 4) & 0x0F) as u16;
                            // C reg (this) at insn[4] low; D reg (name) at insn[4] high.
                            // We don't track them but use string_idx from
                            // the most recent const-string for the name.
                            if let Some(name_string_idx) = last_string_idx.take() {
                                let e_bool = tracker.get(e_reg as usize).copied().unwrap_or(None);
                                let f_bool = tracker.get(f_reg as usize).copied().unwrap_or(None);
                                out.push(RawRegistration {
                                    invoke_direct_off_in_dex: insns_off + pc,
                                    name_string_idx,
                                    e_reg,
                                    f_reg,
                                    e_bool,
                                    f_bool,
                                });
                            }
                            // If no string_idx is in flight, this isn't a
                            // typical feature registration; skip.
                        }
                    }
                }
                _ => {}
            }

            pc += width;
        }

        Ok(out)
    }

    /// Decode a known-bool const into (dest_reg, bool). Returns None for
    /// non-const opcodes or const literals outside {0, 1}.
    fn insn_const_bool(insn: &[u8]) -> Option<(u16, bool)> {
        match insn[0] {
            0x12 => {
                // const/4 vA, #+B (B is sign-extended 4-bit literal in
                // the high nibble of byte 1).
                let a = (insn[1] & 0x0F) as u16;
                let b_signed = (insn[1] as i8) >> 4;
                match b_signed {
                    0 => Some((a, false)),
                    1 => Some((a, true)),
                    _ => None,
                }
            }
            0x13 => {
                // const/16 vAA, #+BBBB
                if insn.len() < 4 {
                    return None;
                }
                let a = insn[1] as u16;
                let lit = i16::from_le_bytes([insn[2], insn[3]]);
                match lit {
                    0 => Some((a, false)),
                    1 => Some((a, true)),
                    _ => None,
                }
            }
            0x14 => {
                // const vAA, #+BBBBBBBB
                if insn.len() < 6 {
                    return None;
                }
                let a = insn[1] as u16;
                let lit = i32::from_le_bytes([insn[2], insn[3], insn[4], insn[5]]);
                match lit {
                    0 => Some((a, false)),
                    1 => Some((a, true)),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    /// Best-effort destination-register list for a small set of
    /// register-writing opcodes commonly seen inside `<clinit>`. Unknown
    /// opcodes return an empty list — the tracker keeps existing
    /// entries, which is safe because the boolean registers (typically
    /// `v3` and `v4`) are loaded once at the top of `<clinit>` and never
    /// rewritten by the registration loop.
    fn insn_destination_regs(insn: &[u8]) -> Vec<u16> {
        match insn[0] {
            // 12x: move, move-object, neg-* / not-* / *-to-* / 2addr-style.
            0x01 | 0x07 => vec![(insn[1] & 0x0F) as u16],
            // 12x wide: move-wide → clears reg + reg+1.
            0x04 => {
                let r = (insn[1] & 0x0F) as u16;
                vec![r, r.saturating_add(1)]
            }
            // 22x: move/from16, move-object/from16.
            0x02 | 0x08 => vec![insn[1] as u16],
            // 22x wide: move-wide/from16.
            0x05 => {
                let r = insn[1] as u16;
                vec![r, r.saturating_add(1)]
            }
            // 32x: move/16, move-object/16.
            0x03 | 0x09 => {
                if insn.len() >= 4 {
                    vec![u16::from_le_bytes([insn[2], insn[3]])]
                } else {
                    vec![]
                }
            }
            // 32x wide: move-wide/16.
            0x06 => {
                if insn.len() >= 4 {
                    let r = u16::from_le_bytes([insn[2], insn[3]]);
                    vec![r, r.saturating_add(1)]
                } else {
                    vec![]
                }
            }
            // 11x: move-result, move-result-object, move-exception.
            0x0A | 0x0C | 0x0D => vec![insn[1] as u16],
            // 11x wide: move-result-wide.
            0x0B => {
                let r = insn[1] as u16;
                vec![r, r.saturating_add(1)]
            }
            // 21h / 21s / 31i / 21c (const family): handled separately
            // by insn_const_bool when the literal is 0/1; otherwise the
            // tracker entry should be cleared.
            0x13 | 0x14 | 0x15 | 0x1A | 0x1B | 0x1C | 0x1F | 0x22 => vec![insn[1] as u16],
            // const/4 (handled by insn_const_bool when 0/1; otherwise
            // clear via destination).
            0x12 => vec![(insn[1] & 0x0F) as u16],
            // 21s / 21h wide: const-wide/16, const-wide/high16.
            0x16 | 0x19 => {
                let r = insn[1] as u16;
                vec![r, r.saturating_add(1)]
            }
            // 31i wide: const-wide/32.
            0x17 => {
                let r = insn[1] as u16;
                vec![r, r.saturating_add(1)]
            }
            // 51l: const-wide.
            0x18 => {
                let r = insn[1] as u16;
                vec![r, r.saturating_add(1)]
            }
            // 21t / 22b / 22c / 22s / 23x (binary / array / instanceof)
            // — destination is the low nibble of byte 1.
            0x20 | 0x23 => vec![(insn[1] & 0x0F) as u16],
            // iget-* (22c) — A nibble.
            0x52..=0x58 => vec![(insn[1] & 0x0F) as u16],
            // sget-* (21c) — AA.
            0x60..=0x66 => vec![insn[1] as u16],
            // aget-* (23x) — AA.
            0x44..=0x4A => vec![insn[1] as u16],
            // unop / lit ops 7B..8F (12x) — A nibble.
            0x7B..=0x8F => vec![(insn[1] & 0x0F) as u16],
            // binop 23x (90..AF) — AA.
            0x90..=0xAF => vec![insn[1] as u16],
            // binop 2addr (B0..CF) — A nibble.
            0xB0..=0xCF => vec![(insn[1] & 0x0F) as u16],
            // binop lit16 (D0..D7) — A nibble.
            0xD0..=0xD7 => vec![(insn[1] & 0x0F) as u16],
            // binop lit8 (D8..E2) — AA.
            0xD8..=0xE2 => vec![insn[1] as u16],
            // Anything else (returns, throws, gotos, ifs, sput*, iput*,
            // invoke*, monitor*, fill-array, packed/sparse switches,
            // nop, etc.) — does not write a numbered register relevant
            // to the tracker.
            _ => vec![],
        }
    }

    fn find_type_idx(
        dex: &[u8],
        string_ids_size: usize,
        string_ids_off: usize,
        type_ids_size: usize,
        type_ids_off: usize,
        descriptor: &str,
    ) -> Result<Option<u32>> {
        let Some(s_idx) = find_string_idx_strict(dex, string_ids_size, string_ids_off, descriptor)?
        else {
            return Ok(None);
        };
        let table_end = type_ids_off
            .checked_add(type_ids_size.saturating_mul(4))
            .ok_or_else(|| anyhow!("dex type_ids overflow"))?;
        if table_end > dex.len() {
            bail!("dex type_ids out of bounds");
        }
        for idx in 0..type_ids_size {
            let entry_off = type_ids_off + idx * 4;
            let descriptor_idx = read_u32_le(dex, entry_off);
            if descriptor_idx == s_idx {
                return Ok(Some(idx as u32));
            }
        }
        Ok(None)
    }

    fn find_method_idx(
        dex: &[u8],
        method_ids_size: usize,
        method_ids_off: usize,
        class_type_idx: u32,
        name_string_idx: u32,
        proto_idx: u32,
    ) -> Result<Option<u32>> {
        let table_end = method_ids_off
            .checked_add(method_ids_size.saturating_mul(8))
            .ok_or_else(|| anyhow!("dex method_ids overflow"))?;
        if table_end > dex.len() {
            bail!("dex method_ids out of bounds");
        }
        for idx in 0..method_ids_size {
            let entry_off = method_ids_off + idx * 8;
            let class_idx = read_u16_le(dex, entry_off) as u32;
            let proto_at_idx = read_u16_le(dex, entry_off + 2) as u32;
            let name_idx = read_u32_le(dex, entry_off + 4);
            if class_idx == class_type_idx
                && proto_at_idx == proto_idx
                && name_idx == name_string_idx
            {
                return Ok(Some(idx as u32));
            }
        }
        Ok(None)
    }

    fn find_proto_idx_for_init(
        dex: &[u8],
        string_ids_size: usize,
        string_ids_off: usize,
        type_ids_size: usize,
        type_ids_off: usize,
        proto_ids_size: usize,
        proto_ids_off: usize,
    ) -> Result<Option<u32>> {
        // Resolve the type idx for `Ljava/lang/String;` and `V` (void).
        let Some(string_type_idx) = find_type_idx(
            dex,
            string_ids_size,
            string_ids_off,
            type_ids_size,
            type_ids_off,
            "Ljava/lang/String;",
        )?
        else {
            return Ok(None);
        };
        let Some(void_type_idx) = find_type_idx(
            dex,
            string_ids_size,
            string_ids_off,
            type_ids_size,
            type_ids_off,
            "V",
        )?
        else {
            return Ok(None);
        };

        let table_end = proto_ids_off
            .checked_add(proto_ids_size.saturating_mul(12))
            .ok_or_else(|| anyhow!("dex proto_ids overflow"))?;
        if table_end > dex.len() {
            bail!("dex proto_ids out of bounds");
        }

        for idx in 0..proto_ids_size {
            let entry_off = proto_ids_off + idx * 12;
            let return_type_idx = read_u32_le(dex, entry_off + 4);
            let parameters_off = read_u32_le(dex, entry_off + 8) as usize;
            if return_type_idx != void_type_idx {
                continue;
            }
            // Empty parameters => no `String;ZZ` match.
            if parameters_off == 0 {
                continue;
            }
            // type_list layout: u32 size, u16 list[size].
            if parameters_off + 4 > dex.len() {
                continue;
            }
            let list_size = read_u32_le(dex, parameters_off) as usize;
            if list_size != 3 {
                continue;
            }
            let list_off = parameters_off + 4;
            let list_end = list_off + list_size * 2;
            if list_end > dex.len() {
                continue;
            }
            let p0 = read_u16_le(dex, list_off) as u32;
            let p1 = read_u16_le(dex, list_off + 2) as u32;
            let p2 = read_u16_le(dex, list_off + 4) as u32;
            // p0 must be Ljava/lang/String;, p1/p2 must both resolve to
            // primitive boolean "Z".
            if p0 != string_type_idx {
                continue;
            }
            // Check p1 and p2 type descriptors are "Z".
            if !type_idx_is(
                dex,
                type_ids_off,
                type_ids_size,
                string_ids_off,
                string_ids_size,
                p1,
                "Z",
            )? {
                continue;
            }
            if !type_idx_is(
                dex,
                type_ids_off,
                type_ids_size,
                string_ids_off,
                string_ids_size,
                p2,
                "Z",
            )? {
                continue;
            }
            return Ok(Some(idx as u32));
        }
        Ok(None)
    }

    fn type_idx_is(
        dex: &[u8],
        type_ids_off: usize,
        type_ids_size: usize,
        string_ids_off: usize,
        string_ids_size: usize,
        type_idx: u32,
        target: &str,
    ) -> Result<bool> {
        if type_idx as usize >= type_ids_size {
            return Ok(false);
        }
        let entry_off = type_ids_off + (type_idx as usize) * 4;
        if entry_off + 4 > dex.len() {
            return Ok(false);
        }
        let descriptor_idx = read_u32_le(dex, entry_off);
        let s = read_string_at_idx(dex, string_ids_size, string_ids_off, descriptor_idx)?;
        Ok(s.as_deref() == Some(target))
    }

    fn find_class_data_off(
        dex: &[u8],
        class_defs_size: usize,
        class_defs_off: usize,
        class_type_idx: u32,
    ) -> Result<Option<usize>> {
        let table_end = class_defs_off
            .checked_add(class_defs_size.saturating_mul(32))
            .ok_or_else(|| anyhow!("dex class_defs overflow"))?;
        if table_end > dex.len() {
            bail!("dex class_defs out of bounds");
        }
        for idx in 0..class_defs_size {
            let entry_off = class_defs_off + idx * 32;
            let class_idx = read_u32_le(dex, entry_off);
            if class_idx == class_type_idx {
                let class_data_off = read_u32_le(dex, entry_off + 24) as usize;
                if class_data_off == 0 {
                    return Ok(None);
                }
                return Ok(Some(class_data_off));
            }
        }
        Ok(None)
    }

    fn find_clinit_code_off(
        dex: &[u8],
        class_data_off: usize,
        method_ids_size: usize,
        method_ids_off: usize,
        string_ids_size: usize,
        string_ids_off: usize,
    ) -> Result<Option<usize>> {
        let mut p = class_data_off;
        // class_data_item: 4 ULEB128 sizes, then field/method arrays.
        let static_fields_size = read_uleb128(dex, &mut p)?;
        let instance_fields_size = read_uleb128(dex, &mut p)?;
        let direct_methods_size = read_uleb128(dex, &mut p)?;
        let _virtual_methods_size = read_uleb128(dex, &mut p)?;
        // Skip static_fields[] and instance_fields[] (each entry = 2 ULEB128s).
        for _ in 0..(static_fields_size + instance_fields_size) {
            let _idx_diff = read_uleb128(dex, &mut p)?;
            let _access = read_uleb128(dex, &mut p)?;
        }
        // Walk direct_methods[] = Vec<{method_idx_diff, access_flags, code_off}>.
        let mut method_idx_acc: u64 = 0;
        for _ in 0..direct_methods_size {
            let diff = read_uleb128(dex, &mut p)?;
            method_idx_acc += diff;
            let _access = read_uleb128(dex, &mut p)?;
            let code_off = read_uleb128(dex, &mut p)? as usize;
            // Resolve method name string idx and check for "<clinit>".
            let method_idx = method_idx_acc as u32;
            if (method_idx as usize) < method_ids_size {
                let method_off = method_ids_off + (method_idx as usize) * 8;
                if method_off + 8 <= dex.len() {
                    let name_idx = read_u32_le(dex, method_off + 4);
                    let s = read_string_at_idx(dex, string_ids_size, string_ids_off, name_idx)?;
                    if s.as_deref() == Some("<clinit>") {
                        if code_off == 0 {
                            return Ok(None);
                        }
                        return Ok(Some(code_off));
                    }
                }
            }
        }
        Ok(None)
    }

    /// Find the string idx of `needle` in `string_ids`. Strict variant
    /// requires an exact match including length and NUL terminator.
    fn find_string_idx_strict(
        dex: &[u8],
        string_ids_size: usize,
        string_ids_off: usize,
        needle: &str,
    ) -> Result<Option<u32>> {
        let needle_bytes = needle.as_bytes();
        let table_end = string_ids_off
            .checked_add(string_ids_size.saturating_mul(4))
            .ok_or_else(|| anyhow!("dex string_ids overflow"))?;
        if table_end > dex.len() {
            bail!("dex string_ids out of bounds");
        }
        for idx in 0..string_ids_size {
            let entry_off = string_ids_off + idx * 4;
            let str_data_off = read_u32_le(dex, entry_off) as usize;
            if str_data_off >= dex.len() {
                continue;
            }
            // Skip ULEB128 utf16_size.
            let mut p = str_data_off;
            loop {
                if p >= dex.len() {
                    bail!("dex string_data_item truncated at offset {p}");
                }
                let b = dex[p];
                p += 1;
                if b & 0x80 == 0 {
                    break;
                }
            }
            if p + needle_bytes.len() + 1 > dex.len() {
                continue;
            }
            if &dex[p..p + needle_bytes.len()] == needle_bytes && dex[p + needle_bytes.len()] == 0 {
                return Ok(Some(idx as u32));
            }
        }
        Ok(None)
    }

    /// Decode the string at the given string idx.
    fn read_string_at_idx(
        dex: &[u8],
        string_ids_size: usize,
        string_ids_off: usize,
        idx: u32,
    ) -> Result<Option<String>> {
        if (idx as usize) >= string_ids_size {
            return Ok(None);
        }
        let entry_off = string_ids_off + (idx as usize) * 4;
        if entry_off + 4 > dex.len() {
            return Ok(None);
        }
        let str_data_off = read_u32_le(dex, entry_off) as usize;
        if str_data_off >= dex.len() {
            return Ok(None);
        }
        let mut p = str_data_off;
        loop {
            if p >= dex.len() {
                bail!("dex string_data_item truncated at offset {p}");
            }
            let b = dex[p];
            p += 1;
            if b & 0x80 == 0 {
                break;
            }
        }
        // Read until NUL.
        let str_start = p;
        while p < dex.len() && dex[p] != 0 {
            p += 1;
        }
        if p >= dex.len() {
            return Ok(None);
        }
        let bytes = &dex[str_start..p];
        match std::str::from_utf8(bytes) {
            Ok(s) => Ok(Some(s.to_string())),
            Err(_) => Ok(None), // MUTF-8 not strictly UTF-8; non-ASCII strings get filtered out
        }
    }

    fn read_uleb128(dex: &[u8], p: &mut usize) -> Result<u64> {
        let mut result: u64 = 0;
        let mut shift = 0u32;
        loop {
            if *p >= dex.len() {
                bail!("dex ULEB128 truncated at offset {p}", p = *p);
            }
            let b = dex[*p];
            *p += 1;
            result |= ((b & 0x7F) as u64) << shift;
            if b & 0x80 == 0 {
                return Ok(result);
            }
            shift += 7;
            if shift >= 64 {
                bail!("dex ULEB128 overflow");
            }
        }
    }

    /// Instruction width in 16-bit code units, indexed by opcode.
    /// `0` marks unused / reserved opcodes; the walker bails on those.
    /// Source: Android Dalvik bytecode spec.
    const DEX_INSN_WIDTH_UNITS: [u8; 256] = [
        /* 0x00 */ 1, 1, 2, 3, 1, 2, 3, 1, 2, 3, 1, 1, 1, 1, 1, 1, /* 0x10 */ 1, 1, 1, 2,
        3, 2, 2, 3, 5, 2, 2, 3, 2, 1, 1, 2, /* 0x20 */ 2, 1, 2, 2, 3, 3, 3, 1, 1, 2, 3, 3, 3,
        2, 2, 2, /* 0x30 */ 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0, /* 0x40 */ 0,
        0, 0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, /* 0x50 */ 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2, 2, /* 0x60 */ 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3,
        /* 0x70 */ 3, 3, 3, 0, 3, 3, 3, 3, 3, 0, 0, 1, 1, 1, 1, 1, /* 0x80 */ 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 0x90 */ 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, /* 0xA0 */ 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, /* 0xB0 */ 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 0xC0 */ 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, /* 0xD0 */ 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        /* 0xE0 */ 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0xF0 */ 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 3, 3, 3, 3, 2, 2,
    ];

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn insn_const_bool_const4_matches_zero_one() {
            // const/4 v3, #+0 -> opcode 0x12, byte1 = 0x03 (A=3, B=0).
            assert_eq!(insn_const_bool(&[0x12, 0x03]), Some((3, false)));
            // const/4 v4, #+1 -> opcode 0x12, byte1 = 0x14 (A=4, B=1).
            assert_eq!(insn_const_bool(&[0x12, 0x14]), Some((4, true)));
            // const/4 v3, #+2 (literal != 0/1) -> None.
            assert_eq!(insn_const_bool(&[0x12, 0x23]), None);
            // const/16 v5, #+1 -> opcode 0x13, AA=5, BBBB=0x0001.
            assert_eq!(insn_const_bool(&[0x13, 0x05, 0x01, 0x00]), Some((5, true)));
            // const/16 v5, #+0
            assert_eq!(insn_const_bool(&[0x13, 0x05, 0x00, 0x00]), Some((5, false)));
            // const/16 v5, #+2 -> None.
            assert_eq!(insn_const_bool(&[0x13, 0x05, 0x02, 0x00]), None);
        }

        #[test]
        fn insn_destination_regs_const4_returns_low_nibble() {
            // const/4 v4, #+1 -> dest = 4.
            assert_eq!(insn_destination_regs(&[0x12, 0x14]), vec![4]);
        }

        #[test]
        fn dex_insn_width_units_known_opcodes() {
            assert_eq!(DEX_INSN_WIDTH_UNITS[0x00], 1); // nop
            assert_eq!(DEX_INSN_WIDTH_UNITS[0x12], 1); // const/4
            assert_eq!(DEX_INSN_WIDTH_UNITS[0x13], 2); // const/16
            assert_eq!(DEX_INSN_WIDTH_UNITS[0x14], 3); // const
            assert_eq!(DEX_INSN_WIDTH_UNITS[0x18], 5); // const-wide
            assert_eq!(DEX_INSN_WIDTH_UNITS[0x1A], 2); // const-string
            assert_eq!(DEX_INSN_WIDTH_UNITS[0x1B], 3); // const-string/jumbo
            assert_eq!(DEX_INSN_WIDTH_UNITS[0x70], 3); // invoke-direct
            assert_eq!(DEX_INSN_WIDTH_UNITS[0x71], 3); // invoke-static
            assert_eq!(DEX_INSN_WIDTH_UNITS[0x73], 0); // unused
        }
    }
}

// ---------------------------------------------------------------------------
// Cross-reference: which nibble (E or F) holds Enabled?
// ---------------------------------------------------------------------------

mod cross_ref {
    use super::*;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum EnabledNibble {
        E,
        F,
    }

    pub fn determine_enabled_nibble(
        html: &[html_parser::HtmlFeature],
        dex: &[dex_walker::DexFeature],
    ) -> Result<EnabledNibble> {
        let html_lookup: HashMap<&str, bool> =
            html.iter().map(|h| (h.name.as_str(), h.enabled)).collect();
        let mut e_match = 0usize;
        let mut f_match = 0usize;
        let mut e_total = 0usize;
        let mut f_total = 0usize;
        let mut considered = 0usize;
        for df in dex {
            let Some(html_enabled) = html_lookup.get(df.name.as_str()).copied() else {
                continue;
            };
            considered += 1;
            if let Some(e) = df.e_bool {
                e_total += 1;
                if e == html_enabled {
                    e_match += 1;
                }
            }
            if let Some(f) = df.f_bool {
                f_total += 1;
                if f == html_enabled {
                    f_match += 1;
                }
            }
        }
        let cross_referable = e_total.min(f_total);
        if cross_referable < CROSS_REF_MIN_FEATURES {
            bail!(
                "too few cross-referable LGSI features ({cross_referable}, considered {considered}, \
                 minimum {CROSS_REF_MIN_FEATURES}) to determine the Enabled nibble"
            );
        }
        let e_ratio = e_match as f64 / e_total as f64;
        let f_ratio = f_match as f64 / f_total as f64;
        match (
            e_ratio >= CROSS_REF_MATCH_RATIO,
            f_ratio >= CROSS_REF_MATCH_RATIO,
        ) {
            (true, false) => Ok(EnabledNibble::E),
            (false, true) => Ok(EnabledNibble::F),
            (true, true) => {
                // Pick the higher one; ties fall to F (smali convention
                // = mIsActive sits at F).
                if e_ratio > f_ratio {
                    Ok(EnabledNibble::E)
                } else {
                    Ok(EnabledNibble::F)
                }
            }
            (false, false) => bail!(
                "Cross-reference inconclusive: E nibble matched {}/{} ({:.0}%), \
                 F nibble matched {}/{} ({:.0}%); neither hit the {:.0}% threshold",
                e_match,
                e_total,
                e_ratio * 100.0,
                f_match,
                f_total,
                f_ratio * 100.0,
                CROSS_REF_MATCH_RATIO * 100.0
            ),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn h(name: &str, enabled: bool) -> html_parser::HtmlFeature {
            html_parser::HtmlFeature {
                name: name.to_string(),
                enabled,
            }
        }

        fn d(name: &str, e: Option<bool>, f: Option<bool>) -> dex_walker::DexFeature {
            dex_walker::DexFeature {
                name: name.to_string(),
                invoke_direct_off_in_dex: 0,
                e_reg: 0,
                f_reg: 0,
                e_bool: e,
                f_bool: f,
            }
        }

        #[test]
        fn picks_e_when_e_matches_html() {
            // 8 features all with E=enabled, F=different.
            let html: Vec<_> = (0..8).map(|i| h(&format!("F{i}"), i % 2 == 0)).collect();
            let dex: Vec<_> = (0..8)
                .map(|i| d(&format!("F{i}"), Some(i % 2 == 0), Some(false)))
                .collect();
            let n = determine_enabled_nibble(&html, &dex).expect("ok");
            assert_eq!(n, EnabledNibble::E);
        }

        #[test]
        fn bails_when_inconclusive() {
            // 8 features, half E matches, half F matches — 50/50 each.
            let html: Vec<_> = (0..8).map(|i| h(&format!("F{i}"), true)).collect();
            let dex: Vec<_> = (0..8)
                .map(|i| {
                    if i < 4 {
                        d(&format!("F{i}"), Some(true), Some(false))
                    } else {
                        d(&format!("F{i}"), Some(false), Some(true))
                    }
                })
                .collect();
            let err = determine_enabled_nibble(&html, &dex).expect_err("inconclusive");
            assert!(format!("{err}").contains("inconclusive"));
        }

        #[test]
        fn bails_when_too_few_features() {
            let html: Vec<_> = (0..3).map(|i| h(&format!("F{i}"), true)).collect();
            let dex: Vec<_> = (0..3)
                .map(|i| d(&format!("F{i}"), Some(true), Some(false)))
                .collect();
            let err = determine_enabled_nibble(&html, &dex).expect_err("too few");
            assert!(format!("{err}").contains("too few"));
        }
    }
}

// ---------------------------------------------------------------------------
// Workspace I/O
// ---------------------------------------------------------------------------

mod workspace {
    use super::*;

    pub fn write_workspace(
        workspace_dir: &Path,
        html_features: &[html_parser::HtmlFeature],
        html_bytes: &[u8],
    ) -> Result<()> {
        std::fs::create_dir_all(workspace_dir).with_context(|| {
            format!(
                "Failed to create LGSI workspace directory {}",
                workspace_dir.display()
            )
        })?;
        let json_path = workspace_dir.join(WORKSPACE_JSON_NAME);
        let html_path = workspace_dir.join(WORKSPACE_HTML_NAME);
        let mut map = serde_json::Map::new();
        for f in html_features {
            map.insert(f.name.clone(), serde_json::Value::Bool(f.enabled));
        }
        let json = serde_json::Value::Object(map);
        let pretty = serde_json::to_string_pretty(&json)
            .context("Failed to serialise lgsi_features.json")?;
        std::fs::write(&json_path, pretty)
            .with_context(|| format!("Failed to write {}", json_path.display()))?;
        std::fs::write(&html_path, html_bytes)
            .with_context(|| format!("Failed to write {}", html_path.display()))?;
        Ok(())
    }

    pub fn cleanup(workspace_dir: &Path) -> Result<()> {
        let json_path = workspace_dir.join(WORKSPACE_JSON_NAME);
        let html_path = workspace_dir.join(WORKSPACE_HTML_NAME);
        if json_path.exists() {
            std::fs::remove_file(&json_path)?;
        }
        if html_path.exists() {
            std::fs::remove_file(&html_path)?;
        }
        Ok(())
    }

    pub fn interactive_collect_edited_state(workspace_dir: &Path) -> Result<Vec<(String, bool)>> {
        let stdin = io::stdin();
        if !stdin.is_terminal() {
            bail!(
                "--fuck-lgsi needs an interactive terminal; pass --fuck-lgsi-config <path> instead"
            );
        }
        let json_path = workspace_dir.join(WORKSPACE_JSON_NAME);
        let html_path = workspace_dir.join(WORKSPACE_HTML_NAME);
        eprintln!();
        eprintln!("LGSI workspace ready:");
        eprintln!("  JSON  : {}", json_path.display());
        eprintln!("  HTML  : {} (reference, do not edit)", html_path.display());
        eprintln!("Edit the JSON to flip individual features (true = enabled, false = disabled),");
        eprintln!("then press Enter to continue. Ctrl-C aborts the resign stage.");
        loop {
            wait_for_enter()?;
            match read_user_json(&json_path) {
                Ok(state) => return Ok(state),
                Err(e) => {
                    eprintln!();
                    eprintln!("JSON parse error: {e}");
                    eprintln!("Fix the file and press Enter again, or Ctrl-C to abort.");
                }
            }
        }
    }

    fn wait_for_enter() -> Result<()> {
        let mut buf = [0u8; 1];
        let mut stdin = io::stdin().lock();
        loop {
            let n = stdin.read(&mut buf).context("failed to read from stdin")?;
            if n == 0 {
                bail!(
                    "stdin closed before Enter was pressed; --fuck-lgsi requires an \
                     interactive terminal"
                );
            }
            if buf[0] == b'\n' {
                return Ok(());
            }
        }
    }

    pub fn read_user_json(path: &Path) -> Result<Vec<(String, bool)>> {
        let bytes = std::fs::read(path)
            .with_context(|| format!("Failed to read LGSI config JSON {}", path.display()))?;
        let value: serde_json::Value = serde_json::from_slice(&bytes)
            .with_context(|| format!("Failed to parse {} as JSON", path.display()))?;
        let map = value
            .as_object()
            .ok_or_else(|| anyhow!("{} top-level value is not a JSON object", path.display()))?;
        let mut out = Vec::with_capacity(map.len());
        for (k, v) in map.iter() {
            let b = v.as_bool().ok_or_else(|| {
                anyhow!(
                    "{}: feature `{k}` is not a boolean (got {:?})",
                    path.display(),
                    v
                )
            })?;
            out.push((k.clone(), b));
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Patch: byte-level rewrite of one feature's F|E nibble.
// ---------------------------------------------------------------------------

mod patch {
    use super::*;

    /// Apply one feature's edit to the dex slice in place.
    ///
    /// The chosen `enabled_nibble` (E or F) is the one whose register
    /// corresponds to the `Enabled` boolean. We swap that nibble's
    /// register number from the current bool's register to the opposite
    /// bool's register. The other nibble is left untouched.
    pub fn apply_change(
        dex_slice: &mut [u8],
        feat: &dex_walker::DexFeature,
        enabled_nibble: cross_ref::EnabledNibble,
        target_bool: bool,
    ) -> Result<()> {
        // We need the register currently holding `target_bool` and the
        // register currently holding `!target_bool`. Both come from
        // `feat.e_bool` / `feat.f_bool` — by definition cross-ref
        // already verified the bool registers are consistent.
        let (e_reg, f_reg) = (feat.e_reg, feat.f_reg);
        let e_bool = feat
            .e_bool
            .ok_or_else(|| anyhow!("feature {} has unknown E-bool at patch time", feat.name))?;
        let f_bool = feat
            .f_bool
            .ok_or_else(|| anyhow!("feature {} has unknown F-bool at patch time", feat.name))?;

        // Identify the register that currently holds `target_bool`.
        let new_reg_for_enabled = if e_bool == target_bool {
            e_reg
        } else if f_bool == target_bool {
            f_reg
        } else {
            // Neither tracked register holds the requested bool. Without
            // a register holding `target_bool` we can't patch by reg
            // swap. Bail loudly so the caller can decide.
            bail!(
                "feature {}: no tracked register currently holds {target_bool} \
                 (e_reg=v{e_reg}={e_bool}, f_reg=v{f_reg}={f_bool}); \
                 unable to compute target nibble value",
                feat.name
            );
        };
        if new_reg_for_enabled > 0xF {
            bail!(
                "feature {}: target register v{new_reg_for_enabled} exceeds 4-bit nibble \
                 encoding; cannot patch via 35c F|E byte",
                feat.name
            );
        }

        let patch_off = feat
            .invoke_direct_off_in_dex
            .checked_add(5)
            .ok_or_else(|| anyhow!("feature {}: patch offset overflow", feat.name))?;
        if patch_off >= dex_slice.len() {
            bail!(
                "feature {}: patch offset {patch_off} >= dex slice length {}",
                feat.name,
                dex_slice.len()
            );
        }
        let current = dex_slice[patch_off];
        let new_byte = match enabled_nibble {
            cross_ref::EnabledNibble::E => (current & 0xF0) | (new_reg_for_enabled as u8 & 0x0F),
            cross_ref::EnabledNibble::F => (current & 0x0F) | ((new_reg_for_enabled as u8) << 4),
        };
        dex_slice[patch_off] = new_byte;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ZIP central-directory parsing (carryover from fuck_as.rs)
// ---------------------------------------------------------------------------

const ZIP_LOCAL_FILE_HEADER_SIG: u32 = 0x04034B50;
const ZIP_CENTRAL_DIRECTORY_SIG: u32 = 0x02014B50;
const ZIP_END_OF_CENTRAL_DIRECTORY_SIG: u32 = 0x06054B50;
const ZIP_FLAG_DATA_DESCRIPTOR: u16 = 0x0008;
const ZIP64_SENTINEL_U32: u32 = 0xFFFFFFFF;

#[derive(Debug, Clone)]
struct ZipEntry {
    name: String,
    data_start: usize,
    compressed_size: usize,
    local_header_crc_offset: usize,
    cd_crc_offset: usize,
    compression_method: u16,
    uses_data_descriptor: bool,
    is_zip64: bool,
}

#[derive(Debug, Clone)]
struct ZipLayout {
    entries: Vec<ZipEntry>,
}

fn parse_zip_central_directory(bytes: &[u8]) -> Result<ZipLayout> {
    let eocd_off = find_eocd(bytes)?;
    if bytes.len() < eocd_off + 22 {
        return Err(anyhow!("framework.jar truncated at EOCD"));
    }
    let cd_size = read_u32_le(bytes, eocd_off + 12) as usize;
    let cd_off = read_u32_le(bytes, eocd_off + 16) as usize;
    let total_records = read_u16_le(bytes, eocd_off + 10) as usize;

    let mut entries = Vec::with_capacity(total_records);
    let mut cursor = cd_off;
    let cd_end = checked_range_end(cd_off, cd_size, "framework.jar central directory")?;
    if cd_end > bytes.len() {
        return Err(anyhow!(
            "framework.jar central directory range {}..{} exceeds jar length {}",
            cd_off,
            cd_end,
            bytes.len()
        ));
    }
    while cursor < cd_end {
        let fixed_end = checked_range_end(cursor, 46, "framework.jar central directory entry")?;
        if fixed_end > cd_end || fixed_end > bytes.len() {
            return Err(anyhow!("framework.jar central directory truncated"));
        }
        let sig = read_u32_le(bytes, cursor);
        if sig != ZIP_CENTRAL_DIRECTORY_SIG {
            return Err(anyhow!(
                "framework.jar central directory: unexpected signature {sig:#010x} at offset {cursor}"
            ));
        }
        let cd_flags = read_u16_le(bytes, cursor + 8);
        let compression_method = read_u16_le(bytes, cursor + 10);
        let cd_crc_offset = cursor + 16;
        let compressed_size_raw = read_u32_le(bytes, cursor + 20);
        let uncompressed_size_raw = read_u32_le(bytes, cursor + 24);
        let name_len = read_u16_le(bytes, cursor + 28) as usize;
        let extra_len = read_u16_le(bytes, cursor + 30) as usize;
        let comment_len = read_u16_le(bytes, cursor + 32) as usize;
        let local_header_offset_raw = read_u32_le(bytes, cursor + 42);
        let variable_len = name_len
            .checked_add(extra_len)
            .and_then(|len| len.checked_add(comment_len))
            .ok_or_else(|| anyhow!("framework.jar central directory entry length overflow"))?;
        let entry_end = checked_range_end(
            fixed_end,
            variable_len,
            "framework.jar central directory entry",
        )?;
        if entry_end > cd_end || entry_end > bytes.len() {
            return Err(anyhow!(
                "framework.jar central directory entry at offset {} extends past directory end",
                cursor
            ));
        }
        let name_end = checked_range_end(fixed_end, name_len, "framework.jar entry name")?;
        let name = std::str::from_utf8(&bytes[fixed_end..name_end])
            .context("framework.jar central directory entry has non-UTF-8 name")?
            .to_string();

        let is_zip64 = compressed_size_raw == ZIP64_SENTINEL_U32
            || uncompressed_size_raw == ZIP64_SENTINEL_U32
            || local_header_offset_raw == ZIP64_SENTINEL_U32;
        let cd_uses_data_descriptor = cd_flags & ZIP_FLAG_DATA_DESCRIPTOR != 0;
        let compressed_size = compressed_size_raw as usize;
        let local_header_offset = local_header_offset_raw as usize;

        let local_fixed_end =
            checked_range_end(local_header_offset, 30, "framework.jar local file header")?;
        if local_fixed_end > bytes.len() {
            return Err(anyhow!(
                "framework.jar local file header for {name} truncated"
            ));
        }
        let lfh_sig = read_u32_le(bytes, local_header_offset);
        if lfh_sig != ZIP_LOCAL_FILE_HEADER_SIG {
            return Err(anyhow!(
                "framework.jar local file header for {name}: unexpected signature {lfh_sig:#010x}"
            ));
        }
        let lfh_flags = read_u16_le(bytes, local_header_offset + 6);
        let lfh_uses_data_descriptor = lfh_flags & ZIP_FLAG_DATA_DESCRIPTOR != 0;
        let local_header_crc_offset = local_header_offset + 14;
        let local_name_len = read_u16_le(bytes, local_header_offset + 26) as usize;
        let local_extra_len = read_u16_le(bytes, local_header_offset + 28) as usize;
        let local_variable_len = local_name_len
            .checked_add(local_extra_len)
            .ok_or_else(|| anyhow!("framework.jar local file header length overflow for {name}"))?;
        let data_start = checked_range_end(
            local_fixed_end,
            local_variable_len,
            "framework.jar local file header",
        )?;
        let data_end = checked_range_end(data_start, compressed_size, "framework.jar entry data")?;
        if data_end > bytes.len() {
            return Err(anyhow!(
                "framework.jar entry {} data range {}..{} exceeds jar length {}",
                name,
                data_start,
                data_end,
                bytes.len()
            ));
        }

        entries.push(ZipEntry {
            name,
            data_start,
            compressed_size,
            local_header_crc_offset,
            cd_crc_offset,
            compression_method,
            uses_data_descriptor: cd_uses_data_descriptor || lfh_uses_data_descriptor,
            is_zip64,
        });

        cursor = entry_end;
    }
    Ok(ZipLayout { entries })
}

fn find_eocd(bytes: &[u8]) -> Result<usize> {
    let max_back = std::cmp::min(bytes.len(), 65_557);
    let start = bytes.len().saturating_sub(max_back);
    for off in (start..bytes.len().saturating_sub(21)).rev() {
        if read_u32_le(bytes, off) == ZIP_END_OF_CENTRAL_DIRECTORY_SIG {
            return Ok(off);
        }
    }
    Err(anyhow!(
        "framework.jar EOCD signature not found; not a valid ZIP"
    ))
}

// ---------------------------------------------------------------------------
// LgsiFeatures dex location
// ---------------------------------------------------------------------------

/// Collect every `classes*.dex` entry that mentions
/// `Lcom/lgsi/config/LgsiFeatures;` in its string pool. The descriptor
/// shows up in any dex that *references* the type, but only the dex
/// that *defines* the class also carries its `class_data_item` and
/// `<clinit>`; framework.jar can ship a dozen dexes referencing the
/// type (other classes calling into LgsiFeatures) while the actual
/// class_def lives in only one. The caller (`apply_fuck_lgsi`) walks
/// candidates in order and picks the first whose dex walker returns
/// non-empty.
fn collect_lgsi_features_candidate_dexes(
    jar_bytes: &[u8],
    zip: &ZipLayout,
) -> Result<Vec<ZipEntry>> {
    let needle = build_dex_string_with_uleb_prefix(LGSI_FEATURES_CLASS);
    let mut out = Vec::new();
    for entry in &zip.entries {
        if !entry.name.ends_with(".dex") {
            continue;
        }
        if entry.compression_method != 0 {
            return Err(anyhow!(
                "framework.jar dex entry {} is compressed (method {}); only stored dex entries are supported",
                entry.name,
                entry.compression_method
            ));
        }
        if entry.uses_data_descriptor {
            return Err(anyhow!(
                "framework.jar dex entry {} uses ZIP data-descriptor (flag bit 3); CRC + sizes live in a trailing record this parser does not handle",
                entry.name
            ));
        }
        if entry.is_zip64 {
            return Err(anyhow!(
                "framework.jar dex entry {} uses ZIP64 extended fields ({:#010x} sentinel); ZIP64 is not supported here",
                entry.name,
                ZIP64_SENTINEL_U32
            ));
        }
        let dex_end = checked_range_end(
            entry.data_start,
            entry.compressed_size,
            "framework.jar dex entry",
        )?;
        if dex_end > jar_bytes.len() {
            return Err(anyhow!(
                "framework.jar dex entry {} range {}..{} exceeds jar length {}",
                entry.name,
                entry.data_start,
                dex_end,
                jar_bytes.len()
            ));
        }
        let dex_bytes = &jar_bytes[entry.data_start..dex_end];
        if memmem::find(dex_bytes, &needle).is_some() {
            out.push(entry.clone());
        }
    }
    Ok(out)
}

fn build_dex_string_with_uleb_prefix(needle: &str) -> Vec<u8> {
    let len = needle.len();
    let mut out = Vec::with_capacity(len + 4);
    let mut v = len as u32;
    loop {
        let mut byte = (v & 0x7F) as u8;
        v >>= 7;
        if v != 0 {
            byte |= 0x80;
            out.push(byte);
        } else {
            out.push(byte);
            break;
        }
    }
    out.extend_from_slice(needle.as_bytes());
    out.push(0);
    out
}

// ---------------------------------------------------------------------------
// Dex header recomputation (carryover)
// ---------------------------------------------------------------------------

fn recompute_dex_header_sums(dex: &mut [u8]) {
    let sig = sha1_digest(&dex[32..]);
    dex[12..32].copy_from_slice(&sig);
    let cksum = adler32(&dex[12..]);
    dex[8..12].copy_from_slice(&cksum.to_le_bytes());
}

fn sha1_digest(data: &[u8]) -> [u8; 20] {
    use sha1_hasher::SimpleSha1;
    let mut h = SimpleSha1::new();
    h.update(data);
    h.finalize()
}

fn adler32(data: &[u8]) -> u32 {
    const MOD_ADLER: u32 = 65521;
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for chunk in data.chunks(5552) {
        for &byte in chunk {
            a += byte as u32;
            b += a;
        }
        a %= MOD_ADLER;
        b %= MOD_ADLER;
    }
    (b << 16) | a
}

mod sha1_hasher {
    pub struct SimpleSha1 {
        h: [u32; 5],
        buffer: Vec<u8>,
        total_len: u64,
    }

    impl SimpleSha1 {
        pub fn new() -> Self {
            Self {
                h: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
                buffer: Vec::with_capacity(64),
                total_len: 0,
            }
        }
        pub fn update(&mut self, data: &[u8]) {
            self.total_len = self.total_len.wrapping_add(data.len() as u64);
            let mut data = data;

            if !self.buffer.is_empty() {
                let needed = 64 - self.buffer.len();
                let take = std::cmp::min(needed, data.len());
                self.buffer.extend_from_slice(&data[..take]);
                data = &data[take..];

                if self.buffer.len() == 64 {
                    let block: [u8; 64] = self.buffer[..64].try_into().unwrap();
                    self.process_block(&block);
                    self.buffer.clear();
                }
            }

            let mut chunks = data.chunks_exact(64);
            for chunk in &mut chunks {
                let block: &[u8; 64] = chunk.try_into().unwrap();
                self.process_block(block);
            }
            self.buffer.extend_from_slice(chunks.remainder());
        }
        pub fn finalize(mut self) -> [u8; 20] {
            let bit_len = self.total_len.wrapping_mul(8);
            self.buffer.push(0x80);
            while self.buffer.len() % 64 != 56 {
                self.buffer.push(0);
            }
            self.buffer.extend_from_slice(&bit_len.to_be_bytes());
            while self.buffer.len() >= 64 {
                let block: [u8; 64] = self.buffer[..64].try_into().unwrap();
                self.process_block(&block);
                self.buffer.drain(..64);
            }
            let mut out = [0u8; 20];
            for (i, word) in self.h.iter().enumerate() {
                out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
            }
            out
        }
        fn process_block(&mut self, block: &[u8; 64]) {
            let mut w = [0u32; 80];
            for i in 0..16 {
                w[i] = u32::from_be_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
            }
            for i in 16..80 {
                w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
            }
            let [mut a, mut b, mut c, mut d, mut e] = self.h;
            for i in 0..80 {
                let (f, k) = if i < 20 {
                    ((b & c) | ((!b) & d), 0x5A827999)
                } else if i < 40 {
                    (b ^ c ^ d, 0x6ED9EBA1)
                } else if i < 60 {
                    ((b & c) | (b & d) | (c & d), 0x8F1BBCDC)
                } else {
                    (b ^ c ^ d, 0xCA62C1D6)
                };
                let temp = a
                    .rotate_left(5)
                    .wrapping_add(f)
                    .wrapping_add(e)
                    .wrapping_add(k)
                    .wrapping_add(w[i]);
                e = d;
                d = c;
                c = b.rotate_left(30);
                b = a;
                a = temp;
            }
            self.h[0] = self.h[0].wrapping_add(a);
            self.h[1] = self.h[1].wrapping_add(b);
            self.h[2] = self.h[2].wrapping_add(c);
            self.h[3] = self.h[3].wrapping_add(d);
            self.h[4] = self.h[4].wrapping_add(e);
        }
    }
}

// ---------------------------------------------------------------------------
// CRC32 (carryover)
// ---------------------------------------------------------------------------

fn crc32_ieee(data: &[u8]) -> u32 {
    let mut table = [0u32; 256];
    for n in 0..256 {
        let mut c = n as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 {
                0xEDB88320 ^ (c >> 1)
            } else {
                c >> 1
            };
        }
        table[n] = c;
    }
    let mut crc = 0xFFFFFFFFu32;
    for &b in data {
        crc = table[((crc ^ b as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc ^ 0xFFFFFFFF
}

// ---------------------------------------------------------------------------
// Misc helpers (carryover)
// ---------------------------------------------------------------------------

fn read_u16_le(bytes: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(bytes[off..off + 2].try_into().unwrap())
}

fn read_u32_le(bytes: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap())
}

fn checked_range_end(start: usize, len: usize, label: &str) -> Result<usize> {
    start
        .checked_add(len)
        .ok_or_else(|| anyhow!("{label} offset overflow"))
}

fn write_u32_le(bytes: &mut [u8], off: usize, value: u32) {
    bytes[off..off + 4].copy_from_slice(&value.to_le_bytes());
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adler32_known_values() {
        assert_eq!(adler32(b""), 1);
        assert_eq!(adler32(b"abc"), 0x024D0127);
        assert_eq!(adler32(b"Wikipedia"), 0x11E60398);
    }

    /// Smoke test against a real TB323 framework.jar if the dump is on
    /// the developer's machine. Walks ZIP -> finds candidate dexes ->
    /// runs `extract_lgsi_features` on each. Asserts at least one
    /// candidate returns `Found`. Surfaces per-dex diagnostics so
    /// regressions point at the failing lookup step. Silent no-op when
    /// the dump path doesn't exist (CI / fresh checkouts).
    #[test]
    fn extract_real_framework_jar_when_available() {
        let path = std::path::Path::new(
            r"D:\Git\Project-DeZUX\dump\TB323_ZUXOS_2.0.11.043_Tool\system\framework\framework.jar",
        );
        let Ok(jar_bytes) = std::fs::read(path) else {
            return;
        };
        let zip = parse_zip_central_directory(&jar_bytes).expect("zip parse");
        let candidates =
            collect_lgsi_features_candidate_dexes(&jar_bytes, &zip).expect("candidate collect");
        assert!(
            !candidates.is_empty(),
            "no dex candidates in real framework.jar"
        );
        let mut diagnostics: Vec<String> = Vec::new();
        let mut found_any = false;
        for entry in &candidates {
            let dex_data_end = entry.data_start + entry.compressed_size;
            let dex_bytes = &jar_bytes[entry.data_start..dex_data_end];
            match dex_walker::extract_lgsi_features(dex_bytes).expect("extract ok") {
                dex_walker::DexExtractOutcome::Found(features) => {
                    assert!(
                        !features.is_empty(),
                        "Found variant must carry features for {}",
                        entry.name
                    );
                    eprintln!(
                        "real framework.jar: {} -> {} features",
                        entry.name,
                        features.len()
                    );
                    found_any = true;
                    break;
                }
                dex_walker::DexExtractOutcome::NotApplicable(reason) => {
                    diagnostics.push(format!("{}: {reason}", entry.name));
                }
            }
        }
        assert!(
            found_any,
            "no dex candidate in real framework.jar resolved to LgsiFeatures \
             registrations. Per-dex diagnostics: {}",
            diagnostics.join("; ")
        );
    }

    #[test]
    fn crc32_ieee_known_values() {
        assert_eq!(crc32_ieee(b""), 0);
        assert_eq!(crc32_ieee(b"123456789"), 0xCBF43926);
    }

    #[test]
    fn sha1_known_values() {
        let d = sha1_digest(b"abc");
        let expected: [u8; 20] = [
            0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
            0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
        ];
        assert_eq!(d, expected);
    }

    #[test]
    fn build_dex_string_with_uleb_prefix_round_trip() {
        let s = build_dex_string_with_uleb_prefix("zh");
        assert_eq!(s, vec![0x02, b'z', b'h', 0x00]);
    }

    #[test]
    fn parse_zip_central_directory_rejects_truncated_entry_name() {
        let mut jar = vec![0u8; 46 + 22];
        jar[0..4].copy_from_slice(&ZIP_CENTRAL_DIRECTORY_SIG.to_le_bytes());
        jar[28..30].copy_from_slice(&1000u16.to_le_bytes());
        let eocd = 46;
        jar[eocd..eocd + 4].copy_from_slice(&ZIP_END_OF_CENTRAL_DIRECTORY_SIG.to_le_bytes());
        jar[eocd + 10..eocd + 12].copy_from_slice(&1u16.to_le_bytes());
        jar[eocd + 12..eocd + 16].copy_from_slice(&46u32.to_le_bytes());
        jar[eocd + 16..eocd + 20].copy_from_slice(&0u32.to_le_bytes());

        assert!(parse_zip_central_directory(&jar).is_err());
    }
}
