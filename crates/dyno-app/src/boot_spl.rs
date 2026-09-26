//! Re-sign `boot.img` and patch its
//! `com.android.build.boot.security_patch` AVB property descriptor.
//!
//! The patch is an in-place byte rewrite on the descriptors blob: date strings
//! are always 10 bytes, so the descriptor body keeps the same padded size and
//! no header offsets need to be recomputed. `avbtool-rs` first verifies and
//! re-signs the still-valid input image; the property is then rewritten and
//! the authentication block is refreshed over the unchanged-size VBMeta data.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use avbtool_rs::crypto::{
    AvbMldsaPublicKey, AvbPublicKey, compute_hash_for_algorithm, extract_public_key,
    is_mldsa_algorithm, load_key_from_spec, load_mldsa_key_from_spec, lookup_algorithm_by_type,
};
use avbtool_rs::parser::{
    AVB_FOOTER_SIZE, AVB_VBMETA_IMAGE_HEADER_SIZE, AvbFooter, AvbImageType, AvbVBMetaHeader,
    detect_avb_image_type,
};
use avbtool_rs::resign::{ResignOutcome, resign_image_with_options};

use crate::avb_descriptor::{PatchPropertyOutcome, patch_property_value};

pub const BOOT_SPL_PROPERTY: &str = "com.android.build.boot.security_patch";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootSplPatchOutcome {
    Patched { old: String, new: String },
    SkippedNotNewer { old: String, requested: String },
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootSplResignOutcome {
    /// Result returned by the normal `avbtool-rs` resign operation.
    pub resign: ResignOutcome,
    /// Result of the subsequent same-size boot SPL property update.
    pub spl: BootSplPatchOutcome,
}

/// A VBMeta image that avbtool-rs has verified and re-signed before DynoBox
/// performs a known, same-size descriptor mutation.
#[derive(Debug)]
pub struct PreparedVbmetaResign {
    image_path: PathBuf,
    key_spec: String,
    outcome: ResignOutcome,
}

impl PreparedVbmetaResign {
    /// Recompute the authentication block over the descriptor bytes written
    /// after preparation and return the original resign outcome.
    pub fn finish(self) -> Result<ResignOutcome> {
        refresh_vbmeta_authentication(&self.image_path, &self.key_spec)?;
        Ok(self.outcome)
    }
}

/// Verify and re-sign an untouched VBMeta image before a caller applies a
/// trusted same-size descriptor mutation. The returned marker must be finished
/// after all mutations to authenticate the final header + auxiliary data.
pub fn prepare_vbmeta_for_descriptor_mutation(
    image_path: &Path,
    key_spec: &str,
    algorithm_name: Option<&str>,
    force: bool,
    rollback_index: Option<u64>,
) -> Result<PreparedVbmetaResign> {
    ensure_dense_avb_image(image_path)?;
    let outcome = resign_image_with_options(
        image_path,
        key_spec,
        algorithm_name,
        force,
        rollback_index,
        false,
    )
    .with_context(|| {
        format!(
            "failed to verify and re-sign {} before descriptor mutation",
            image_path.display()
        )
    })?;
    Ok(PreparedVbmetaResign {
        image_path: image_path.to_path_buf(),
        key_spec: key_spec.to_string(),
        outcome,
    })
}

/// Validate that `spl` is a strict `YYYY-MM-DD` 10-byte ASCII string. The
/// in-place patch relies on the new value matching the existing length.
pub fn validate_spl_format(spl: &str) -> Result<()> {
    crate::spl::validate_spl_format("--boot-spl", spl)
}

/// Read the current value of the boot security_patch property descriptor.
/// Returns `Ok(None)` when the image has no AVB metadata or no such property.
pub fn read_security_patch(image_path: &Path) -> Result<Option<String>> {
    crate::avb_descriptor::read_property_value(image_path, BOOT_SPL_PROPERTY)
}

/// Patch the `com.android.build.boot.security_patch` property descriptor in
/// `image_path` to `new_spl`. The new value must be lexicographically greater
/// than the existing one (which, for `YYYY-MM-DD`, matches chronological order).
///
/// The descriptors blob layout is preserved because both the existing and the
/// new value are 10 bytes. The image is left with a stale signature; the caller
/// is expected to re-sign immediately after.
pub fn patch_security_patch(image_path: &Path, new_spl: &str) -> Result<BootSplPatchOutcome> {
    validate_spl_format(new_spl)?;

    // Read the current value first so the not-newer skip and the
    // "Patched { old, new }" logging both work without rereading.
    let current_value = match read_security_patch(image_path)? {
        Some(value) => value,
        None => return Ok(BootSplPatchOutcome::NotFound),
    };

    if new_spl <= current_value.as_str() {
        return Ok(BootSplPatchOutcome::SkippedNotNewer {
            old: current_value,
            requested: new_spl.to_string(),
        });
    }

    match patch_property_value(image_path, BOOT_SPL_PROPERTY, new_spl.as_bytes())? {
        PatchPropertyOutcome::Patched { old_value } => Ok(BootSplPatchOutcome::Patched {
            old: old_value,
            new: new_spl.to_string(),
        }),
        PatchPropertyOutcome::NotFound => Ok(BootSplPatchOutcome::NotFound),
        PatchPropertyOutcome::LengthMismatch {
            current_value,
            current_len,
            requested_len,
        } => Err(anyhow!(
            "Cannot patch boot SPL in place on {}: existing value {:?} ({} bytes) does not match new value length ({} bytes). Only same-length YYYY-MM-DD replacements are supported.",
            image_path.display(),
            current_value,
            current_len,
            requested_len
        )),
    }
}

/// Re-sign a valid boot image, then apply the same-length SPL property update
/// and refresh only its VBMeta authentication block.
///
/// `avbtool-rs` 0.2 verifies an image before re-signing it. Applying the SPL
/// update first would intentionally stale that signature and make the signer
/// reject a mutation DynoBox itself just performed. This ordering preserves
/// the dependency's verification of the original image while still signing
/// the final descriptor bytes.
pub fn resign_image_with_security_patch(
    image_path: &Path,
    key_spec: &str,
    algorithm_name: Option<&str>,
    force: bool,
    rollback_index: Option<u64>,
    new_spl: &str,
) -> Result<BootSplResignOutcome> {
    validate_spl_format(new_spl)?;
    ensure_dense_avb_image(image_path)?;
    let current_spl = read_security_patch(image_path)?.ok_or_else(|| {
        anyhow!(
            "boot.img has no {} property descriptor; cannot apply --boot-spl",
            BOOT_SPL_PROPERTY
        )
    })?;
    if current_spl.len() != new_spl.len() {
        return Err(anyhow!(
            "cannot patch boot SPL in place: existing value {:?} is {} bytes but requested value is {} bytes",
            current_spl,
            current_spl.len(),
            new_spl.len()
        ));
    }
    validate_spl_format(&current_spl)
        .context("boot image contains an invalid security patch date")?;

    let resign = resign_image_with_options(
        image_path,
        key_spec,
        algorithm_name,
        force,
        rollback_index,
        false,
    )
    .with_context(|| {
        format!(
            "failed to re-sign {} before boot SPL patch",
            image_path.display()
        )
    })?;
    let spl = patch_security_patch(image_path, new_spl)?;
    if matches!(spl, BootSplPatchOutcome::Patched { .. }) {
        refresh_vbmeta_authentication(image_path, key_spec)?;
    }

    Ok(BootSplResignOutcome { resign, spl })
}

pub(crate) fn refresh_vbmeta_authentication(image_path: &Path, key_spec: &str) -> Result<()> {
    let vbmeta = avbtool_rs::image::load_vbmeta_blob(image_path)
        .with_context(|| format!("failed to read VBMeta from {}", image_path.display()))?;
    if vbmeta.len() < AVB_VBMETA_IMAGE_HEADER_SIZE {
        return Err(anyhow!("VBMeta blob is shorter than its header"));
    }
    let header = AvbVBMetaHeader::from_reader(&vbmeta[..AVB_VBMETA_IMAGE_HEADER_SIZE])?;
    if header.algorithm_type == 0 {
        return Ok(());
    }

    let auth_size = usize::try_from(header.authentication_data_block_size)
        .context("VBMeta authentication block is too large")?;
    let aux_size = usize::try_from(header.auxiliary_data_block_size)
        .context("VBMeta auxiliary block is too large")?;
    let aux_start = AVB_VBMETA_IMAGE_HEADER_SIZE
        .checked_add(auth_size)
        .ok_or_else(|| anyhow!("VBMeta auxiliary offset overflow"))?;
    let aux_end = aux_start
        .checked_add(aux_size)
        .filter(|&end| end <= vbmeta.len())
        .ok_or_else(|| anyhow!("VBMeta auxiliary block exceeds the blob"))?;
    let algorithm = lookup_algorithm_by_type(header.algorithm_type)?;

    let public_key_start = aux_start
        .checked_add(usize::try_from(header.public_key_offset)?)
        .ok_or_else(|| anyhow!("VBMeta public-key offset overflow"))?;
    let public_key_end = public_key_start
        .checked_add(usize::try_from(header.public_key_size)?)
        .filter(|&end| end <= aux_end)
        .ok_or_else(|| anyhow!("VBMeta public key exceeds the auxiliary block"))?;
    let expected_public_key = extract_public_key(key_spec)?;
    if vbmeta[public_key_start..public_key_end] != expected_public_key {
        return Err(anyhow!(
            "VBMeta public key does not match the requested signing key"
        ));
    }

    let mut data_to_sign = Vec::with_capacity(AVB_VBMETA_IMAGE_HEADER_SIZE + aux_size);
    data_to_sign.extend_from_slice(&vbmeta[..AVB_VBMETA_IMAGE_HEADER_SIZE]);
    data_to_sign.extend_from_slice(&vbmeta[aux_start..aux_end]);
    let signature = if is_mldsa_algorithm(algorithm.name) {
        load_mldsa_key_from_spec(key_spec)?.sign(&data_to_sign, algorithm.name)?
    } else {
        load_key_from_spec(key_spec)?.sign(&data_to_sign, algorithm.name)?
    };
    let hash = compute_hash_for_algorithm(algorithm, &data_to_sign)?;
    if hash.len() != usize::try_from(header.hash_size)?
        || signature.len() != usize::try_from(header.signature_size)?
    {
        return Err(anyhow!(
            "generated VBMeta authentication sizes do not match the header"
        ));
    }

    let hash_start = usize::try_from(header.hash_offset)?;
    let hash_end = hash_start
        .checked_add(hash.len())
        .filter(|&end| end <= auth_size)
        .ok_or_else(|| anyhow!("VBMeta hash exceeds the authentication block"))?;
    let signature_start = usize::try_from(header.signature_offset)?;
    let signature_end = signature_start
        .checked_add(signature.len())
        .filter(|&end| end <= auth_size)
        .ok_or_else(|| anyhow!("VBMeta signature exceeds the authentication block"))?;
    if hash_start < signature_end && signature_start < hash_end {
        return Err(anyhow!("VBMeta hash and signature ranges overlap"));
    }

    let signature_valid = if is_mldsa_algorithm(algorithm.name) {
        AvbMldsaPublicKey::decode(algorithm.name, &expected_public_key)?.verify(
            algorithm,
            &signature,
            &data_to_sign,
        )?
    } else {
        AvbPublicKey::decode(&expected_public_key)?.verify(algorithm, &signature, &data_to_sign)?
    };
    if !signature_valid {
        return Err(anyhow!("generated VBMeta signature did not verify"));
    }

    let mut authentication = vec![0u8; auth_size];
    authentication[hash_start..hash_end].copy_from_slice(&hash);
    authentication[signature_start..signature_end].copy_from_slice(&signature);
    let vbmeta_offset = locate_dense_vbmeta_offset(image_path)?;
    let auth_file_offset = vbmeta_offset
        .checked_add(AVB_VBMETA_IMAGE_HEADER_SIZE as u64)
        .ok_or_else(|| anyhow!("VBMeta authentication file offset overflow"))?;
    let mut file = OpenOptions::new().read(true).write(true).open(image_path)?;
    file.seek(SeekFrom::Start(auth_file_offset))?;
    file.write_all(&authentication)?;
    file.sync_data()?;

    let persisted = avbtool_rs::image::load_vbmeta_blob(image_path)?;
    let persisted_auth_end = AVB_VBMETA_IMAGE_HEADER_SIZE
        .checked_add(auth_size)
        .filter(|&end| end <= persisted.len())
        .ok_or_else(|| anyhow!("persisted VBMeta authentication block is truncated"))?;
    if persisted.len() < aux_end
        || persisted[..AVB_VBMETA_IMAGE_HEADER_SIZE] != vbmeta[..AVB_VBMETA_IMAGE_HEADER_SIZE]
        || persisted[aux_start..aux_end] != vbmeta[aux_start..aux_end]
    {
        return Err(anyhow!(
            "VBMeta header or auxiliary data changed during authentication refresh"
        ));
    }
    if persisted[AVB_VBMETA_IMAGE_HEADER_SIZE..persisted_auth_end] != authentication {
        return Err(anyhow!("VBMeta authentication write did not persist"));
    }
    Ok(())
}

fn ensure_dense_avb_image(image_path: &Path) -> Result<()> {
    let image =
        avbtool_rs::sparse::ImageHandler::open(image_path, true).map_err(|error| anyhow!(error))?;
    if image.is_sparse() {
        return Err(anyhow!(
            "cannot mutate VBMeta descriptors in an Android sparse image"
        ));
    }
    if detect_avb_image_type(image_path)? == AvbImageType::None {
        return Err(anyhow!("image has no AVB metadata"));
    }
    Ok(())
}

fn locate_dense_vbmeta_offset(image_path: &Path) -> Result<u64> {
    match detect_avb_image_type(image_path)? {
        AvbImageType::Vbmeta => Ok(0),
        AvbImageType::Footer => {
            let mut file = File::open(image_path)?;
            let file_size = file.metadata()?.len();
            if file_size < AVB_FOOTER_SIZE {
                return Err(anyhow!("AVB footer image is shorter than its footer"));
            }
            file.seek(SeekFrom::End(-(AVB_FOOTER_SIZE as i64)))?;
            let mut footer_bytes = vec![0u8; AVB_FOOTER_SIZE as usize];
            file.read_exact(&mut footer_bytes)?;
            let footer = AvbFooter::from_reader(footer_bytes.as_slice())?;
            footer
                .vbmeta_offset
                .checked_add(footer.vbmeta_size)
                .filter(|&end| end <= file_size)
                .ok_or_else(|| anyhow!("AVB footer points outside the image"))?;
            Ok(footer.vbmeta_offset)
        }
        AvbImageType::None => Err(anyhow!("image has no AVB metadata")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signed_boot_vbmeta(path: &Path, spl: Option<&str>, algorithm_name: &str, key_spec: &str) {
        use avbtool_rs::builder::{PropertySpec, VbmetaImageArgs, make_vbmeta_image};

        make_vbmeta_image(
            path,
            &VbmetaImageArgs {
                algorithm_name: algorithm_name.to_string(),
                key_spec: Some(key_spec.to_string()),
                public_key_metadata: None,
                rollback_index: 0,
                flags: 0,
                rollback_index_location: 0,
                properties: spl
                    .map(|value| PropertySpec {
                        key: BOOT_SPL_PROPERTY.to_string(),
                        value: value.as_bytes().to_vec(),
                    })
                    .into_iter()
                    .collect(),
                kernel_cmdlines: Vec::new(),
                extra_descriptors: Vec::new(),
                include_descriptors_from_images: Vec::new(),
                chain_partitions: Vec::new(),
                release_string: None,
                append_to_release_string: None,
                padding_size: 0,
            },
        )
        .unwrap();
    }

    #[test]
    fn resign_then_patch_refreshes_vbmeta_authentication() {
        use avbtool_rs::resign::ResignOutcome;
        use avbtool_rs::verify::{VerifyImageOptions, verify_image};

        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("boot-vbmeta.img");
        signed_boot_vbmeta(
            &image,
            Some("2025-02-05"),
            "SHA256_RSA2048",
            "testkey_rsa2048",
        );

        let outcome = resign_image_with_security_patch(
            &image,
            "testkey_rsa2048_2",
            None,
            false,
            Some(123),
            "2026-02-05",
        )
        .unwrap();

        assert_eq!(outcome.resign, ResignOutcome::Resigned);
        assert_eq!(
            outcome.spl,
            BootSplPatchOutcome::Patched {
                old: "2025-02-05".to_string(),
                new: "2026-02-05".to_string(),
            }
        );
        assert_eq!(
            read_security_patch(&image).unwrap().as_deref(),
            Some("2026-02-05")
        );
        assert_eq!(
            avbtool_rs::image::inspect_avb_image(&image)
                .unwrap()
                .header
                .rollback_index,
            123
        );
        verify_image(
            &image,
            &VerifyImageOptions {
                key_blob: Some(
                    avbtool_rs::crypto::extract_public_key("testkey_rsa2048_2").unwrap(),
                ),
                expected_chain_partitions: Vec::new(),
                follow_chain_partitions: false,
                accept_zeroed_hashtree: false,
            },
        )
        .unwrap();
    }

    #[test]
    fn prepared_vbmeta_resign_allows_descriptor_mutation_after_v02_verification() {
        use avbtool_rs::resign::ResignOutcome;
        use avbtool_rs::verify::{VerifyImageOptions, verify_image};

        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("vbmeta.img");
        signed_boot_vbmeta(
            &image,
            Some("2025-02-05"),
            "SHA256_RSA2048",
            "testkey_rsa2048",
        );

        let prepared = prepare_vbmeta_for_descriptor_mutation(
            &image,
            "testkey_rsa2048_2",
            None,
            false,
            Some(456),
        )
        .unwrap();
        let patch = patch_property_value(&image, BOOT_SPL_PROPERTY, b"2026-02-05").unwrap();
        assert!(matches!(patch, PatchPropertyOutcome::Patched { .. }));

        assert_eq!(prepared.finish().unwrap(), ResignOutcome::Resigned);
        assert_eq!(
            read_security_patch(&image).unwrap().as_deref(),
            Some("2026-02-05")
        );
        assert_eq!(
            avbtool_rs::image::inspect_avb_image(&image)
                .unwrap()
                .header
                .rollback_index,
            456
        );
        verify_image(
            &image,
            &VerifyImageOptions {
                key_blob: Some(
                    avbtool_rs::crypto::extract_public_key("testkey_rsa2048_2").unwrap(),
                ),
                expected_chain_partitions: Vec::new(),
                follow_chain_partitions: false,
                accept_zeroed_hashtree: false,
            },
        )
        .unwrap();
    }

    #[test]
    fn resign_then_patch_refuses_tampered_original_before_mutation() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("tampered-boot-vbmeta.img");
        signed_boot_vbmeta(
            &image,
            Some("2025-02-05"),
            "SHA256_RSA2048",
            "testkey_rsa2048",
        );
        let mut bytes = std::fs::read(&image).unwrap();
        bytes[AVB_VBMETA_IMAGE_HEADER_SIZE + 8] ^= 0xff;
        std::fs::write(&image, bytes).unwrap();
        let tampered_before = std::fs::read(&image).unwrap();

        let error = resign_image_with_security_patch(
            &image,
            "testkey_rsa2048_2",
            None,
            false,
            None,
            "2026-02-05",
        )
        .unwrap_err();
        let error = format!("{error:#}");

        assert!(error.contains("signature verification failed"), "{error}");
        assert_eq!(std::fs::read(&image).unwrap(), tampered_before);
        assert_eq!(
            read_security_patch(&image).unwrap().as_deref(),
            Some("2025-02-05")
        );
    }

    #[test]
    fn missing_boot_spl_property_is_rejected_before_resign() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("missing-property-vbmeta.img");
        signed_boot_vbmeta(&image, None, "SHA256_RSA2048", "testkey_rsa2048");
        let before = std::fs::read(&image).unwrap();

        let error = resign_image_with_security_patch(
            &image,
            "testkey_rsa2048_2",
            None,
            false,
            None,
            "2026-02-05",
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("has no com.android.build.boot.security_patch"));
        assert_eq!(std::fs::read(&image).unwrap(), before);
    }

    #[test]
    fn resign_then_patch_supports_sha512_and_mldsa() {
        use avbtool_rs::verify::{VerifyImageOptions, verify_image};

        for (algorithm, old_key, new_key) in [
            ("SHA512_RSA2048", "testkey_rsa2048", "testkey_rsa2048_2"),
            ("MLDSA65", "testkey_mldsa65", "testkey_mldsa65"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let image = dir.path().join(format!("{algorithm}.img"));
            signed_boot_vbmeta(&image, Some("2025-02-05"), algorithm, old_key);

            resign_image_with_security_patch(
                &image,
                new_key,
                Some(algorithm),
                false,
                None,
                "2026-02-05",
            )
            .unwrap();

            verify_image(
                &image,
                &VerifyImageOptions {
                    key_blob: Some(avbtool_rs::crypto::extract_public_key(new_key).unwrap()),
                    expected_chain_partitions: Vec::new(),
                    follow_chain_partitions: false,
                    accept_zeroed_hashtree: false,
                },
            )
            .unwrap();
        }
    }

    #[test]
    #[ignore = "fixture: set DYNOBOX_BOOT_SPL_IMAGE"]
    fn resign_then_patch_lands_on_real_boot_image() {
        use avbtool_rs::verify::{VerifyImageOptions, verify_image};

        let source = crate::test_fixtures::env("DYNOBOX_BOOT_SPL_IMAGE");
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("boot.img");
        std::fs::copy(source, &image).unwrap();
        let original_len = std::fs::metadata(&image).unwrap().len();

        let outcome = resign_image_with_security_patch(
            &image,
            "testkey_rsa4096",
            None,
            false,
            None,
            "2026-02-05",
        )
        .unwrap();

        assert!(matches!(outcome.spl, BootSplPatchOutcome::Patched { .. }));
        assert_eq!(std::fs::metadata(&image).unwrap().len(), original_len);
        assert_eq!(
            read_security_patch(&image).unwrap().as_deref(),
            Some("2026-02-05")
        );
        verify_image(
            &image,
            &VerifyImageOptions {
                key_blob: Some(avbtool_rs::crypto::extract_public_key("testkey_rsa4096").unwrap()),
                expected_chain_partitions: Vec::new(),
                follow_chain_partitions: false,
                accept_zeroed_hashtree: false,
            },
        )
        .unwrap();
    }

    #[test]
    fn validate_spl_format_accepts_iso_date() {
        assert!(validate_spl_format("2026-04-05").is_ok());
        assert!(validate_spl_format("1970-01-01").is_ok());
    }

    #[test]
    fn validate_spl_format_rejects_bad_inputs() {
        assert!(validate_spl_format("2026/04/05").is_err());
        assert!(validate_spl_format("2026-4-5").is_err());
        assert!(validate_spl_format("26-04-05").is_err());
        assert!(validate_spl_format("").is_err());
        assert!(validate_spl_format("2026-04-05 ").is_err());
        assert!(validate_spl_format("2026-00-05").is_err());
        assert!(validate_spl_format("2026-13-05").is_err());
        assert!(validate_spl_format("2026-04-31").is_err());
        assert!(validate_spl_format("2025-02-29").is_err());
    }
}
