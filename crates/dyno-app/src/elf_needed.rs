//! Minimal ELF64/AArch64 `DT_NEEDED` injection.
//!
//! `app_process64` runs under a secure-exec context on user builds, so the
//! dynamic linker ignores the `LD_PRELOAD` that the zygote service sets. Adding
//! the preload library to the executable's own `DT_NEEDED` list makes the
//! linker map it before `libandroid_runtime.so`, independent of `AT_SECURE`.
//! The same in-place patch gives init-native executables such as
//! `bootanimation`, which never runs through the zygote, the preload too.
//!
//! The patch keeps the file length unchanged. It copies the dynamic table and
//! the string table into the zero-filled tail of the writable `PT_LOAD` that
//! already owns `PT_DYNAMIC`, prepends the new `DT_NEEDED` entry, updates
//! `DT_STRTAB`/`DT_STRSZ`, and points `PT_DYNAMIC` (and the matching section
//! headers) at the copy. The original tables stay in place so old addresses in
//! the rest of the file remain valid.

use anyhow::{Result, anyhow, bail};

const ELF_HEADER_SIZE: usize = 64;
const PROGRAM_HEADER_SIZE: usize = 56;
const SECTION_HEADER_SIZE: usize = 64;
const DYNAMIC_ENTRY_SIZE: usize = 16;

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PF_W: u32 = 2;

const DT_NULL: i64 = 0;
const DT_NEEDED: i64 = 1;
const DT_STRTAB: i64 = 5;
const DT_STRSZ: i64 = 10;
const DT_DEBUG: i64 = 0x15;

const ELF_MAGIC: &[u8; 4] = b"\x7fELF";
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const ET_DYN: u16 = 3;
const EM_AARCH64: u16 = 183;

#[derive(Clone, Copy)]
struct ProgramHeader {
    index: usize,
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
}

struct Layout {
    phoff: usize,
    phentsize: usize,
    phdrs: Vec<ProgramHeader>,
    shoff: usize,
    shentsize: usize,
    shnum: usize,
    shstrndx: usize,
}

/// Add `needed` as the first `DT_NEEDED` entry of `bytes`.
///
/// Returns `Ok(None)` when the library is already listed, so applying the same
/// payload to an already-patched image is a no-op.
pub fn add_needed(bytes: &[u8], needed: &str) -> Result<Option<Vec<u8>>> {
    if needed.is_empty() {
        bail!("elf: empty DT_NEEDED name");
    }
    if needed.bytes().any(|b| b == 0 || b == b'/') {
        bail!("elf: DT_NEEDED name `{needed}` must be a plain soname");
    }

    let layout = parse_layout(bytes)?;
    let dynamic = layout
        .phdrs
        .iter()
        .find(|p| p.p_type == PT_DYNAMIC)
        .copied()
        .ok_or_else(|| anyhow!("elf: no PT_DYNAMIC segment"))?;
    let entries = read_dynamic(bytes, &dynamic)?;

    let strtab_vaddr =
        dynamic_value(&entries, DT_STRTAB).ok_or_else(|| anyhow!("elf: no DT_STRTAB"))?;
    let strsz = dynamic_value(&entries, DT_STRSZ).ok_or_else(|| anyhow!("elf: no DT_STRSZ"))?;
    let strtab_off = vaddr_to_offset(&layout.phdrs, strtab_vaddr, strsz)
        .ok_or_else(|| anyhow!("elf: DT_STRTAB is not inside a file-backed PT_LOAD"))?;
    let strtab_end = strtab_off
        .checked_add(strsz)
        .ok_or_else(|| anyhow!("elf: DT_STRSZ overflow"))?;
    let strtab = bytes
        .get(strtab_off as usize..strtab_end as usize)
        .ok_or_else(|| anyhow!("elf: DT_STRTAB extends past the file"))?;

    for &(tag, value) in &entries {
        if tag != DT_NEEDED {
            continue;
        }
        let name = string_at(strtab, value as usize)
            .ok_or_else(|| anyhow!("elf: DT_NEEDED offset {value} is outside DT_STRTAB"))?;
        if name == needed {
            return Ok(None);
        }
    }

    let load = layout
        .phdrs
        .iter()
        .find(|p| {
            p.p_type == PT_LOAD
                && dynamic.p_offset >= p.p_offset
                && dynamic.p_offset + dynamic.p_filesz <= p.p_offset + p.p_filesz
                && dynamic.p_vaddr >= p.p_vaddr
                && dynamic.p_vaddr + dynamic.p_memsz <= p.p_vaddr + p.p_memsz
        })
        .copied()
        .ok_or_else(|| anyhow!("elf: PT_DYNAMIC is not inside a PT_LOAD"))?;
    if load.p_flags & PF_W == 0 {
        bail!("elf: the PT_LOAD that owns PT_DYNAMIC is not writable");
    }
    if dynamic.p_vaddr - load.p_vaddr != dynamic.p_offset - load.p_offset {
        bail!("elf: PT_DYNAMIC vaddr/file offset are not congruent with its PT_LOAD");
    }
    if load.p_align != 0 && load.p_vaddr % load.p_align != load.p_offset % load.p_align {
        bail!("elf: PT_LOAD vaddr/file offset are not aligned");
    }

    // Put the copy in the writable segment's .bss/relro tail, immediately after
    // the file-backed bytes. The 4 KiB block that holds PT_DYNAMIC is already
    // allocated in the partition image, so writing inside the same block works
    // even when the rest of the file is sparse (the ext4 writer skips holes).
    let new_vaddr = align_up(
        load.p_vaddr
            .checked_add(load.p_filesz)
            .ok_or_else(|| anyhow!("elf: PT_LOAD vaddr overflow"))?,
        16,
    )?;
    let block_end = align_up(new_vaddr, 0x1000)?;
    let segment_end = load
        .p_vaddr
        .checked_add(load.p_memsz)
        .ok_or_else(|| anyhow!("elf: PT_LOAD memsz overflow"))?;
    let mut kept = 0usize;
    for &(tag, _) in &entries {
        if tag != DT_NULL && tag != DT_DEBUG {
            kept += 1;
        }
    }
    let dynamic_size = (kept as u64 + 2) // new DT_NEEDED + DT_NULL
        .checked_mul(DYNAMIC_ENTRY_SIZE as u64)
        .ok_or_else(|| anyhow!("elf: dynamic table size overflow"))?;
    let strtab_size = strsz
        .checked_add(needed.len() as u64 + 1)
        .ok_or_else(|| anyhow!("elf: string table size overflow"))?;
    let total = dynamic_size
        .checked_add(strtab_size)
        .ok_or_else(|| anyhow!("elf: patch size overflow"))?;
    let new_end = new_vaddr
        .checked_add(total)
        .ok_or_else(|| anyhow!("elf: patch vaddr overflow"))?;
    if new_end > block_end {
        bail!("elf: the patched dynamic/string tables do not fit in the PT_LOAD's page");
    }
    if new_end > segment_end {
        bail!("elf: the patched dynamic/string tables do not fit in the PT_LOAD");
    }
    let new_offset = load
        .p_offset
        .checked_add(new_vaddr - load.p_vaddr)
        .ok_or_else(|| anyhow!("elf: patch file offset overflow"))?;
    let new_offset_end = new_offset
        .checked_add(total)
        .ok_or_else(|| anyhow!("elf: patch file end overflow"))?;
    let new_strtab_vaddr = new_vaddr + dynamic_size;
    let new_strtab_offset = new_offset + dynamic_size;

    let file_len = bytes.len() as u64;
    if new_offset_end > file_len {
        bail!(
            "elf: no room for the patched dynamic/string tables (need {new_offset_end:#x} bytes, file is {file_len:#x})"
        );
    }

    let filesz = new_end - load.p_vaddr;
    let memsz = align_up(filesz, 0x1000)?.max(load.p_memsz);
    let mapped_end = load
        .p_vaddr
        .checked_add(memsz)
        .ok_or_else(|| anyhow!("elf: PT_LOAD memsz overflow"))?;

    for other in layout.phdrs.iter().filter(|p| p.p_type == PT_LOAD) {
        if other.index == load.index {
            continue;
        }
        if ranges_overlap(
            new_vaddr,
            mapped_end,
            other.p_vaddr,
            other.p_vaddr + other.p_memsz,
        ) {
            bail!("elf: patched virtual range overlaps another PT_LOAD");
        }
        if ranges_overlap(
            new_offset,
            new_offset_end,
            other.p_offset,
            other.p_offset + other.p_filesz,
        ) {
            bail!("elf: patched file range overlaps another PT_LOAD");
        }
    }

    if layout.shoff != 0 && layout.shnum != 0 {
        let sh_size = layout
            .shnum
            .checked_mul(layout.shentsize)
            .ok_or_else(|| anyhow!("elf: section header table overflow"))?;
        let sh_end = layout
            .shoff
            .checked_add(sh_size)
            .ok_or_else(|| anyhow!("elf: section header table overflow"))?;
        if ranges_overlap(
            new_offset,
            new_offset_end,
            layout.shoff as u64,
            sh_end as u64,
        ) {
            bail!("elf: patched file range overlaps the section header table");
        }
        if let Some((shstr_offset, shstr_size)) = section_names_range(bytes, &layout) {
            if ranges_overlap(
                new_offset,
                new_offset_end,
                shstr_offset,
                shstr_offset + shstr_size,
            ) {
                bail!("elf: patched file range overlaps the section name table");
            }
        }
    }

    let mut dynamic_entries: Vec<(i64, u64)> = Vec::with_capacity(kept + 2);
    dynamic_entries.push((DT_NEEDED, strsz));
    for &(tag, value) in &entries {
        if tag == DT_NULL || tag == DT_DEBUG {
            // The copy lives in the RELRO tail, so drop the one dynamic entry
            // the linker writes to; there is no r_debug consumer for zygote.
            continue;
        }
        let value = match tag {
            DT_STRTAB => new_strtab_vaddr,
            DT_STRSZ => strtab_size,
            _ => value,
        };
        dynamic_entries.push((tag, value));
    }
    dynamic_entries.push((DT_NULL, 0));
    debug_assert_eq!(
        dynamic_entries.len() as u64 * DYNAMIC_ENTRY_SIZE as u64,
        dynamic_size
    );

    let mut out = bytes.to_vec();

    // The tail of the writable segment becomes file-backed. Keep the bytes that
    // used to be zero-filled .bss zero-filled.
    let bss_start = (load.p_offset + load.p_filesz) as usize;
    let new_offset_usize = new_offset as usize;
    if bss_start < new_offset_usize {
        out[bss_start..new_offset_usize].fill(0);
    }

    for (index, &(tag, value)) in dynamic_entries.iter().enumerate() {
        let offset = new_offset_usize + index * DYNAMIC_ENTRY_SIZE;
        out[offset..offset + 8].copy_from_slice(&(tag as u64).to_le_bytes());
        out[offset + 8..offset + 16].copy_from_slice(&value.to_le_bytes());
    }

    let mut new_strtab = Vec::with_capacity(strtab_size as usize);
    new_strtab.extend_from_slice(strtab);
    new_strtab.extend_from_slice(needed.as_bytes());
    new_strtab.push(0);
    let strtab_offset_usize = new_strtab_offset as usize;
    out[strtab_offset_usize..strtab_offset_usize + new_strtab.len()].copy_from_slice(&new_strtab);

    let dynamic_base = layout.phoff + dynamic.index * layout.phentsize;
    write_u64(&mut out, dynamic_base + 8, new_offset);
    write_u64(&mut out, dynamic_base + 16, new_vaddr);
    write_u64(&mut out, dynamic_base + 24, new_vaddr);
    write_u64(&mut out, dynamic_base + 32, dynamic_size);
    write_u64(&mut out, dynamic_base + 40, dynamic_size);

    let load_base = layout.phoff + load.index * layout.phentsize;
    write_u64(&mut out, load_base + 32, filesz);
    write_u64(&mut out, load_base + 40, memsz);

    update_section_headers(
        &mut out,
        &layout,
        &SectionPatch {
            dynamic_vaddr: new_vaddr,
            dynamic_offset: new_offset,
            dynamic_size,
            strtab_vaddr: new_strtab_vaddr,
            strtab_offset: new_strtab_offset,
            strtab_size,
        },
    );

    Ok(Some(out))
}

fn parse_layout(bytes: &[u8]) -> Result<Layout> {
    if bytes.len() < ELF_HEADER_SIZE {
        bail!("elf: file is too small to be an ELF");
    }
    if &bytes[0..4] != ELF_MAGIC {
        bail!("elf: not an ELF file");
    }
    if bytes[4] != ELFCLASS64 {
        bail!("elf: not a 64-bit ELF");
    }
    if bytes[5] != ELFDATA2LSB {
        bail!("elf: not a little-endian ELF");
    }
    if u16_at(bytes, 16)? != ET_DYN {
        bail!("elf: not a shared object (ET_DYN)");
    }
    if u16_at(bytes, 18)? != EM_AARCH64 {
        bail!("elf: not an AArch64 ELF");
    }

    let phoff = u64_at(bytes, 32)? as usize;
    let shoff = u64_at(bytes, 40)? as usize;
    let phentsize = u16_at(bytes, 54)? as usize;
    let phnum = u16_at(bytes, 56)? as usize;
    let shentsize = u16_at(bytes, 58)? as usize;
    let shnum = u16_at(bytes, 60)? as usize;
    let shstrndx = u16_at(bytes, 62)? as usize;
    if phentsize != PROGRAM_HEADER_SIZE {
        bail!("elf: unsupported program header size {phentsize}");
    }
    let ph_size = phnum
        .checked_mul(phentsize)
        .ok_or_else(|| anyhow!("elf: program header table overflow"))?;
    let ph_end = phoff
        .checked_add(ph_size)
        .ok_or_else(|| anyhow!("elf: program header table overflow"))?;
    if ph_end > bytes.len() {
        bail!("elf: program header table extends past the file");
    }

    let mut phdrs = Vec::with_capacity(phnum);
    for index in 0..phnum {
        let offset = phoff + index * phentsize;
        phdrs.push(ProgramHeader {
            index,
            p_type: u32_at(bytes, offset)?,
            p_flags: u32_at(bytes, offset + 4)?,
            p_offset: u64_at(bytes, offset + 8)?,
            p_vaddr: u64_at(bytes, offset + 16)?,
            p_filesz: u64_at(bytes, offset + 32)?,
            p_memsz: u64_at(bytes, offset + 40)?,
            p_align: u64_at(bytes, offset + 48)?,
        });
    }

    if shoff != 0 && shnum != 0 && shentsize != SECTION_HEADER_SIZE {
        bail!("elf: unsupported section header size {shentsize}");
    }

    Ok(Layout {
        phoff,
        phentsize,
        phdrs,
        shoff,
        shentsize,
        shnum,
        shstrndx,
    })
}

fn read_dynamic(bytes: &[u8], dynamic: &ProgramHeader) -> Result<Vec<(i64, u64)>> {
    let count = (dynamic.p_filesz / DYNAMIC_ENTRY_SIZE as u64) as usize;
    if count == 0 {
        bail!("elf: empty PT_DYNAMIC");
    }
    let offset = dynamic.p_offset as usize;
    let table_size = count
        .checked_mul(DYNAMIC_ENTRY_SIZE)
        .ok_or_else(|| anyhow!("elf: dynamic table overflow"))?;
    let end = offset
        .checked_add(table_size)
        .ok_or_else(|| anyhow!("elf: dynamic table overflow"))?;
    if end > bytes.len() {
        bail!("elf: dynamic table extends past the file");
    }
    let mut entries = Vec::with_capacity(count);
    for index in 0..count {
        let entry = offset + index * DYNAMIC_ENTRY_SIZE;
        let tag = i64_at(bytes, entry)?;
        let value = u64_at(bytes, entry + 8)?;
        entries.push((tag, value));
        if tag == DT_NULL {
            return Ok(entries);
        }
    }
    bail!("elf: PT_DYNAMIC has no DT_NULL terminator")
}

fn dynamic_value(entries: &[(i64, u64)], tag: i64) -> Option<u64> {
    entries
        .iter()
        .find(|(entry_tag, _)| *entry_tag == tag)
        .map(|(_, value)| *value)
}

fn vaddr_to_offset(phdrs: &[ProgramHeader], vaddr: u64, len: u64) -> Option<u64> {
    phdrs.iter().find_map(|ph| {
        if ph.p_type != PT_LOAD {
            return None;
        }
        let file_end = ph.p_vaddr.checked_add(ph.p_filesz)?;
        let want_end = vaddr.checked_add(len)?;
        if vaddr >= ph.p_vaddr && want_end <= file_end {
            Some(ph.p_offset + (vaddr - ph.p_vaddr))
        } else {
            None
        }
    })
}

fn string_at(table: &[u8], offset: usize) -> Option<&str> {
    let tail = table.get(offset..)?;
    let end = tail.iter().position(|&b| b == 0)?;
    std::str::from_utf8(&tail[..end]).ok()
}

fn ranges_overlap(a_start: u64, a_end: u64, b_start: u64, b_end: u64) -> bool {
    a_start < b_end && b_start < a_end
}

fn align_up(value: u64, align: u64) -> Result<u64> {
    if align == 0 {
        bail!("elf: zero alignment");
    }
    value
        .checked_add(align - 1)
        .map(|v| v / align * align)
        .ok_or_else(|| anyhow!("elf: alignment overflow"))
}

fn section_names_range(bytes: &[u8], layout: &Layout) -> Option<(u64, u64)> {
    if layout.shoff == 0
        || layout.shnum == 0
        || layout.shstrndx == 0
        || layout.shstrndx >= layout.shnum
    {
        return None;
    }
    let header = section_header(layout.shoff, layout.shentsize, layout.shstrndx)?;
    let offset = read_u64(bytes, header + 24)?;
    let size = read_u64(bytes, header + 32)?;
    let start = usize::try_from(offset).ok()?;
    let len = usize::try_from(size).ok()?;
    if start.checked_add(len)? > bytes.len() {
        return None;
    }
    Some((offset, size))
}

struct SectionPatch {
    dynamic_vaddr: u64,
    dynamic_offset: u64,
    dynamic_size: u64,
    strtab_vaddr: u64,
    strtab_offset: u64,
    strtab_size: u64,
}

fn update_section_headers(bytes: &mut [u8], layout: &Layout, patch: &SectionPatch) {
    if layout.shoff == 0
        || layout.shnum == 0
        || layout.shstrndx == 0
        || layout.shstrndx >= layout.shnum
    {
        return;
    }
    let Some(shstr_header) = section_header(layout.shoff, layout.shentsize, layout.shstrndx) else {
        return;
    };
    let Some(name_offset) = read_u64(bytes, shstr_header + 24) else {
        return;
    };
    let Some(name_size) = read_u64(bytes, shstr_header + 32) else {
        return;
    };
    let (Ok(name_start), Ok(name_end)) = (usize::try_from(name_offset), usize::try_from(name_size))
    else {
        return;
    };
    let Some(names) = bytes.get(name_start..name_start.saturating_add(name_end)) else {
        return;
    };
    let names = names.to_vec();

    for index in 0..layout.shnum {
        let Some(header) = section_header(layout.shoff, layout.shentsize, index) else {
            return;
        };
        let Some(name) = read_u32(bytes, header) else {
            return;
        };
        let Some(name) = string_at(&names, name as usize) else {
            continue;
        };
        match name {
            ".dynamic" => {
                write_u64(bytes, header + 16, patch.dynamic_vaddr);
                write_u64(bytes, header + 24, patch.dynamic_offset);
                write_u64(bytes, header + 32, patch.dynamic_size);
            }
            ".dynstr" => {
                write_u64(bytes, header + 16, patch.strtab_vaddr);
                write_u64(bytes, header + 24, patch.strtab_offset);
                write_u64(bytes, header + 32, patch.strtab_size);
            }
            _ => {}
        }
    }
}

fn section_header(shoff: usize, shentsize: usize, index: usize) -> Option<usize> {
    shoff.checked_add(index.checked_mul(shentsize)?)
}

fn u16_at(bytes: &[u8], offset: usize) -> Result<u16> {
    let raw = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| anyhow!("elf: truncated u16 at {offset:#x}"))?;
    Ok(u16::from_le_bytes([raw[0], raw[1]]))
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32> {
    let raw = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| anyhow!("elf: truncated u32 at {offset:#x}"))?;
    Ok(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn u64_at(bytes: &[u8], offset: usize) -> Result<u64> {
    read_u64(bytes, offset).ok_or_else(|| anyhow!("elf: truncated u64 at {offset:#x}"))
}

fn i64_at(bytes: &[u8], offset: usize) -> Result<i64> {
    Ok(u64_at(bytes, offset)? as i64)
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let raw = bytes.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    let raw = bytes.get(offset..offset + 8)?;
    Some(u64::from_le_bytes([
        raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
    ]))
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    if let Some(raw) = bytes.get_mut(offset..offset + 8) {
        raw.copy_from_slice(&value.to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NEEDED: &str = "libspoof.so";
    const STRING_TABLE: &[u8] = b"\0libc.so\0";
    const DYNAMIC_OFFSET: usize = 0x100;
    const STRING_OFFSET: usize = 0x200;
    const LOAD_MEMSZ: u64 = 0x1000;
    const FILE_SIZE: usize = 0x2000;

    fn synthetic_elf() -> Vec<u8> {
        let mut bytes = vec![0u8; FILE_SIZE];
        bytes[0..4].copy_from_slice(ELF_MAGIC);
        bytes[4] = ELFCLASS64;
        bytes[5] = ELFDATA2LSB;
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&ET_DYN.to_le_bytes());
        bytes[18..20].copy_from_slice(&EM_AARCH64.to_le_bytes());
        bytes[32..40].copy_from_slice(&(ELF_HEADER_SIZE as u64).to_le_bytes());
        bytes[54..56].copy_from_slice(&(PROGRAM_HEADER_SIZE as u16).to_le_bytes());
        bytes[56..58].copy_from_slice(&2u16.to_le_bytes());

        let load = ELF_HEADER_SIZE;
        bytes[load..load + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
        bytes[load + 4..load + 8].copy_from_slice(&PF_W.to_le_bytes());
        bytes[load + 8..load + 16].copy_from_slice(&0u64.to_le_bytes());
        bytes[load + 16..load + 24].copy_from_slice(&0u64.to_le_bytes());
        bytes[load + 32..load + 40]
            .copy_from_slice(&(STRING_OFFSET as u64 + STRING_TABLE.len() as u64).to_le_bytes());
        bytes[load + 40..load + 48].copy_from_slice(&LOAD_MEMSZ.to_le_bytes());
        bytes[load + 48..load + 56].copy_from_slice(&0x1000u64.to_le_bytes());

        let dynamic = ELF_HEADER_SIZE + PROGRAM_HEADER_SIZE;
        let dynamic_size = 4 * DYNAMIC_ENTRY_SIZE;
        bytes[dynamic..dynamic + 4].copy_from_slice(&PT_DYNAMIC.to_le_bytes());
        bytes[dynamic + 8..dynamic + 16].copy_from_slice(&(DYNAMIC_OFFSET as u64).to_le_bytes());
        bytes[dynamic + 16..dynamic + 24].copy_from_slice(&(DYNAMIC_OFFSET as u64).to_le_bytes());
        bytes[dynamic + 32..dynamic + 40].copy_from_slice(&(dynamic_size as u64).to_le_bytes());
        bytes[dynamic + 40..dynamic + 48].copy_from_slice(&(dynamic_size as u64).to_le_bytes());
        bytes[dynamic + 48..dynamic + 56].copy_from_slice(&8u64.to_le_bytes());

        let entries = [
            (DT_NEEDED, 1u64),
            (DT_STRTAB, STRING_OFFSET as u64),
            (DT_STRSZ, STRING_TABLE.len() as u64),
            (DT_NULL, 0u64),
        ];
        for (index, (tag, value)) in entries.iter().enumerate() {
            let offset = DYNAMIC_OFFSET + index * DYNAMIC_ENTRY_SIZE;
            bytes[offset..offset + 8].copy_from_slice(&(*tag as u64).to_le_bytes());
            bytes[offset + 8..offset + 16].copy_from_slice(&value.to_le_bytes());
        }
        bytes[STRING_OFFSET..STRING_OFFSET + STRING_TABLE.len()].copy_from_slice(STRING_TABLE);
        bytes
    }

    fn dynamic_entries(bytes: &[u8]) -> Vec<(i64, u64)> {
        let layout = parse_layout(bytes).unwrap();
        let dynamic = layout
            .phdrs
            .iter()
            .find(|p| p.p_type == PT_DYNAMIC)
            .copied()
            .unwrap();
        read_dynamic(bytes, &dynamic).unwrap()
    }

    fn needed_names(bytes: &[u8]) -> Vec<String> {
        let layout = parse_layout(bytes).unwrap();
        let entries = dynamic_entries(bytes);
        let strtab_vaddr = dynamic_value(&entries, DT_STRTAB).unwrap();
        let strsz = dynamic_value(&entries, DT_STRSZ).unwrap();
        let strtab_off = vaddr_to_offset(&layout.phdrs, strtab_vaddr, strsz).unwrap();
        let strtab = &bytes[strtab_off as usize..(strtab_off + strsz) as usize];
        entries
            .iter()
            .filter(|(tag, _)| *tag == DT_NEEDED)
            .map(|(_, value)| string_at(strtab, *value as usize).unwrap().to_string())
            .collect()
    }

    #[test]
    fn prepends_the_needed_entry_without_changing_file_size() {
        let original = synthetic_elf();
        let patched = add_needed(&original, NEEDED).unwrap().expect("patched");

        assert_eq!(patched.len(), original.len());
        assert_eq!(
            needed_names(&patched),
            vec![NEEDED.to_string(), "libc.so".to_string()]
        );

        let entries = dynamic_entries(&patched);
        assert_eq!(
            dynamic_value(&entries, DT_STRSZ),
            Some((STRING_TABLE.len() + NEEDED.len() + 1) as u64)
        );
    }

    #[test]
    fn points_the_dynamic_segment_at_the_copy() {
        let original = synthetic_elf();
        let patched = add_needed(&original, NEEDED).unwrap().expect("patched");
        let layout = parse_layout(&patched).unwrap();
        let dynamic = layout
            .phdrs
            .iter()
            .find(|p| p.p_type == PT_DYNAMIC)
            .copied()
            .unwrap();
        assert_eq!(dynamic.p_vaddr, 0x210);
        assert_eq!(dynamic.p_offset, 0x210);
        assert_eq!(dynamic.p_filesz, 5 * DYNAMIC_ENTRY_SIZE as u64);

        let load = layout
            .phdrs
            .iter()
            .find(|p| p.p_type == PT_LOAD)
            .copied()
            .unwrap();
        assert!(load.p_filesz > 0x200);
        assert!(load.p_filesz <= load.p_memsz);
        assert_eq!(load.p_memsz % 0x1000, 0);
    }

    #[test]
    fn second_application_is_a_no_op() {
        let original = synthetic_elf();
        let patched = add_needed(&original, NEEDED).unwrap().expect("patched");
        assert!(add_needed(&patched, NEEDED).unwrap().is_none());
    }

    #[test]
    fn rejects_a_name_with_a_path() {
        let original = synthetic_elf();
        let err = add_needed(&original, "/system/lib64/libspoof.so").unwrap_err();
        assert!(err.to_string().contains("plain soname"));
    }

    #[test]
    fn rejects_a_non_elf_file() {
        let err = add_needed(b"not an elf", NEEDED).unwrap_err();
        assert!(err.to_string().contains("too small"));
    }

    #[test]
    fn rejects_a_foreign_machine() {
        let mut original = synthetic_elf();
        original[18..20].copy_from_slice(&62u16.to_le_bytes());
        let err = add_needed(&original, NEEDED).unwrap_err();
        assert!(err.to_string().contains("AArch64"));
    }

    #[test]
    fn rejects_a_missing_dynamic_segment() {
        let mut original = synthetic_elf();
        let dynamic = ELF_HEADER_SIZE + PROGRAM_HEADER_SIZE;
        original[dynamic..dynamic + 4].copy_from_slice(&0u32.to_le_bytes());
        let err = add_needed(&original, NEEDED).unwrap_err();
        assert!(err.to_string().contains("PT_DYNAMIC"));
    }

    #[test]
    #[ignore = "fixture: set DYNOBOX_TEST_APP_PROCESS64 and DYNOBOX_TEST_APP_PROCESS64_OUT"]
    fn patches_real_app_process64_when_env_set() {
        let input = crate::test_fixtures::env("DYNOBOX_TEST_APP_PROCESS64");
        let output = crate::test_fixtures::env("DYNOBOX_TEST_APP_PROCESS64_OUT");
        let bytes = std::fs::read(&input).unwrap();
        let patched = add_needed(&bytes, NEEDED).unwrap().expect("patched");
        assert_eq!(patched.len(), bytes.len());
        assert!(add_needed(&patched, NEEDED).unwrap().is_none());
        std::fs::write(&output, patched).unwrap();
    }

    /// `bootanimation` is a small executable whose only writable `PT_LOAD`
    /// carries the dynamic table plus a zero-filled tail; the same in-place
    /// patch has to fit there.
    #[test]
    #[ignore = "fixture: set DYNOBOX_TEST_BOOTANIMATION and DYNOBOX_TEST_BOOTANIMATION_OUT"]
    fn patches_real_bootanimation_when_env_set() {
        let input = crate::test_fixtures::env("DYNOBOX_TEST_BOOTANIMATION");
        let output = crate::test_fixtures::env("DYNOBOX_TEST_BOOTANIMATION_OUT");
        let bytes = std::fs::read(&input).unwrap();
        let patched = add_needed(&bytes, NEEDED).unwrap().expect("patched");
        assert_eq!(patched.len(), bytes.len());
        assert!(add_needed(&patched, NEEDED).unwrap().is_none());
        std::fs::write(&output, patched).unwrap();
    }
}
