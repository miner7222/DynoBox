//! Android binary XML (AXML) element / attribute navigation for the
//! in-place layout patch ops.

use anyhow::{Result, anyhow};

const AXML_CHUNK_XML: u16 = 0x0003;
const AXML_CHUNK_STRING_POOL: u16 = 0x0001;
const AXML_CHUNK_START_ELEMENT: u16 = 0x0102;
const AXML_STRING_POOL_UTF8_FLAG: u32 = 1 << 8;

/// One attribute of one binary-XML element, with the file offsets needed to
/// rewrite its typed value in place. Namespace/name resolution is tolerant:
/// resource-obfuscation tooling can leave stale pool offsets behind, so an
/// unresolvable name is `None` (never matchable) rather than a hard error.
#[derive(Debug, Clone)]
pub(crate) struct AxmlAttr {
    pub(crate) ns: Option<String>,
    pub(crate) name: Option<String>,
    /// Offset of the 8-byte typed value (`u16 size`, `u8 res0`, `u8 type`,
    /// `u32 data`); the type byte lives at `type_off + 3`, data at `+4`.
    pub(crate) type_off: usize,
    pub(crate) data_type: u8,
    pub(crate) data: u32,
}

/// One binary-XML start-element and its attributes in document order.
#[derive(Debug, Clone)]
pub(crate) struct AxmlElement {
    pub(crate) attrs: Vec<AxmlAttr>,
}

fn axml_range_end(off: usize, len: usize, label: &str) -> Result<usize> {
    off.checked_add(len)
        .filter(|&end| end >= off)
        .ok_or_else(|| anyhow!("{label} offset overflow"))
}

fn axml_slice<'a>(bytes: &'a [u8], off: usize, len: usize, label: &str) -> Result<&'a [u8]> {
    let end = axml_range_end(off, len, label)?;
    bytes.get(off..end).ok_or_else(|| {
        anyhow!(
            "{label} range {off}..{end} exceeds file length {}",
            bytes.len()
        )
    })
}

fn axml_u16(bytes: &[u8], off: usize, label: &str) -> Result<u16> {
    Ok(u16::from_le_bytes(
        axml_slice(bytes, off, 2, label)?
            .try_into()
            .map_err(|_| anyhow!("{label} truncated u16 at {off}"))?,
    ))
}

fn axml_u32(bytes: &[u8], off: usize, label: &str) -> Result<u32> {
    Ok(u32::from_le_bytes(
        axml_slice(bytes, off, 4, label)?
            .try_into()
            .map_err(|_| anyhow!("{label} truncated u32 at {off}"))?,
    ))
}

/// Decode one pool string. Returns the string and the offset just past its
/// NUL terminator. UTF-16 lengths are u16-based (0x8000 extension);
/// UTF-8 lengths are u8-based (0x80 extension), with separate char and
/// byte counts.
fn axml_pool_string(bytes: &[u8], off: usize, utf8: bool) -> Result<(String, usize)> {
    let mut cur = off;
    // UTF-16 path keeps the u16-based length form.
    let take_u16 = |bytes: &[u8], cur: &mut usize| -> Result<u32> {
        let v = axml_u16(bytes, *cur, "axml string length")? as u32;
        *cur += 2;
        if v & 0x8000 != 0 {
            let lo = axml_u16(bytes, *cur, "axml string length extension")? as u32;
            *cur += 2;
            Ok(((v & 0x7FFF) << 16) | lo)
        } else {
            Ok(v)
        }
    };
    // UTF-8 path uses single bytes with a 0x80 extension bit instead.
    let take_u8 = |bytes: &[u8], cur: &mut usize| -> Result<u32> {
        let b = *axml_slice(bytes, *cur, 1, "axml string length")?
            .first()
            .ok_or_else(|| anyhow!("axml string length truncated"))? as u32;
        *cur += 1;
        if b & 0x80 != 0 {
            let lo = *axml_slice(bytes, *cur, 1, "axml string length extension")?
                .first()
                .ok_or_else(|| anyhow!("axml string length truncated"))?
                as u32;
            *cur += 1;
            Ok(((b & 0x7F) << 8) | lo)
        } else {
            Ok(b)
        }
    };
    if utf8 {
        let _chars = take_u8(bytes, &mut cur)?;
        let nbytes = take_u8(bytes, &mut cur)? as usize;
        let raw = axml_slice(bytes, cur, nbytes, "axml utf-8 string")?;
        let text = std::str::from_utf8(raw)
            .map_err(|_| anyhow!("axml string pool has non-UTF-8 entry"))?
            .to_string();
        cur += nbytes;
        if axml_slice(bytes, cur, 1, "axml string NUL")? != [0] {
            return Err(anyhow!("axml utf-8 string missing NUL terminator"));
        }
        Ok((text, cur + 1))
    } else {
        let nunits = take_u16(bytes, &mut cur)? as usize;
        let raw = axml_slice(bytes, cur, nunits * 2, "axml utf-16 string")?;
        let units: Vec<u16> = raw
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        let text = String::from_utf16(&units)
            .map_err(|_| anyhow!("axml string pool has invalid UTF-16 entry"))?;
        cur += nunits * 2;
        if axml_slice(bytes, cur, 2, "axml string NUL")? != [0, 0] {
            return Err(anyhow!("axml utf-16 string missing NUL terminator"));
        }
        Ok((text, cur + 2))
    }
}

struct AxmlPool {
    strings: Vec<Option<String>>,
}

fn axml_parse_pool(bytes: &[u8], chunk_off: usize) -> Result<AxmlPool> {
    let string_count = axml_u32(bytes, chunk_off + 8, "axml pool count")? as usize;
    let flags = axml_u32(bytes, chunk_off + 16, "axml pool flags")?;
    let strings_start = axml_u32(bytes, chunk_off + 20, "axml pool data")? as usize;
    let utf8 = flags & AXML_STRING_POOL_UTF8_FLAG != 0;
    if string_count > 100_000 {
        return Err(anyhow!("axml string pool count {string_count} implausible"));
    }
    let data_base = axml_range_end(chunk_off, strings_start, "axml pool data")?;
    let mut strings = Vec::with_capacity(string_count.min(4096));
    for i in 0..string_count {
        let entry_off = axml_u32(bytes, chunk_off + 28 + i * 4, "axml pool index")? as usize;
        let text = axml_range_end(data_base, entry_off, "axml pool entry")
            .ok()
            .and_then(|abs| axml_pool_string(bytes, abs, utf8).ok().map(|(t, _)| t));
        strings.push(text);
    }
    Ok(AxmlPool { strings })
}

/// Parse every start-element of a binary-XML file with resolved namespace /
/// attribute names. Refuses malformed structures rather than guessing.
pub(crate) fn parse_axml_elements(bytes: &[u8]) -> Result<Vec<AxmlElement>> {
    if axml_u16(bytes, 0, "axml file type").unwrap_or(0) != AXML_CHUNK_XML {
        return Err(anyhow!("not a binary XML file (missing 0x0003 header)"));
    }
    let mut pool: Option<AxmlPool> = None;
    let mut elements = Vec::new();
    let mut cursor = 0usize;
    while cursor + 8 <= bytes.len() {
        let ty = axml_u16(bytes, cursor, "axml chunk type")?;
        let size = axml_u32(bytes, cursor + 4, "axml chunk size")? as usize;
        if size < 8 {
            return Err(anyhow!("axml chunk at {cursor} has size {size}"));
        }
        let end = axml_range_end(cursor, size, "axml chunk")?;
        if end > bytes.len() {
            return Err(anyhow!("axml chunk at {cursor} overruns file"));
        }
        if ty == AXML_CHUNK_XML {
            // File container: descend past its 8-byte header into the chunks.
            cursor += 8;
            continue;
        }
        match ty {
            AXML_CHUNK_STRING_POOL => {
                if pool.is_none() {
                    pool = Some(axml_parse_pool(bytes, cursor)?);
                }
            }
            AXML_CHUNK_START_ELEMENT => {
                let pool = pool
                    .as_ref()
                    .ok_or_else(|| anyhow!("axml element before string pool"))?;
                // Chunk header(8) + lineNumber(4) + comment(4), then ns/name.
                let attr_start = axml_u16(bytes, cursor + 24, "axml attr start")? as usize;
                let attr_size = axml_u16(bytes, cursor + 26, "axml attr size")? as usize;
                let attr_count = axml_u16(bytes, cursor + 28, "axml attr count")? as usize;
                if attr_size != 20 {
                    return Err(anyhow!("axml element has attribute size {attr_size}"));
                }
                if attr_count > 500 {
                    return Err(anyhow!("axml element has {attr_count} attributes"));
                }
                // attributeStart is relative to the end of the node header
                // (lineNumber + comment), i.e. chunk start + 16.
                let attrs_base = axml_range_end(cursor + 16, attr_start, "axml attrs")?;
                let mut attrs = Vec::with_capacity(attr_count.min(32));
                for i in 0..attr_count {
                    let base = axml_range_end(attrs_base, i * attr_size, "axml attr")?;
                    let attr_end = axml_range_end(base, 20, "axml attr")?;
                    if attr_end > end {
                        return Err(anyhow!("axml attribute overruns element"));
                    }
                    let ns_raw = axml_u32(bytes, base, "axml attr ns")?;
                    let name_raw = axml_u32(bytes, base + 4, "axml attr name")?;
                    let ns = if ns_raw == 0xFFFF_FFFF {
                        None
                    } else {
                        pool.strings.get(ns_raw as usize).and_then(|o| o.clone())
                    };
                    let name = pool.strings.get(name_raw as usize).and_then(|o| o.clone());
                    let typed_size = axml_u16(bytes, base + 12, "axml value size")?;
                    if typed_size != 8 {
                        return Err(anyhow!("axml attribute value size {typed_size}"));
                    }
                    let data_type = axml_slice(bytes, base + 15, 1, "axml value type")?[0];
                    let data = axml_u32(bytes, base + 16, "axml value data")?;
                    attrs.push(AxmlAttr {
                        ns,
                        name,
                        type_off: base + 12,
                        data_type,
                        data,
                    });
                }
                elements.push(AxmlElement { attrs });
            }
            _ => {}
        }
        cursor = end;
    }
    Ok(elements)
}

// ---------------------------------------------------------------------------
/// Build a minimal binary XML: file header, UTF-8 string pool, and one
/// LinearLayout element carrying android:id, layout_height (dimension),
/// layout_marginTop (reference) and background (reference).
#[cfg(test)]
pub(crate) fn build_test_axml() -> Vec<u8> {
    fn u8len(s: &str, out: &mut Vec<u8>) {
        // u8-based length form (chars, then bytes).
        out.push(s.chars().count() as u8);
        out.push(s.len() as u8);
        out.extend_from_slice(s.as_bytes());
        out.push(0);
    }
    let strings = [
        "http://schemas.android.com/apk/res/android",
        "id",
        "layout_height",
        "layout_marginTop",
        "background",
        "layout_width",
    ];
    let mut pool_data = Vec::new();
    let mut offsets = Vec::new();
    for s in strings {
        offsets.push(pool_data.len() as u32);
        u8len(s, &mut pool_data);
    }
    let mut pool = Vec::new();
    pool.extend_from_slice(&0x0001u16.to_le_bytes());
    pool.extend_from_slice(&28u16.to_le_bytes());
    let pool_len_pos = pool.len();
    pool.extend_from_slice(&0u32.to_le_bytes());
    pool.extend_from_slice(&(strings.len() as u32).to_le_bytes());
    pool.extend_from_slice(&0u32.to_le_bytes());
    pool.extend_from_slice(&256u32.to_le_bytes());
    // String data starts after the 28-byte header plus the offset table.
    let strings_start = 28 + strings.len() as u32 * 4;
    pool.extend_from_slice(&strings_start.to_le_bytes());
    pool.extend_from_slice(&0u32.to_le_bytes());
    for off in &offsets {
        pool.extend_from_slice(&off.to_le_bytes());
    }
    pool.extend_from_slice(&pool_data);
    let pool_len = pool.len() as u32;
    pool[pool_len_pos..pool_len_pos + 4].copy_from_slice(&pool_len.to_le_bytes());

    // One element: ns=-1 tag "LinearLayout" is index-free here; only
    // attribute names/values matter for the navigator test.
    let mut el = Vec::new();
    el.extend_from_slice(&0x0102u16.to_le_bytes());
    el.extend_from_slice(&16u16.to_le_bytes());
    el.extend_from_slice(&0u32.to_le_bytes()); // size, patched below
    el.extend_from_slice(&0u32.to_le_bytes()); // lineNumber
    el.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes()); // comment
    el.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes()); // ns (none)
    el.extend_from_slice(&0u32.to_le_bytes()); // name idx 0 (unused)
    el.extend_from_slice(&20u16.to_le_bytes()); // attrStart
    el.extend_from_slice(&20u16.to_le_bytes()); // attrSize
    el.extend_from_slice(&4u16.to_le_bytes()); // attrCount
    el.extend_from_slice(&0xFFFFu16.to_le_bytes()); // idIndex
    el.extend_from_slice(&0xFFFFu16.to_le_bytes()); // classIndex
    el.extend_from_slice(&0xFFFFu16.to_le_bytes()); // styleIndex
    // Attrs: id(ref 0x7f090001), height(dim 0x4001), marginTop(ref),
    // background(ref). String indexes: android-ns=0? No: pool[0] is the
    // android URI, so ns idx 0; names: id=1, height=2, marginTop=3,
    // background=4.
    let attr = |ns: u32, name: u32, dtype: u8, data: u32, out: &mut Vec<u8>| {
        out.extend_from_slice(&ns.to_le_bytes());
        out.extend_from_slice(&name.to_le_bytes());
        out.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes()); // rawValue
        out.extend_from_slice(&8u16.to_le_bytes());
        out.push(0);
        out.push(dtype);
        out.extend_from_slice(&data.to_le_bytes());
    };
    attr(0, 1, 0x01, 0x7f090001, &mut el);
    attr(0, 2, 0x05, 0x4001, &mut el);
    attr(0, 3, 0x01, 0x7f060001, &mut el);
    attr(0, 4, 0x01, 0x7f080001, &mut el);
    let el_len = el.len() as u32;
    el[4..8].copy_from_slice(&el_len.to_le_bytes());

    let mut file = Vec::new();
    file.extend_from_slice(&0x0003u16.to_le_bytes());
    file.extend_from_slice(&8u16.to_le_bytes());
    let file_len_pos = file.len();
    file.extend_from_slice(&0u32.to_le_bytes());
    file.extend_from_slice(&pool);
    file.extend_from_slice(&el);
    let file_len = file.len() as u32;
    file[file_len_pos..file_len_pos + 4].copy_from_slice(&file_len.to_le_bytes());
    file
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn axml_synthetic_element_round_trip() {
        let xml = build_test_axml();
        let elements = parse_axml_elements(&xml).expect("synthetic parses");
        assert_eq!(elements.len(), 1);
        let attrs = &elements[0].attrs;
        assert_eq!(attrs.len(), 4);
        let by_name = |name: &str| {
            attrs
                .iter()
                .find(|a| {
                    a.ns.as_deref() == Some("http://schemas.android.com/apk/res/android")
                        && a.name.as_deref() == Some(name)
                })
                .expect("attr present")
        };
        let id = by_name("id");
        assert_eq!((id.data_type, id.data), (0x01, 0x7f090001));
        let height = by_name("layout_height");
        assert_eq!((height.data_type, height.data), (0x05, 0x4001));
    }
}
