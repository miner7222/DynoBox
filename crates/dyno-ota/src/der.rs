//! Minimal DER reader and writer for the X.509 and CMS structures DynoBox
//! builds. Only single-byte tags and definite lengths are supported, which
//! covers every structure used here.

use anyhow::{Result, anyhow, bail};

pub(crate) const TAG_INTEGER: u8 = 0x02;
pub(crate) const TAG_BIT_STRING: u8 = 0x03;
pub(crate) const TAG_NULL: u8 = 0x05;
pub(crate) const TAG_OID: u8 = 0x06;
pub(crate) const TAG_UTF8_STRING: u8 = 0x0C;
pub(crate) const TAG_UTC_TIME: u8 = 0x17;
pub(crate) const TAG_GENERALIZED_TIME: u8 = 0x18;
pub(crate) const TAG_SEQUENCE: u8 = 0x30;
pub(crate) const TAG_SET: u8 = 0x31;

/// One decoded TLV. `raw` spans the whole element, header included.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Tlv<'a> {
    pub tag: u8,
    pub content: &'a [u8],
    pub raw: &'a [u8],
}

/// Decode the element at the start of `input`; return it and the remainder.
pub(crate) fn read_tlv(input: &[u8]) -> Result<(Tlv<'_>, &[u8])> {
    let (&tag, rest) = input
        .split_first()
        .ok_or_else(|| anyhow!("DER: truncated tag"))?;
    if tag & 0x1F == 0x1F {
        bail!("DER: multi-byte tags are not supported");
    }
    let (&first, rest) = rest
        .split_first()
        .ok_or_else(|| anyhow!("DER: truncated length"))?;
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let count = usize::from(first & 0x7F);
        if count == 0 || count > 4 {
            bail!("DER: unsupported length encoding {first:#04x}");
        }
        if rest.len() < count {
            bail!("DER: truncated long-form length");
        }
        let len = rest[..count]
            .iter()
            .fold(0usize, |acc, &b| (acc << 8) | usize::from(b));
        (len, &rest[count..])
    };
    if rest.len() < len {
        bail!("DER: element claims {len} bytes, {} remain", rest.len());
    }
    let header_len = input.len() - rest.len();
    let tlv = Tlv {
        tag,
        content: &rest[..len],
        raw: &input[..header_len + len],
    };
    Ok((tlv, &rest[len..]))
}

/// Decode a single element that must span all of `input`.
pub(crate) fn read_single(input: &[u8], expected_tag: u8) -> Result<Tlv<'_>> {
    let (tlv, rest) = read_tlv(input)?;
    if !rest.is_empty() {
        bail!("DER: {} trailing bytes after element", rest.len());
    }
    expect_tag(&tlv, expected_tag)?;
    Ok(tlv)
}

pub(crate) fn expect_tag(tlv: &Tlv<'_>, expected_tag: u8) -> Result<()> {
    if tlv.tag != expected_tag {
        bail!(
            "DER: expected tag {expected_tag:#04x}, found {:#04x}",
            tlv.tag
        );
    }
    Ok(())
}

/// Decode every element inside a constructed value's content.
pub(crate) fn read_children(mut content: &[u8]) -> Result<Vec<Tlv<'_>>> {
    let mut out = Vec::new();
    while !content.is_empty() {
        let (tlv, rest) = read_tlv(content)?;
        out.push(tlv);
        content = rest;
    }
    Ok(out)
}

fn encode_len(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|&&b| b == 0).count();
        out.push(0x80 | (bytes.len() - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
}

/// Encode one element from its tag and content.
pub(crate) fn encode(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 6);
    out.push(tag);
    encode_len(content.len(), &mut out);
    out.extend_from_slice(content);
    out
}

/// Encode a constructed element from already-encoded children.
pub(crate) fn constructed(tag: u8, children: &[&[u8]]) -> Vec<u8> {
    encode(tag, &children.concat())
}

pub(crate) fn sequence(children: &[&[u8]]) -> Vec<u8> {
    constructed(TAG_SEQUENCE, children)
}

/// Encode a non-negative big-endian magnitude as an INTEGER.
pub(crate) fn unsigned_integer(magnitude: &[u8]) -> Vec<u8> {
    let skip = magnitude.iter().take_while(|&&b| b == 0).count();
    let trimmed = &magnitude[skip..];
    let mut content = Vec::with_capacity(trimmed.len() + 1);
    if trimmed.first().is_none_or(|&b| b & 0x80 != 0) {
        content.push(0);
    }
    content.extend_from_slice(trimmed);
    encode(TAG_INTEGER, &content)
}

pub(crate) fn bit_string(bytes: &[u8]) -> Vec<u8> {
    let mut content = Vec::with_capacity(bytes.len() + 1);
    content.push(0);
    content.extend_from_slice(bytes);
    encode(TAG_BIT_STRING, &content)
}

pub(crate) fn null() -> Vec<u8> {
    vec![TAG_NULL, 0]
}

/// Encode a dotted OID string.
pub(crate) fn oid(dotted: &str) -> Vec<u8> {
    let arcs: Vec<u64> = dotted
        .split('.')
        .map(|arc| arc.parse().expect("static OID arcs are numeric"))
        .collect();
    assert!(arcs.len() >= 2, "OID needs at least two arcs");
    let mut content = Vec::new();
    push_base128(arcs[0] * 40 + arcs[1], &mut content);
    for &arc in &arcs[2..] {
        push_base128(arc, &mut content);
    }
    encode(TAG_OID, &content)
}

fn push_base128(mut value: u64, out: &mut Vec<u8>) {
    let mut groups = [0u8; 10];
    let mut len = 0;
    loop {
        groups[len] = (value & 0x7F) as u8;
        len += 1;
        value >>= 7;
        if value == 0 {
            break;
        }
    }
    for i in (0..len).rev() {
        out.push(groups[i] | if i > 0 { 0x80 } else { 0 });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_short_and_long_lengths() {
        for len in [0usize, 1, 127, 128, 255, 256, 70_000] {
            let content = vec![0xAB; len];
            let encoded = encode(0x04, &content);
            let tlv = read_single(&encoded, 0x04).unwrap();
            assert_eq!(tlv.content, &content[..]);
            assert_eq!(tlv.raw, &encoded[..]);
        }
    }

    #[test]
    fn encodes_known_oid_and_integers() {
        // sha256WithRSAEncryption
        assert_eq!(
            oid("1.2.840.113549.1.1.11"),
            [
                0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B
            ]
        );
        assert_eq!(unsigned_integer(&[0x00, 0x7F]), [0x02, 0x01, 0x7F]);
        assert_eq!(unsigned_integer(&[0x80]), [0x02, 0x02, 0x00, 0x80]);
        assert_eq!(unsigned_integer(&[]), [0x02, 0x01, 0x00]);
    }

    #[test]
    fn rejects_truncated_and_indefinite_input() {
        assert!(read_tlv(&[0x30]).is_err());
        assert!(read_tlv(&[0x30, 0x80]).is_err());
        assert!(read_tlv(&[0x30, 0x05, 0x00]).is_err());
        assert!(read_single(&[0x05, 0x00, 0x00], TAG_NULL).is_err());
    }

    #[test]
    fn reader_survives_mutated_input() {
        let seed = sequence(&[&unsigned_integer(&[1, 2, 3]), &oid("2.5.4.3"), &null()]);
        dynobox_core::testutil::for_each_mutation(&seed, 0xDE12, 4000, |bytes| {
            if let Ok((tlv, _)) = read_tlv(bytes) {
                let _ = read_children(tlv.content);
            }
        });
    }
}
