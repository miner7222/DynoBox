//! Base64 and PEM armor for certificates and keys.

use anyhow::{Result, anyhow, bail};

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub(crate) fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[((n >> (18 - 6 * i)) & 0x3F) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

pub(crate) fn base64_decode(text: &str) -> Result<Vec<u8>> {
    let symbols: Vec<u8> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if symbols.len() % 4 != 0 {
        bail!("base64 length {} is not a multiple of 4", symbols.len());
    }
    let quads = symbols.len() / 4;
    let mut out = Vec::with_capacity(quads * 3);
    for (index, quad) in symbols.chunks(4).enumerate() {
        let pad = quad.iter().rev().take_while(|&&b| b == b'=').count();
        if pad > 2 || (pad > 0 && index + 1 != quads) {
            bail!("invalid base64 padding");
        }
        let mut n = 0u32;
        for &symbol in &quad[..4 - pad] {
            let value = ALPHABET
                .iter()
                .position(|&c| c == symbol)
                .ok_or_else(|| anyhow!("invalid base64 symbol {:?}", symbol as char))?;
            n = (n << 6) | value as u32;
        }
        n <<= 6 * pad as u32;
        let bytes = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        out.extend_from_slice(&bytes[..3 - pad]);
    }
    Ok(out)
}

/// Wrap DER bytes in `-----BEGIN {label}-----` armor with 64-column lines.
pub(crate) fn encode(label: &str, der: &[u8]) -> String {
    let body = base64_encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in body.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// Extract the DER payload of the first `label` block in `text`.
pub(crate) fn decode(text: &str, label: &str) -> Result<Vec<u8>> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let start = text
        .find(&begin)
        .ok_or_else(|| anyhow!("no `{begin}` block found"))?
        + begin.len();
    let stop = text[start..]
        .find(&end)
        .ok_or_else(|| anyhow!("unterminated `{begin}` block"))?;
    base64_decode(&text[start..start + stop])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_rfc4648_vectors() {
        for (plain, encoded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64_encode(plain.as_bytes()), encoded);
            assert_eq!(base64_decode(encoded).unwrap(), plain.as_bytes());
        }
        assert!(base64_decode("Zg=").is_err());
        assert!(base64_decode("Zg==Zg==").is_err());
        assert!(base64_decode("Z!==").is_err());
    }

    #[test]
    fn pem_round_trips() {
        let der: Vec<u8> = (0..=255).collect();
        let text = encode("CERTIFICATE", &der);
        assert!(text.lines().all(|l| l.len() <= 64));
        assert_eq!(decode(&text, "CERTIFICATE").unwrap(), der);
        assert!(decode(&text, "PRIVATE KEY").is_err());
    }
}
