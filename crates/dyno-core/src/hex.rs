//! Lowercase hexadecimal encoding shared by the digest / key reporting code.

/// Encode `bytes` as lowercase hex, two characters per byte.
pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_lowercase_pairs() {
        assert_eq!(hex_encode(&[]), "");
        assert_eq!(
            hex_encode(&[0x00, 0x0f, 0xDE, 0xAD, 0xBE, 0xEF]),
            "000fdeadbeef"
        );
    }
}
