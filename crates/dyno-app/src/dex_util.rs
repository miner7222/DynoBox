//! DEX header checksum maintenance after in-place bytecode patches.

use sha1::{Digest, Sha1};

/// Refresh the DEX header SHA-1 signature (bytes 12..32, over `dex[32..]`)
/// and Adler-32 checksum (bytes 8..12, over `dex[12..]`).
pub(crate) fn recompute_dex_header_sums(dex: &mut [u8]) {
    let sig = sha1_digest(&dex[32..]);
    dex[12..32].copy_from_slice(&sig);
    let cksum = adler32(&dex[12..]);
    dex[8..12].copy_from_slice(&cksum.to_le_bytes());
}

fn sha1_digest(data: &[u8]) -> [u8; 20] {
    let mut out = [0u8; 20];
    out.copy_from_slice(&Sha1::digest(data));
    out
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adler32_known_values() {
        assert_eq!(adler32(b""), 1);
        assert_eq!(adler32(b"abc"), 0x024D0127);
        assert_eq!(adler32(b"Wikipedia"), 0x11E60398);
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
}
