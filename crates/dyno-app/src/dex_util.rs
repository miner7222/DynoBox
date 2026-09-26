//! DEX header checksum maintenance after in-place bytecode patches.

/// Refresh the DEX header SHA-1 signature (bytes 12..32, over `dex[32..]`)
/// and Adler-32 checksum (bytes 8..12, over `dex[12..]`).
pub(crate) fn recompute_dex_header_sums(dex: &mut [u8]) {
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
