use dynobox_core::error::{DynoError, Result};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::{BigUint, RsaPrivateKey, traits::PublicKeyParts};
use sha2::{Digest, Sha256};
use std::path::Path;

pub struct AvbKey {
    private_key: RsaPrivateKey,
}

impl AvbKey {
    pub fn load_pem(path: &Path) -> Result<Self> {
        let pem = std::fs::read_to_string(path)?;
        Self::from_pem(&pem)
    }

    pub fn from_pem(pem: &str) -> Result<Self> {
        let private_key = RsaPrivateKey::from_pkcs8_pem(pem)
            .or_else(|_| RsaPrivateKey::from_pkcs1_pem(pem))
            .map_err(|e| DynoError::Tool(format!("Failed to load RSA key: {}", e)))?;

        Ok(Self { private_key })
    }

    pub fn bits(&self) -> u32 {
        (self.private_key.size() * 8) as u32
    }

    /// Returns the standard AVB algorithm name based on key size
    pub fn algorithm(&self) -> Result<String> {
        match self.bits() {
            2048 => Ok("SHA256_RSA2048".to_string()),
            4096 => Ok("SHA256_RSA4096".to_string()),
            8192 => Ok("SHA256_RSA8192".to_string()),
            _ => Err(DynoError::Tool(format!(
                "No standard AVB algorithm for {} bits",
                self.bits()
            ))),
        }
    }

    pub fn public_key_parts(&self) -> (BigUint, u32) {
        let n = self.private_key.n();
        let num_bits = self.bits();
        (n.clone(), num_bits)
    }

    /// Encodes the public key in AvbRSAPublicKeyHeader format
    pub fn encode_public_key(&self) -> Vec<u8> {
        let n = self.private_key.n();
        let num_bits = self.bits();

        // Calculate n0inv = -1/n[0] (mod 2^32)
        let b = BigUint::from(1u64 << 32);
        let n_mod_b = n % &b;

        let n0inv = if let Some(inv) = mod_inverse(&n_mod_b, &b) {
            let n0inv_val = &b - (inv % &b);
            let bytes = n0inv_val.to_bytes_le();
            let mut buf = [0u8; 4];
            let len = std::cmp::min(bytes.len(), 4);
            buf[..len].copy_from_slice(&bytes[..len]);
            u32::from_le_bytes(buf)
        } else {
            0
        };

        // Calculate rr = r^2 (mod N), where r = 2^(# of key bits)
        let r = BigUint::from(1u8) << (n.bits() as usize);
        let rr = (&r * &r) % n;

        let mut ret = Vec::new();
        ret.extend_all_be(num_bits);
        ret.extend_all_be(n0inv);
        ret.extend(encode_biguint(n, num_bits / 8));
        ret.extend(encode_biguint(&rr, num_bits / 8));
        ret
    }

    pub fn sign_sha256(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize();

        let num_bits = self.bits();
        let padding = match num_bits {
            2048 => get_pkcs1_v15_padding_sha256_2048(),
            4096 => get_pkcs1_v15_padding_sha256_4096(),
            8192 => get_pkcs1_v15_padding_sha256_8192(),
            _ => {
                return Err(DynoError::Tool(format!(
                    "Unsupported RSA key size for signing: {} bits",
                    num_bits
                )));
            }
        };

        let mut to_sign = padding.to_vec();
        to_sign.extend_from_slice(&hash);

        use rsa::traits::PrivateKeyParts;
        let n = self.private_key.n();
        let d = self.private_key.d();
        let m = BigUint::from_bytes_be(&to_sign);
        let s = m.modpow(d, n);

        Ok(encode_biguint(&s, num_bits / 8))
    }
}

pub fn get_embedded_key(name: &str) -> Option<&'static str> {
    match name {
        "testkey_rsa2048" => Some(include_str!("keys/testkey_rsa2048.pem")),
        "testkey_rsa2048_2" => Some(include_str!("keys/testkey_rsa2048_2.pem")),
        "testkey_rsa4096" => Some(include_str!("keys/testkey_rsa4096.pem")),
        "testkey_rsa8192" => Some(include_str!("keys/testkey_rsa8192.pem")),
        _ => None,
    }
}

trait VecExt {
    fn extend_all_be(&mut self, val: u32);
}

impl VecExt for Vec<u8> {
    fn extend_all_be(&mut self, val: u32) {
        self.extend_from_slice(&val.to_be_bytes());
    }
}

fn encode_biguint(val: &BigUint, len: u32) -> Vec<u8> {
    let bytes = val.to_bytes_be();
    if bytes.len() >= len as usize {
        bytes[bytes.len() - len as usize..].to_vec()
    } else {
        let mut ret = vec![0u8; len as usize - bytes.len()];
        ret.extend_from_slice(&bytes);
        ret
    }
}

fn mod_inverse(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    use num_bigint_dig::{BigInt, Sign};
    use num_integer::Integer;
    use num_traits::Signed;

    let a_bytes = a.to_bytes_be();
    let m_bytes = m.to_bytes_be();
    let a_dig = num_bigint_dig::BigInt::from_bytes_be(Sign::Plus, &a_bytes);
    let m_dig = num_bigint_dig::BigInt::from_bytes_be(Sign::Plus, &m_bytes);

    let egcd = a_dig.extended_gcd(&m_dig);
    if egcd.gcd != BigInt::from(1) {
        return None;
    }

    let mut res = egcd.x % &m_dig;
    if res.is_negative() {
        res += &m_dig;
    }

    let (_, res_bytes) = res.to_bytes_be();
    Some(BigUint::from_bytes_be(&res_bytes))
}

fn get_pkcs1_v15_padding_sha256_2048() -> &'static [u8] {
    lazy_static::lazy_static! {
        static ref PADDING: Vec<u8> = {
            let mut p = vec![0x00, 0x01];
            p.extend(std::iter::repeat(0xff).take(202));
            p.push(0x00);
            p.extend_from_slice(&[
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
                0x00, 0x04, 0x20,
            ]);
            p
        };
    }
    &PADDING
}

fn get_pkcs1_v15_padding_sha256_4096() -> &'static [u8] {
    lazy_static::lazy_static! {
        static ref PADDING: Vec<u8> = {
            let mut p = vec![0x00, 0x01];
            p.extend(std::iter::repeat(0xff).take(458));
            p.push(0x00);
            p.extend_from_slice(&[
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
                0x00, 0x04, 0x20,
            ]);
            p
        };
    }
    &PADDING
}

fn get_pkcs1_v15_padding_sha256_8192() -> &'static [u8] {
    lazy_static::lazy_static! {
        static ref PADDING: Vec<u8> = {
            let mut p = vec![0x00, 0x01];
            p.extend(std::iter::repeat(0xff).take(970));
            p.push(0x00);
            p.extend_from_slice(&[
                0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
                0x00, 0x04, 0x20,
            ]);
            p
        };
    }
    &PADDING
}
