//! Little-endian integer reads and writes at fixed byte offsets.
//!
//! Callers bounds-check the surrounding structure first; these helpers
//! panic on an out-of-range offset like any slice index.

pub(crate) fn read_u16_le(bytes: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(bytes[off..off + 2].try_into().unwrap())
}

pub(crate) fn read_u32_le(bytes: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap())
}

pub(crate) fn write_u32_le(bytes: &mut [u8], off: usize, value: u32) {
    bytes[off..off + 4].copy_from_slice(&value.to_le_bytes());
}

pub(crate) fn write_u16_le(bytes: &mut [u8], off: usize, value: u16) {
    bytes[off..off + 2].copy_from_slice(&value.to_le_bytes());
}
