use std::io::{Cursor, Read, Write};

use dynobox_core::error::{DynoError, Result};
use prost::Message;

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/puffin.metadata.rs"));
}

const MAGIC: &[u8; 4] = b"PUF1";
const MAX_HUFFMAN_BITS: usize = 15;
const LITERALS_MAX_LENGTH: usize = (1 << 16) + 127;
const PERMUTATIONS: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];
const LENGTH_BASES: [u16; 30] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258, 0xFFFF,
];
const LENGTH_EXTRA_BITS: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DISTANCE_BASES: [u16; 31] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577, 0xFFFF,
];
const DISTANCE_EXTRA_BITS: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];

type PatchType = proto::patch_header::PatchType;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PuffPatchKind {
    Bsdiff,
    Zucchini,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BitExtent {
    offset: u64,
    length: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ByteExtent {
    offset: u64,
    length: u64,
}

#[derive(Clone, Debug)]
struct StreamLayout {
    puff_size: u64,
    deflate_stream_size: u64,
    deflates: Vec<BitExtent>,
    puffs: Vec<ByteExtent>,
}

#[derive(Clone, Debug)]
struct ParsedPatch {
    src: StreamLayout,
    dst: StreamLayout,
    patch_type: PatchType,
    raw_patch_offset: usize,
}

#[derive(Clone, Debug)]
enum PuffData {
    Literal(u8),
    Literals(Vec<u8>),
    LenDist { length: u16, distance: u16 },
    BlockMetadata(Vec<u8>),
    EndOfBlock,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PuffReaderState {
    ReadingBlockMetadata,
    ReadingLenDist,
}

struct BufferPuffReader<'a> {
    input: &'a [u8],
    index: usize,
    state: PuffReaderState,
}

impl<'a> BufferPuffReader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            index: 0,
            state: PuffReaderState::ReadingBlockMetadata,
        }
    }

    fn bytes_left(&self) -> usize {
        self.input.len().saturating_sub(self.index)
    }

    fn get_next(&mut self) -> Result<PuffData> {
        if self.state == PuffReaderState::ReadingBlockMetadata {
            if self.index + 2 > self.input.len() {
                return Err(tool_error("Puff metadata truncated"));
            }
            let length = usize::from(read_be_u16(&self.input[self.index..self.index + 2])) + 1;
            self.index += 2;
            if self.index + length > self.input.len() {
                return Err(tool_error("Puff block metadata truncated"));
            }
            let metadata = self.input[self.index..self.index + length].to_vec();
            self.index += length;
            self.state = PuffReaderState::ReadingLenDist;
            return Ok(PuffData::BlockMetadata(metadata));
        }

        if self.index >= self.input.len() {
            return Err(tool_error("Puff stream truncated"));
        }

        let header = self.input[self.index];
        if (header & 0x80) != 0 {
            let mut length = usize::from(header & 0x7F);
            if length >= 127 {
                self.index += 1;
                if self.index >= self.input.len() {
                    return Err(tool_error("Puff len/dist extension truncated"));
                }
                length += usize::from(self.input[self.index]);
            }
            length += 3;
            self.index += 1;

            if length == 259 {
                self.state = PuffReaderState::ReadingBlockMetadata;
                return Ok(PuffData::EndOfBlock);
            }

            if self.index + 2 > self.input.len() {
                return Err(tool_error("Puff len/dist distance truncated"));
            }
            let distance = read_be_u16(&self.input[self.index..self.index + 2]);
            self.index += 2;
            return Ok(PuffData::LenDist {
                length: length as u16,
                distance: distance + 1,
            });
        }

        let mut length = usize::from(header & 0x7F);
        if length < 127 {
            self.index += 1;
        } else {
            self.index += 1;
            if self.index + 2 > self.input.len() {
                return Err(tool_error("Puff literal extension truncated"));
            }
            length += usize::from(read_be_u16(&self.input[self.index..self.index + 2]));
            self.index += 2;
        }
        length += 1;
        if self.index + length > self.input.len() {
            return Err(tool_error("Puff literals truncated"));
        }
        let literals = self.input[self.index..self.index + length].to_vec();
        self.index += length;
        Ok(PuffData::Literals(literals))
    }
}

#[derive(Default)]
struct BufferPuffWriter {
    output: Vec<u8>,
    literal_buf: Vec<u8>,
}

impl BufferPuffWriter {
    fn new() -> Self {
        Self::default()
    }

    fn insert(&mut self, data: PuffData) -> Result<()> {
        match data {
            PuffData::Literal(byte) => self.literal_buf.push(byte),
            PuffData::Literals(bytes) => self.literal_buf.extend_from_slice(&bytes),
            PuffData::LenDist { length, distance } => {
                self.flush_literals();
                if !(3..=258).contains(&length) || !(1..=32768).contains(&distance) {
                    return Err(tool_error("Puff len/dist out of range"));
                }
                if length < 130 {
                    self.output.push(0x80 | ((length - 3) as u8));
                } else {
                    self.output.push(0x80 | 127);
                    self.output.push((length - 3 - 127) as u8);
                }
                write_be_u16(distance - 1, &mut self.output);
            }
            PuffData::BlockMetadata(metadata) => {
                self.flush_literals();
                if metadata.is_empty() || metadata.len() > usize::from(u16::MAX) + 1 {
                    return Err(tool_error("Puff block metadata length out of range"));
                }
                write_be_u16((metadata.len() - 1) as u16, &mut self.output);
                self.output.extend_from_slice(&metadata);
            }
            PuffData::EndOfBlock => {
                self.flush_literals();
                self.output.push(0x80 | 127);
                self.output.push((259 - 3 - 127) as u8);
            }
        }
        Ok(())
    }

    fn flush_literals(&mut self) {
        for chunk in self.literal_buf.chunks(LITERALS_MAX_LENGTH) {
            if chunk.len() < 128 {
                self.output.push((chunk.len() - 1) as u8);
            } else {
                self.output.push(127);
                write_be_u16((chunk.len() - 128) as u16, &mut self.output);
            }
            self.output.extend_from_slice(chunk);
        }
        self.literal_buf.clear();
    }

    fn finish(mut self) -> Vec<u8> {
        self.flush_literals();
        self.output
    }
}

struct BufferBitReader<'a> {
    input: &'a [u8],
    index: usize,
    cache: u32,
    cache_bits: u8,
}

impl<'a> BufferBitReader<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            index: 0,
            cache: 0,
            cache_bits: 0,
        }
    }

    fn cache_bits(&mut self, nbits: usize) -> bool {
        if nbits > 32 {
            return false;
        }
        let remaining_bits =
            (self.input.len().saturating_sub(self.index) * 8) + usize::from(self.cache_bits);
        if remaining_bits < nbits {
            return false;
        }
        while usize::from(self.cache_bits) < nbits {
            self.cache |= u32::from(self.input[self.index]) << self.cache_bits;
            self.index += 1;
            self.cache_bits += 8;
        }
        true
    }

    fn read_bits(&self, nbits: usize) -> u32 {
        if nbits == 0 {
            0
        } else {
            self.cache & ((1u32 << nbits) - 1)
        }
    }

    fn drop_bits(&mut self, nbits: usize) {
        self.cache >>= nbits;
        self.cache_bits -= nbits as u8;
    }

    fn read_boundary_bits(&self) -> u8 {
        let nbits = usize::from(self.cache_bits & 7);
        if nbits == 0 {
            0
        } else {
            (self.cache & ((1u32 << nbits) - 1)) as u8
        }
    }

    fn skip_boundary_bits(&mut self) -> usize {
        let nbits = usize::from(self.cache_bits & 7);
        self.cache >>= nbits;
        self.cache_bits -= nbits as u8;
        nbits
    }

    fn offset(&self) -> usize {
        self.index - usize::from(self.cache_bits / 8)
    }

    fn bits_remaining(&self) -> usize {
        (self.input.len().saturating_sub(self.index) * 8) + usize::from(self.cache_bits)
    }
}

#[derive(Default)]
struct BufferBitWriter {
    output: Vec<u8>,
    holder: u32,
    holder_bits: u8,
}

impl BufferBitWriter {
    fn new() -> Self {
        Self::default()
    }

    fn write_bits(&mut self, mut nbits: usize, mut bits: u32) -> Result<()> {
        while nbits > 0 {
            while self.holder_bits >= 8 {
                self.output.push((self.holder & 0xFF) as u8);
                self.holder >>= 8;
                self.holder_bits -= 8;
            }
            while self.holder_bits < 24 && nbits > 0 {
                self.holder |= (bits & 0xFF) << self.holder_bits;
                let take = nbits.min(8);
                self.holder_bits += take as u8;
                bits >>= take;
                nbits -= take;
            }
        }
        Ok(())
    }

    fn write_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        if self.holder_bits % 8 != 0 {
            return Err(tool_error("Bit writer not at byte boundary"));
        }
        self.flush()?;
        self.output.extend_from_slice(bytes);
        Ok(())
    }

    fn write_boundary_bits(&mut self, bits: u8) -> Result<()> {
        let needed = (8 - usize::from(self.holder_bits & 7)) & 7;
        self.write_bits(needed, u32::from(bits))
    }

    fn flush(&mut self) -> Result<()> {
        self.write_boundary_bits(0)?;
        while self.holder_bits > 0 {
            self.output.push((self.holder & 0xFF) as u8);
            self.holder >>= 8;
            self.holder_bits -= 8;
        }
        Ok(())
    }

    fn finish(mut self) -> Result<Vec<u8>> {
        self.flush()?;
        Ok(self.output)
    }
}

#[derive(Clone, Copy)]
struct CodeIndexPair {
    code: u16,
    index: u16,
}

#[derive(Default)]
struct HuffmanTable {
    codeindexpairs: Vec<CodeIndexPair>,
    lit_len_lens: Vec<u8>,
    lit_len_hcodes: Vec<u16>,
    lit_len_rcodes: Vec<u16>,
    lit_len_max_bits: usize,
    distance_lens: Vec<u8>,
    distance_hcodes: Vec<u16>,
    distance_rcodes: Vec<u16>,
    distance_max_bits: usize,
    tmp_lens: Vec<u8>,
    code_lens: Vec<u8>,
    code_hcodes: Vec<u16>,
    code_rcodes: Vec<u16>,
    code_max_bits: usize,
}

impl HuffmanTable {
    fn new() -> Self {
        Self {
            codeindexpairs: Vec::with_capacity(288),
            ..Self::default()
        }
    }

    fn build_fixed(&mut self) -> Result<()> {
        self.lit_len_lens = vec![0; 288];
        for idx in 0..144 {
            self.lit_len_lens[idx] = 8;
        }
        for idx in 144..256 {
            self.lit_len_lens[idx] = 9;
        }
        for idx in 256..280 {
            self.lit_len_lens[idx] = 7;
        }
        for idx in 280..288 {
            self.lit_len_lens[idx] = 8;
        }
        self.distance_lens = vec![5; 30];
        self.lit_len_hcodes = vec![0; 1 << 9];
        self.distance_hcodes = vec![0; 1 << 5];
        self.lit_len_rcodes = vec![0; 288];
        self.distance_rcodes = vec![0; 30];

        let lit_lens = self.lit_len_lens.clone();
        let mut lit_hcodes = std::mem::take(&mut self.lit_len_hcodes);
        let mut lit_max_bits = self.lit_len_max_bits;
        self.build_huffman_codes(&lit_lens, &mut lit_hcodes, &mut lit_max_bits)?;
        self.lit_len_hcodes = lit_hcodes;
        self.lit_len_max_bits = lit_max_bits;
        let dist_lens = self.distance_lens.clone();
        let mut dist_hcodes = std::mem::take(&mut self.distance_hcodes);
        let mut dist_max_bits = self.distance_max_bits;
        self.build_huffman_codes(&dist_lens, &mut dist_hcodes, &mut dist_max_bits)?;
        self.distance_hcodes = dist_hcodes;
        self.distance_max_bits = dist_max_bits;
        let lit_lens = self.lit_len_lens.clone();
        let mut lit_rcodes = std::mem::take(&mut self.lit_len_rcodes);
        let mut lit_max_bits = self.lit_len_max_bits;
        self.build_huffman_reverse_codes(&lit_lens, &mut lit_rcodes, &mut lit_max_bits)?;
        self.lit_len_rcodes = lit_rcodes;
        self.lit_len_max_bits = lit_max_bits;
        let dist_lens = self.distance_lens.clone();
        let mut dist_rcodes = std::mem::take(&mut self.distance_rcodes);
        let mut dist_max_bits = self.distance_max_bits;
        self.build_huffman_reverse_codes(&dist_lens, &mut dist_rcodes, &mut dist_max_bits)?;
        self.distance_rcodes = dist_rcodes;
        self.distance_max_bits = dist_max_bits;
        Ok(())
    }

    fn check_huffman_array_lengths(
        &self,
        num_lit_len: usize,
        num_distance: usize,
        num_codes: usize,
    ) -> Result<()> {
        if num_lit_len > 286 || num_distance > 30 || num_codes > 19 {
            return Err(tool_error(format!(
                "Invalid dynamic Huffman array lengths: lit_len={num_lit_len} distance={num_distance} codes={num_codes}"
            )));
        }
        Ok(())
    }

    fn lit_len_max_bits(&self) -> usize {
        self.lit_len_max_bits
    }

    fn distance_max_bits(&self) -> usize {
        self.distance_max_bits
    }

    fn end_of_block_bit_length(&self) -> Result<usize> {
        self.lit_len_lens
            .get(256)
            .copied()
            .map(usize::from)
            .ok_or_else(|| tool_error("End-of-block Huffman code missing"))
    }

    fn init_huffman_codes(&mut self, lens: &[u8]) -> Result<usize> {
        let mut len_count = [0u32; MAX_HUFFMAN_BITS + 1];
        let mut next_code = [0u32; MAX_HUFFMAN_BITS + 1];
        for &len in lens {
            if usize::from(len) > MAX_HUFFMAN_BITS {
                return Err(tool_error("Huffman code length exceeds RFC1951 maximum"));
            }
            len_count[len as usize] += 1;
        }

        let mut max_bits = 0usize;
        for bits in (1..=MAX_HUFFMAN_BITS).rev() {
            if len_count[bits] != 0 {
                max_bits = bits;
                break;
            }
        }

        for bits in 1..=max_bits {
            if len_count[bits] > (1 << bits) {
                return Err(tool_error("Oversubscribed Huffman code lengths"));
            }
        }

        let mut code = 0u32;
        for bits in 1..=MAX_HUFFMAN_BITS {
            code = (code + len_count[bits - 1]) << 1;
            next_code[bits] = code;
        }

        self.codeindexpairs.clear();
        for (index, &len) in lens.iter().enumerate() {
            if len == 0 {
                continue;
            }
            let mut reversed = 0u16;
            let mut tmp_code = next_code[len as usize];
            for _ in 0..len {
                reversed <<= 1;
                reversed |= (tmp_code & 1) as u16;
                tmp_code >>= 1;
            }
            self.codeindexpairs.push(CodeIndexPair {
                code: reversed,
                index: index as u16,
            });
            next_code[len as usize] += 1;
        }
        Ok(max_bits)
    }

    fn build_huffman_codes(
        &mut self,
        lens: &[u8],
        hcodes: &mut Vec<u16>,
        max_bits: &mut usize,
    ) -> Result<()> {
        *max_bits = self.init_huffman_codes(lens)?;
        let size = 1usize << (*max_bits).max(1);
        if hcodes.len() != size {
            hcodes.resize(size, 0);
        }
        hcodes.fill(0);
        self.codeindexpairs
            .sort_by(|a, b| lens[b.index as usize].cmp(&lens[a.index as usize]));

        for pair in &self.codeindexpairs {
            hcodes[pair.code as usize] = pair.index | 0x8000;
            let fill_bits = *max_bits - usize::from(lens[pair.index as usize]);
            for idx in 1..(1 << fill_bits) {
                let location = (idx << lens[pair.index as usize]) | usize::from(pair.code);
                if (hcodes[location] & 0x8000) == 0 {
                    hcodes[location] = pair.index | 0x8000;
                }
            }
        }
        Ok(())
    }

    fn build_huffman_reverse_codes(
        &mut self,
        lens: &[u8],
        rcodes: &mut Vec<u16>,
        max_bits: &mut usize,
    ) -> Result<()> {
        *max_bits = self.init_huffman_codes(lens)?;
        if rcodes.len() != lens.len() {
            rcodes.resize(lens.len(), 0);
        }
        self.codeindexpairs.sort_by(|a, b| a.index.cmp(&b.index));
        let mut pair_index = 0usize;
        for index in 0..rcodes.len() {
            if pair_index < self.codeindexpairs.len()
                && index == usize::from(self.codeindexpairs[pair_index].index)
            {
                rcodes[index] = self.codeindexpairs[pair_index].code;
                pair_index += 1;
            } else {
                rcodes[index] = 0;
            }
        }
        Ok(())
    }

    fn lit_len_alphabet(&self, bits: u32) -> Result<(u16, usize)> {
        let entry = *self
            .lit_len_hcodes
            .get(bits as usize)
            .ok_or_else(|| tool_error("Literal/length Huffman lookup out of range"))?;
        if (entry & 0x8000) == 0 {
            return Err(tool_error("Invalid literal/length Huffman code"));
        }
        let alphabet = entry & 0x7FFF;
        let nbits = *self
            .lit_len_lens
            .get(alphabet as usize)
            .ok_or_else(|| tool_error("Literal/length alphabet out of range"))?;
        Ok((alphabet, usize::from(nbits)))
    }

    fn distance_alphabet(&self, bits: u32) -> Result<(u16, usize)> {
        let entry = *self
            .distance_hcodes
            .get(bits as usize)
            .ok_or_else(|| tool_error("Distance Huffman lookup out of range"))?;
        if (entry & 0x8000) == 0 {
            return Err(tool_error("Invalid distance Huffman code"));
        }
        let alphabet = entry & 0x7FFF;
        let nbits = *self
            .distance_lens
            .get(alphabet as usize)
            .ok_or_else(|| tool_error("Distance alphabet out of range"))?;
        Ok((alphabet, usize::from(nbits)))
    }

    fn code_alphabet(&self, bits: u32) -> Result<(u16, usize)> {
        let entry = *self
            .code_hcodes
            .get(bits as usize)
            .ok_or_else(|| tool_error("Code-length Huffman lookup out of range"))?;
        if (entry & 0x8000) == 0 {
            return Err(tool_error("Invalid code-length Huffman code"));
        }
        let alphabet = entry & 0x7FFF;
        let nbits = *self
            .code_lens
            .get(alphabet as usize)
            .ok_or_else(|| tool_error("Code-length alphabet out of range"))?;
        Ok((alphabet, usize::from(nbits)))
    }

    fn lit_len_huffman(&self, alphabet: u16) -> Result<(u16, usize)> {
        let nbits = *self
            .lit_len_lens
            .get(alphabet as usize)
            .ok_or_else(|| tool_error("Literal/length alphabet out of range"))?;
        let code = *self
            .lit_len_rcodes
            .get(alphabet as usize)
            .ok_or_else(|| tool_error("Literal/length reverse code out of range"))?;
        Ok((code, usize::from(nbits)))
    }

    fn distance_huffman(&self, alphabet: u16) -> Result<(u16, usize)> {
        let nbits = *self
            .distance_lens
            .get(alphabet as usize)
            .ok_or_else(|| tool_error("Distance alphabet out of range"))?;
        let code = *self
            .distance_rcodes
            .get(alphabet as usize)
            .ok_or_else(|| tool_error("Distance reverse code out of range"))?;
        Ok((code, usize::from(nbits)))
    }

    fn code_huffman(&self, alphabet: u16) -> Result<(u16, usize)> {
        let nbits = *self
            .code_lens
            .get(alphabet as usize)
            .ok_or_else(|| tool_error("Code-length alphabet out of range"))?;
        let code = *self
            .code_rcodes
            .get(alphabet as usize)
            .ok_or_else(|| tool_error("Code-length reverse code out of range"))?;
        Ok((code, usize::from(nbits)))
    }

    fn build_dynamic_from_reader(&mut self, reader: &mut BufferBitReader<'_>) -> Result<Vec<u8>> {
        self.code_lens.resize(19, 0);
        self.code_hcodes.resize(1 << 7, 0);
        self.lit_len_lens.resize(286, 0);
        self.lit_len_hcodes.resize(1 << 15, 0);
        self.distance_lens.resize(30, 0);
        self.distance_hcodes.resize(1 << 15, 0);
        self.tmp_lens.resize(286 + 30, 0);

        if !reader.cache_bits(14) {
            return Err(tool_error("Dynamic Huffman header truncated"));
        }

        let mut metadata = Vec::new();
        let hlit = reader.read_bits(5) as u8;
        metadata.push(hlit);
        let num_lit_len = usize::from(hlit) + 257;
        reader.drop_bits(5);

        let hdist = reader.read_bits(5) as u8;
        metadata.push(hdist);
        let num_distance = usize::from(hdist) + 1;
        reader.drop_bits(5);

        let hclen = reader.read_bits(4) as u8;
        metadata.push(hclen);
        let num_codes = usize::from(hclen) + 4;
        reader.drop_bits(4);

        self.check_huffman_array_lengths(num_lit_len, num_distance, num_codes)?;

        let mut pending_byte = 0u8;
        let mut have_low_nibble = false;
        for idx in 0..num_codes {
            if !reader.cache_bits(3) {
                return Err(tool_error("Dynamic Huffman code lengths truncated"));
            }
            let len = reader.read_bits(3) as u8;
            self.code_lens[PERMUTATIONS[idx]] = len;
            if have_low_nibble {
                pending_byte |= len;
                metadata.push(pending_byte);
            } else {
                pending_byte = len << 4;
            }
            have_low_nibble = !have_low_nibble;
            reader.drop_bits(3);
        }
        if have_low_nibble {
            metadata.push(pending_byte);
        }
        for idx in num_codes..19 {
            self.code_lens[PERMUTATIONS[idx]] = 0;
        }

        let code_lens = self.code_lens.clone();
        let mut code_hcodes = std::mem::take(&mut self.code_hcodes);
        let mut code_max_bits = self.code_max_bits;
        self.build_huffman_codes(&code_lens, &mut code_hcodes, &mut code_max_bits)?;
        self.code_hcodes = code_hcodes;
        self.code_max_bits = code_max_bits;
        let mut lens_metadata = Vec::new();
        self.tmp_lens = self.build_huffman_code_lengths_from_reader(
            reader,
            &mut lens_metadata,
            self.code_max_bits,
            num_lit_len + num_distance,
        )?;
        metadata.extend_from_slice(&lens_metadata);

        self.lit_len_lens.clear();
        self.lit_len_lens
            .extend_from_slice(&self.tmp_lens[..num_lit_len]);
        self.distance_lens.clear();
        self.distance_lens
            .extend_from_slice(&self.tmp_lens[num_lit_len..]);

        let lit_lens = self.lit_len_lens.clone();
        let mut lit_hcodes = std::mem::take(&mut self.lit_len_hcodes);
        let mut lit_max_bits = self.lit_len_max_bits;
        self.build_huffman_codes(&lit_lens, &mut lit_hcodes, &mut lit_max_bits)?;
        self.lit_len_hcodes = lit_hcodes;
        self.lit_len_max_bits = lit_max_bits;
        let dist_lens = self.distance_lens.clone();
        let mut dist_hcodes = std::mem::take(&mut self.distance_hcodes);
        let mut dist_max_bits = self.distance_max_bits;
        self.build_huffman_codes(&dist_lens, &mut dist_hcodes, &mut dist_max_bits)?;
        self.distance_hcodes = dist_hcodes;
        self.distance_max_bits = dist_max_bits;
        Ok(metadata)
    }

    fn build_dynamic_from_metadata(
        &mut self,
        metadata: &[u8],
        writer: &mut BufferBitWriter,
    ) -> Result<()> {
        self.code_lens.resize(19, 0);
        self.code_rcodes.resize(19, 0);
        self.lit_len_lens.resize(286, 0);
        self.lit_len_rcodes.resize(286, 0);
        self.distance_lens.resize(30, 0);
        self.distance_rcodes.resize(30, 0);
        self.tmp_lens.resize(286 + 30, 0);

        if metadata.len() < 3 {
            return Err(tool_error("Puff dynamic metadata too short"));
        }

        let mut index = 0usize;
        let num_lit_len = usize::from(metadata[index]) + 257;
        writer.write_bits(5, u32::from(metadata[index]))?;
        index += 1;
        let num_distance = usize::from(metadata[index]) + 1;
        writer.write_bits(5, u32::from(metadata[index]))?;
        index += 1;
        let num_codes = usize::from(metadata[index]) + 4;
        writer.write_bits(4, u32::from(metadata[index]))?;
        index += 1;

        self.check_huffman_array_lengths(num_lit_len, num_distance, num_codes)?;

        let mut have_low_nibble = false;
        for idx in 0..num_codes {
            let len = if have_low_nibble {
                let value = metadata
                    .get(index)
                    .ok_or_else(|| tool_error("Puff dynamic code length metadata truncated"))?
                    & 0x0F;
                index += 1;
                value
            } else {
                metadata
                    .get(index)
                    .ok_or_else(|| tool_error("Puff dynamic code length metadata truncated"))?
                    >> 4
            };
            self.code_lens[PERMUTATIONS[idx]] = len;
            writer.write_bits(3, u32::from(len))?;
            have_low_nibble = !have_low_nibble;
        }
        if have_low_nibble {
            index += 1;
        }
        for idx in num_codes..19 {
            self.code_lens[PERMUTATIONS[idx]] = 0;
        }

        let code_lens = self.code_lens.clone();
        let mut code_rcodes = std::mem::take(&mut self.code_rcodes);
        let mut code_max_bits = self.code_max_bits;
        self.build_huffman_reverse_codes(&code_lens, &mut code_rcodes, &mut code_max_bits)?;
        self.code_rcodes = code_rcodes;
        self.code_max_bits = code_max_bits;
        let mut remaining = &metadata[index..];
        self.tmp_lens = self.build_huffman_code_lengths_from_metadata(
            &mut remaining,
            writer,
            num_lit_len + num_distance,
        )?;
        if !remaining.is_empty() {
            return Err(tool_error("Unused dynamic Huffman metadata bytes remain"));
        }

        self.lit_len_lens.clear();
        self.lit_len_lens
            .extend_from_slice(&self.tmp_lens[..num_lit_len]);
        self.distance_lens.clear();
        self.distance_lens
            .extend_from_slice(&self.tmp_lens[num_lit_len..]);

        let lit_lens = self.lit_len_lens.clone();
        let mut lit_rcodes = std::mem::take(&mut self.lit_len_rcodes);
        let mut lit_max_bits = self.lit_len_max_bits;
        self.build_huffman_reverse_codes(&lit_lens, &mut lit_rcodes, &mut lit_max_bits)?;
        self.lit_len_rcodes = lit_rcodes;
        self.lit_len_max_bits = lit_max_bits;
        let dist_lens = self.distance_lens.clone();
        let mut dist_rcodes = std::mem::take(&mut self.distance_rcodes);
        let mut dist_max_bits = self.distance_max_bits;
        self.build_huffman_reverse_codes(&dist_lens, &mut dist_rcodes, &mut dist_max_bits)?;
        self.distance_rcodes = dist_rcodes;
        self.distance_max_bits = dist_max_bits;
        Ok(())
    }

    fn build_huffman_code_lengths_from_reader(
        &self,
        reader: &mut BufferBitReader<'_>,
        metadata_out: &mut Vec<u8>,
        max_bits: usize,
        num_codes: usize,
    ) -> Result<Vec<u8>> {
        let mut lens = Vec::with_capacity(num_codes);
        while lens.len() < num_codes {
            if !reader.cache_bits(max_bits) {
                return Err(tool_error("Dynamic Huffman code lengths truncated"));
            }
            let bits = reader.read_bits(max_bits);
            let (code, nbits) = self.code_alphabet(bits)?;
            reader.drop_bits(nbits);

            if code < 16 {
                metadata_out.push(code as u8);
                lens.push(code as u8);
                continue;
            }

            let (copy_num, copy_val, encoded) = match code {
                16 => {
                    if lens.is_empty() {
                        return Err(tool_error("Dynamic Huffman repeat-without-previous code"));
                    }
                    if !reader.cache_bits(2) {
                        return Err(tool_error("Dynamic Huffman repeat code truncated"));
                    }
                    let extra = reader.read_bits(2) as usize;
                    reader.drop_bits(2);
                    (3 + extra, *lens.last().unwrap(), 16 + extra as u8)
                }
                17 => {
                    if !reader.cache_bits(3) {
                        return Err(tool_error("Dynamic Huffman zero-repeat code truncated"));
                    }
                    let extra = reader.read_bits(3) as usize;
                    reader.drop_bits(3);
                    (3 + extra, 0, 20 + extra as u8)
                }
                18 => {
                    if !reader.cache_bits(7) {
                        return Err(tool_error(
                            "Dynamic Huffman long zero-repeat code truncated",
                        ));
                    }
                    let extra = reader.read_bits(7) as usize;
                    reader.drop_bits(7);
                    (11 + extra, 0, 28 + extra as u8)
                }
                _ => return Err(tool_error("Invalid dynamic Huffman code-length code")),
            };
            metadata_out.push(encoded);
            for _ in 0..copy_num {
                lens.push(copy_val);
            }
        }

        if lens.len() != num_codes {
            return Err(tool_error("Dynamic Huffman code lengths size mismatch"));
        }
        Ok(lens)
    }

    fn build_huffman_code_lengths_from_metadata(
        &self,
        metadata: &mut &[u8],
        writer: &mut BufferBitWriter,
        num_codes: usize,
    ) -> Result<Vec<u8>> {
        let mut lens = Vec::with_capacity(num_codes);
        while lens.len() < num_codes {
            let &pcode = metadata
                .first()
                .ok_or_else(|| tool_error("Puff dynamic metadata truncated"))?;
            *metadata = &metadata[1..];

            if pcode > 155 {
                return Err(tool_error("Puff dynamic metadata code out of range"));
            }

            let code = if pcode < 16 {
                pcode
            } else if pcode < 20 {
                16
            } else if pcode < 28 {
                17
            } else {
                18
            };

            let (huffman, nbits) = self.code_huffman(u16::from(code))?;
            writer.write_bits(nbits, u32::from(huffman))?;

            if code < 16 {
                lens.push(code);
                continue;
            }

            let (copy_num, copy_val) = match code {
                16 => {
                    if lens.is_empty() {
                        return Err(tool_error("Puff repeat-without-previous code"));
                    }
                    writer.write_bits(2, u32::from(pcode - 16))?;
                    (3 + usize::from(pcode - 16), *lens.last().unwrap())
                }
                17 => {
                    writer.write_bits(3, u32::from(pcode - 20))?;
                    (3 + usize::from(pcode - 20), 0)
                }
                18 => {
                    writer.write_bits(7, u32::from(pcode - 28))?;
                    (11 + usize::from(pcode - 28), 0)
                }
                _ => unreachable!(),
            };
            for _ in 0..copy_num {
                lens.push(copy_val);
            }
        }

        if lens.len() != num_codes {
            return Err(tool_error("Puff dynamic metadata lens size mismatch"));
        }
        Ok(lens)
    }
}

struct Puffer {
    dyn_ht: HuffmanTable,
    fix_ht: HuffmanTable,
}

impl Puffer {
    fn new() -> Self {
        Self {
            dyn_ht: HuffmanTable::new(),
            fix_ht: HuffmanTable::new(),
        }
    }

    fn puff_deflate(&mut self, input: &[u8], skip_bits: usize) -> Result<Vec<u8>> {
        let mut reader = BufferBitReader::new(input);
        if skip_bits > 0 {
            if !reader.cache_bits(skip_bits) {
                return Err(tool_error("Deflate skip bits exceed input"));
            }
            reader.drop_bits(skip_bits);
        }

        let mut writer = BufferPuffWriter::new();
        let mut end_loop = false;
        while !end_loop && reader.cache_bits(8) {
            if !reader.cache_bits(3) {
                return Err(tool_error("Deflate block header truncated"));
            }
            let final_bit = reader.read_bits(1) as u8;
            reader.drop_bits(1);
            let block_type = reader.read_bits(2) as u8;
            reader.drop_bits(2);
            if final_bit != 0 {
                end_loop = true;
            }

            let mut block_header = (final_bit << 7) | (block_type << 5);
            let table = match block_type {
                0 => {
                    let skipped_bits = reader.read_boundary_bits();
                    reader.skip_boundary_bits();
                    if !reader.cache_bits(32) {
                        return Err(tool_error("Uncompressed deflate header truncated"));
                    }
                    let len = reader.read_bits(16) as usize;
                    reader.drop_bits(16);
                    let nlen = reader.read_bits(16) as u16;
                    reader.drop_bits(16);
                    if ((len as u16) ^ nlen) != 0xFFFF {
                        return Err(tool_error("Invalid uncompressed deflate LEN/NLEN"));
                    }

                    block_header |= skipped_bits;
                    writer.insert(PuffData::BlockMetadata(vec![block_header]))?;
                    let start = reader.offset();
                    let end = start + len;
                    let bytes = input
                        .get(start..end)
                        .ok_or_else(|| tool_error("Uncompressed deflate payload truncated"))?
                        .to_vec();
                    reader.index = end;
                    reader.cache = 0;
                    reader.cache_bits = 0;
                    writer.insert(PuffData::Literals(bytes))?;
                    writer.insert(PuffData::EndOfBlock)?;
                    continue;
                }
                1 => {
                    self.fix_ht.build_fixed()?;
                    writer.insert(PuffData::BlockMetadata(vec![block_header]))?;
                    &self.fix_ht
                }
                2 => {
                    let metadata = self.dyn_ht.build_dynamic_from_reader(&mut reader)?;
                    let mut block_metadata = Vec::with_capacity(metadata.len() + 1);
                    block_metadata.push(block_header);
                    block_metadata.extend_from_slice(&metadata);
                    writer.insert(PuffData::BlockMetadata(block_metadata))?;
                    &self.dyn_ht
                }
                _ => return Err(tool_error("Invalid deflate block type")),
            };

            loop {
                let mut bits_to_cache = table.lit_len_max_bits();
                if !reader.cache_bits(bits_to_cache) {
                    bits_to_cache = table.end_of_block_bit_length()?;
                }
                if !reader.cache_bits(bits_to_cache) {
                    return Err(tool_error("Literal/length Huffman stream truncated"));
                }
                let bits = reader.read_bits(bits_to_cache);
                let (lit_len_alphabet, nbits) = table.lit_len_alphabet(bits)?;
                reader.drop_bits(nbits);

                if lit_len_alphabet < 256 {
                    writer.insert(PuffData::Literal(lit_len_alphabet as u8))?;
                    continue;
                }
                if lit_len_alphabet == 256 {
                    writer.insert(PuffData::EndOfBlock)?;
                    break;
                }
                if lit_len_alphabet > 285 {
                    return Err(tool_error("Invalid deflate length alphabet"));
                }

                let len_index = usize::from(lit_len_alphabet - 257);
                let extra_len_bits = usize::from(LENGTH_EXTRA_BITS[len_index]);
                let extra_len = if extra_len_bits > 0 {
                    if !reader.cache_bits(extra_len_bits) {
                        return Err(tool_error("Deflate length extra bits truncated"));
                    }
                    let value = reader.read_bits(extra_len_bits) as u16;
                    reader.drop_bits(extra_len_bits);
                    value
                } else {
                    0
                };
                let length = LENGTH_BASES[len_index] + extra_len;

                let mut distance_bits = table.distance_max_bits();
                if !reader.cache_bits(distance_bits) {
                    distance_bits = reader.bits_remaining();
                }
                if !reader.cache_bits(distance_bits) {
                    return Err(tool_error("Deflate distance Huffman stream truncated"));
                }
                let bits = reader.read_bits(distance_bits);
                let (distance_alphabet, nbits) = table.distance_alphabet(bits)?;
                reader.drop_bits(nbits);

                let extra_dist_bits = usize::from(DISTANCE_EXTRA_BITS[distance_alphabet as usize]);
                let extra_dist = if extra_dist_bits > 0 {
                    if !reader.cache_bits(extra_dist_bits) {
                        return Err(tool_error("Deflate distance extra bits truncated"));
                    }
                    let value = reader.read_bits(extra_dist_bits) as u16;
                    reader.drop_bits(extra_dist_bits);
                    value
                } else {
                    0
                };
                let distance = DISTANCE_BASES[distance_alphabet as usize] + extra_dist;
                writer.insert(PuffData::LenDist { length, distance })?;
            }
        }

        Ok(writer.finish())
    }
}

struct Huffer {
    dyn_ht: HuffmanTable,
    fix_ht: HuffmanTable,
}

impl Huffer {
    fn new() -> Self {
        Self {
            dyn_ht: HuffmanTable::new(),
            fix_ht: HuffmanTable::new(),
        }
    }

    fn huff_deflate(
        &mut self,
        input: &[u8],
        prefix_bits: usize,
        prefix_value: u8,
    ) -> Result<Vec<u8>> {
        let mut reader = BufferPuffReader::new(input);
        let mut writer = BufferBitWriter::new();
        if prefix_bits > 0 {
            writer.write_bits(prefix_bits, u32::from(prefix_value))?;
        }

        while reader.bytes_left() != 0 {
            let metadata = reader.get_next()?;
            let PuffData::BlockMetadata(block_metadata) = metadata else {
                return Err(tool_error("Puff stream must start block with metadata"));
            };
            if block_metadata.is_empty() {
                return Err(tool_error("Puff block metadata missing header"));
            }
            let header = block_metadata[0];
            let final_bit = (header & 0x80) >> 7;
            let block_type = (header & 0x60) >> 5;
            let skipped_bits = header & 0x1F;

            writer.write_bits(1, u32::from(final_bit))?;
            writer.write_bits(2, u32::from(block_type))?;

            let table = match block_type {
                0 => {
                    writer.write_boundary_bits(skipped_bits)?;
                    match reader.get_next()? {
                        PuffData::Literals(bytes) => {
                            writer.write_bits(16, bytes.len() as u32)?;
                            writer.write_bits(16, !(bytes.len() as u32) & 0xFFFF)?;
                            writer.write_bytes(&bytes)?;
                            if !matches!(reader.get_next()?, PuffData::EndOfBlock) {
                                return Err(tool_error(
                                    "Uncompressed puff block missing end-of-block",
                                ));
                            }
                        }
                        PuffData::EndOfBlock => {
                            writer.write_bits(16, 0)?;
                            writer.write_bits(16, 0xFFFF)?;
                        }
                        _ => return Err(tool_error("Unexpected puff token in uncompressed block")),
                    }
                    continue;
                }
                1 => {
                    self.fix_ht.build_fixed()?;
                    &self.fix_ht
                }
                2 => {
                    self.dyn_ht
                        .build_dynamic_from_metadata(&block_metadata[1..], &mut writer)?;
                    &self.dyn_ht
                }
                _ => return Err(tool_error("Invalid puff block type")),
            };

            let mut block_ended = false;
            while !block_ended {
                match reader.get_next()? {
                    PuffData::Literal(byte) => {
                        let (huffman, nbits) = table.lit_len_huffman(u16::from(byte))?;
                        writer.write_bits(nbits, u32::from(huffman))?;
                    }
                    PuffData::Literals(bytes) => {
                        for byte in bytes {
                            let (huffman, nbits) = table.lit_len_huffman(u16::from(byte))?;
                            writer.write_bits(nbits, u32::from(huffman))?;
                        }
                    }
                    PuffData::LenDist { length, distance } => {
                        let mut length_index = 0usize;
                        while length > LENGTH_BASES[length_index] {
                            length_index += 1;
                        }
                        if length < LENGTH_BASES[length_index] {
                            length_index -= 1;
                        }
                        let (huffman, nbits) =
                            table.lit_len_huffman((length_index + 257) as u16)?;
                        writer.write_bits(nbits, u32::from(huffman))?;
                        let extra_len_bits = usize::from(LENGTH_EXTRA_BITS[length_index]);
                        if extra_len_bits > 0 {
                            writer.write_bits(
                                extra_len_bits,
                                u32::from(length - LENGTH_BASES[length_index]),
                            )?;
                        }

                        let mut distance_index = 0usize;
                        while distance > DISTANCE_BASES[distance_index] {
                            distance_index += 1;
                        }
                        if distance < DISTANCE_BASES[distance_index] {
                            distance_index -= 1;
                        }
                        let (huffman, nbits) = table.distance_huffman(distance_index as u16)?;
                        writer.write_bits(nbits, u32::from(huffman))?;
                        let extra_dist_bits = usize::from(DISTANCE_EXTRA_BITS[distance_index]);
                        if extra_dist_bits > 0 {
                            writer.write_bits(
                                extra_dist_bits,
                                u32::from(distance - DISTANCE_BASES[distance_index]),
                            )?;
                        }
                    }
                    PuffData::EndOfBlock => {
                        let (huffman, nbits) = table.lit_len_huffman(256)?;
                        writer.write_bits(nbits, u32::from(huffman))?;
                        block_ended = true;
                    }
                    PuffData::BlockMetadata(_) => {
                        return Err(tool_error("Unexpected nested puff block metadata"));
                    }
                }
            }
        }

        writer.finish()
    }
}

fn write_be_u16(value: u16, out: &mut Vec<u8>) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn read_be_u16(bytes: &[u8]) -> u16 {
    u16::from_be_bytes([bytes[0], bytes[1]])
}

fn tool_error(message: impl Into<String>) -> DynoError {
    DynoError::Tool(message.into())
}

fn decode_bit_extents(extents: &[proto::BitExtent]) -> Vec<BitExtent> {
    extents
        .iter()
        .map(|extent| BitExtent {
            offset: extent.offset,
            length: extent.length,
        })
        .collect()
}

fn decode_byte_extents(extents: &[proto::BitExtent]) -> Result<Vec<ByteExtent>> {
    let mut result = Vec::with_capacity(extents.len());
    for extent in extents {
        if extent.offset % 8 != 0 || extent.length % 8 != 0 {
            return Err(tool_error("Puff extents must be byte-aligned"));
        }
        result.push(ByteExtent {
            offset: extent.offset / 8,
            length: extent.length / 8,
        });
    }
    Ok(result)
}

fn validate_sorted_non_overlapping_bits(extents: &[BitExtent]) -> Result<()> {
    for pair in extents.windows(2) {
        let current = pair[0];
        let next = pair[1];
        if current.offset + current.length > next.offset {
            return Err(tool_error("Deflate extents overlap or are unsorted"));
        }
    }
    Ok(())
}

fn validate_sorted_non_overlapping_bytes(extents: &[ByteExtent]) -> Result<()> {
    for pair in extents.windows(2) {
        let current = pair[0];
        let next = pair[1];
        if current.offset + current.length > next.offset {
            return Err(tool_error("Puff extents overlap or are unsorted"));
        }
    }
    Ok(())
}

fn build_stream_layout(
    puff_size: u64,
    mut deflates: Vec<BitExtent>,
    mut puffs: Vec<ByteExtent>,
) -> Result<StreamLayout> {
    if deflates.len() != puffs.len() {
        return Err(tool_error("Puff patch deflate/puff extent count mismatch"));
    }
    validate_sorted_non_overlapping_bits(&deflates)?;
    validate_sorted_non_overlapping_bytes(&puffs)?;
    if let Some(last_puff) = puffs.last() {
        if last_puff.offset + last_puff.length > puff_size {
            return Err(tool_error("Puff stream size smaller than last puff extent"));
        }
    }

    let deflate_stream_size =
        if let (Some(last_deflate), Some(last_puff)) = (deflates.last(), puffs.last()) {
            ((last_deflate.offset + last_deflate.length) / 8) + puff_size
                - (last_puff.offset + last_puff.length)
        } else {
            puff_size
        };

    deflates.push(BitExtent {
        offset: deflate_stream_size * 8,
        length: 0,
    });
    puffs.push(ByteExtent {
        offset: puff_size,
        length: 0,
    });

    Ok(StreamLayout {
        puff_size,
        deflate_stream_size,
        deflates,
        puffs,
    })
}

fn parse_patch(patch: &[u8]) -> Result<ParsedPatch> {
    if patch.len() < 8 {
        return Err(tool_error("Puff patch too small"));
    }
    if &patch[..4] != MAGIC {
        return Err(tool_error(format!(
            "Invalid Puff patch magic: {:?}",
            &patch[..4]
        )));
    }

    let header_size = u32::from_be_bytes([patch[4], patch[5], patch[6], patch[7]]) as usize;
    let header_end = 8 + header_size;
    if patch.len() < header_end {
        return Err(tool_error("Puff patch header truncated"));
    }

    let header = proto::PatchHeader::decode(&patch[8..header_end])
        .map_err(|e| tool_error(format!("Failed to decode Puff patch header: {e}")))?;
    let patch_type = PatchType::try_from(header.r#type)
        .map_err(|_| tool_error(format!("Unsupported Puff patch type id: {}", header.r#type)))?;

    let src = header
        .src
        .ok_or_else(|| tool_error("Puff patch missing source stream info"))?;
    let dst = header
        .dst
        .ok_or_else(|| tool_error("Puff patch missing destination stream info"))?;

    Ok(ParsedPatch {
        src: build_stream_layout(
            src.puff_length,
            decode_bit_extents(&src.deflates),
            decode_byte_extents(&src.puffs)?,
        )?,
        dst: build_stream_layout(
            dst.puff_length,
            decode_bit_extents(&dst.deflates),
            decode_byte_extents(&dst.puffs)?,
        )?,
        patch_type,
        raw_patch_offset: header_end,
    })
}

pub fn inspect_puff_patch_type(patch: &[u8]) -> Result<PuffPatchKind> {
    let parsed = parse_patch(patch)?;
    match parsed.patch_type {
        PatchType::Bsdiff => Ok(PuffPatchKind::Bsdiff),
        PatchType::Zucchini => Ok(PuffPatchKind::Zucchini),
    }
}

fn puff_stream(source: &[u8], layout: &StreamLayout) -> Result<Vec<u8>> {
    if source.len() < layout.deflate_stream_size as usize {
        return Err(tool_error(format!(
            "Source data too small for Puff stream: need {} bytes, got {}",
            layout.deflate_stream_size,
            source.len()
        )));
    }

    let mut output = Vec::with_capacity(layout.puff_size as usize);
    let mut puff_pos = 0u64;
    let mut skip_bytes = 0u64;
    let mut deflate_bit_pos = 0u64;
    let mut current = 0usize;
    let mut puffer = Puffer::new();

    while output.len() < layout.puff_size as usize {
        let current_puff = layout.puffs[current];
        let current_deflate = layout.deflates[current];
        let remaining = layout.puff_size as usize - output.len();

        if puff_pos < current_puff.offset {
            let start_byte = (deflate_bit_pos / 8) as usize;
            let end_byte = current_deflate.offset.div_ceil(8) as usize;
            let bytes_to_read = remaining.min(end_byte.saturating_sub(start_byte));
            if bytes_to_read == 0 {
                return Err(tool_error("Failed to advance raw segment while puffing"));
            }
            let end = start_byte + bytes_to_read;
            let mut chunk = source
                .get(start_byte..end)
                .ok_or_else(|| tool_error("Raw segment extends past source buffer"))?
                .to_vec();
            if (u64::try_from(end).unwrap() * 8) > current_deflate.offset {
                let bit_count = (current_deflate.offset & 7) as u32;
                let mask = ((1u16 << bit_count) - 1) as u8;
                if let Some(last) = chunk.last_mut() {
                    *last &= mask;
                }
            }
            if (start_byte as u64) * 8 < deflate_bit_pos {
                if let Some(first) = chunk.first_mut() {
                    *first >>= (deflate_bit_pos & 7) as u8;
                }
            }
            deflate_bit_pos -= deflate_bit_pos & 7;
            deflate_bit_pos += (bytes_to_read as u64) * 8;
            if deflate_bit_pos > current_deflate.offset {
                deflate_bit_pos = current_deflate.offset;
            }
            puff_pos += bytes_to_read as u64;
            output.extend_from_slice(&chunk);
            continue;
        }

        let start_byte = (current_deflate.offset / 8) as usize;
        let end_byte = (current_deflate.offset + current_deflate.length).div_ceil(8) as usize;
        let deflate_bytes = source
            .get(start_byte..end_byte)
            .ok_or_else(|| tool_error("Deflate extent extends past source buffer"))?;
        let puffed = puffer.puff_deflate(deflate_bytes, (current_deflate.offset & 7) as usize)?;
        if puffed.len() != current_puff.length as usize {
            return Err(tool_error(format!(
                "Puffed stream size mismatch: expected {} bytes, got {}",
                current_puff.length,
                puffed.len()
            )));
        }
        let bytes_to_copy = remaining.min((current_puff.length - skip_bytes) as usize);
        let start = skip_bytes as usize;
        output.extend_from_slice(&puffed[start..start + bytes_to_copy]);
        skip_bytes += bytes_to_copy as u64;

        if puff_pos + skip_bytes == current_puff.offset + current_puff.length {
            puff_pos += skip_bytes;
            skip_bytes = 0;
            deflate_bit_pos = current_deflate.offset + current_deflate.length;
            current += 1;
        }
    }

    Ok(output)
}

fn extra_byte_for(layout: &StreamLayout, index: usize) -> u8 {
    if index + 1 >= layout.deflates.len() {
        return 0;
    }
    let current = layout.deflates[index];
    let next = layout.deflates[index + 1];
    let end_bit = current.offset + current.length;
    if (end_bit & 7) != 0 && ((end_bit + 7) & !7u64) <= next.offset {
        1
    } else {
        0
    }
}

fn huff_stream(puffed: &[u8], layout: &StreamLayout) -> Result<Vec<u8>> {
    if puffed.len() != layout.puff_size as usize {
        return Err(tool_error(format!(
            "Puff stream size mismatch: expected {} bytes, got {}",
            layout.puff_size,
            puffed.len()
        )));
    }

    let mut output = Vec::with_capacity(layout.deflate_stream_size as usize);
    let mut input_index = 0usize;
    let mut current = 0usize;
    let mut puff_pos = 0u64;
    let mut skip_bytes = 0u64;
    let mut deflate_bit_pos = 0u64;
    let mut last_byte = 0u8;
    let mut extra_byte = extra_byte_for(layout, current);
    let mut puff_buffer = Vec::new();
    let mut huffer = Huffer::new();

    while input_index < puffed.len() {
        let current_deflate = layout.deflates[current];
        let current_puff = layout.puffs[current];

        if deflate_bit_pos < (current_deflate.offset & !7u64) {
            let copy_len = ((current_deflate.offset / 8) - (deflate_bit_pos / 8))
                .min((puffed.len() - input_index) as u64) as usize;
            if copy_len == 0 {
                return Err(tool_error("Failed to advance raw segment while huffing"));
            }
            output.extend_from_slice(&puffed[input_index..input_index + copy_len]);
            input_index += copy_len;
            puff_pos += copy_len as u64;
            deflate_bit_pos += (copy_len as u64) * 8;
            continue;
        }

        if deflate_bit_pos < current_deflate.offset {
            last_byte |= puffed[input_index] << ((deflate_bit_pos & 7) as u8);
            input_index += 1;
            skip_bytes = 0;
            deflate_bit_pos = current_deflate.offset;
            puff_pos += 1;
            if puff_pos != current_puff.offset {
                return Err(tool_error("Puff stream and deflate stream cursor desynced"));
            }
        }

        let needed =
            (current_puff.length + u64::from(extra_byte)).saturating_sub(skip_bytes) as usize;
        let copy_len = needed.min(puffed.len() - input_index);
        if skip_bytes == 0 {
            puff_buffer.clear();
        }
        puff_buffer.extend_from_slice(&puffed[input_index..input_index + copy_len]);
        skip_bytes += copy_len as u64;
        input_index += copy_len;

        if skip_bytes == current_puff.length + u64::from(extra_byte) {
            let mut deflated = huffer.huff_deflate(
                &puff_buffer[..current_puff.length as usize],
                (current_deflate.offset & 7) as usize,
                last_byte,
            )?;
            let expected_len = ((current_deflate.offset + current_deflate.length + 7) / 8)
                - (current_deflate.offset / 8);
            if deflated.len() != expected_len as usize {
                return Err(tool_error(format!(
                    "Huffed stream size mismatch: expected {} bytes, got {}",
                    expected_len,
                    deflated.len()
                )));
            }

            deflate_bit_pos = current_deflate.offset + current_deflate.length;
            if extra_byte == 1 {
                let last = deflated
                    .last_mut()
                    .ok_or_else(|| tool_error("Missing final byte for huffed segment"))?;
                *last |= puff_buffer[current_puff.length as usize] << ((deflate_bit_pos & 7) as u8);
                deflate_bit_pos = (deflate_bit_pos + 7) & !7u64;
                last_byte = 0;
            } else if (deflate_bit_pos & 7) != 0 {
                last_byte = *deflated
                    .last()
                    .ok_or_else(|| tool_error("Missing cached final byte for huffed segment"))?;
                deflated.pop();
            } else {
                last_byte = 0;
            }

            output.extend_from_slice(&deflated);
            puff_pos += skip_bytes;
            skip_bytes = 0;
            current += 1;
            extra_byte = extra_byte_for(layout, current);
        }
    }

    if output.len() != layout.deflate_stream_size as usize {
        return Err(tool_error(format!(
            "Huffed output size mismatch: expected {} bytes, got {}",
            layout.deflate_stream_size,
            output.len()
        )));
    }
    Ok(output)
}

fn apply_raw_patch(source: &[u8], patch: &[u8]) -> Result<Vec<u8>> {
    let mut patched = Vec::new();
    if patch.starts_with(b"BSDF2") {
        bsdiff_android::patch_bsdf2(source, patch, &mut patched)
            .map_err(|e| tool_error(format!("PUFFDIFF BSDF2 patch failed: {e}")))?;
    } else {
        let mut cursor = Cursor::new(patch);
        bsdiff_android::patch(source, &mut cursor, &mut patched)
            .map_err(|e| tool_error(format!("PUFFDIFF BSDIFF patch failed: {e}")))?;
    }
    Ok(patched)
}

pub fn apply_puffpatch_bytes(source: &[u8], patch: &[u8]) -> Result<Vec<u8>> {
    let parsed = parse_patch(patch)?;
    if parsed.patch_type != PatchType::Bsdiff {
        return Err(DynoError::UnsupportedOperation(format!(
            "Puff patch type {:?} is not supported in pure Rust",
            parsed.patch_type
        )));
    }

    let puffed_source = puff_stream(source, &parsed.src)?;
    let patched_puff = apply_raw_patch(&puffed_source, &patch[parsed.raw_patch_offset..])?;
    if patched_puff.len() != parsed.dst.puff_size as usize {
        return Err(tool_error(format!(
            "Patched puff size mismatch: expected {} bytes, got {}",
            parsed.dst.puff_size,
            patched_puff.len()
        )));
    }
    huff_stream(&patched_puff, &parsed.dst)
}

pub fn apply_puffpatch<R: Read, W: Write>(
    source: &mut R,
    patch: &[u8],
    dest: &mut W,
) -> Result<()> {
    let mut source_bytes = Vec::new();
    source.read_to_end(&mut source_bytes)?;
    let patched = apply_puffpatch_bytes(&source_bytes, patch)?;
    dest.write_all(&patched)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        BitExtent, ByteExtent, apply_puffpatch_bytes, build_stream_layout, huff_stream, puff_stream,
    };

    const DEFLATES_SAMPLE1: &[u8] = &[
        0x11, 0x22, 0x63, 0x64, 0x62, 0x66, 0x61, 0x05, 0x00, 0x33, 0x03, 0x00, 0x63, 0x04, 0x00,
        0x44, 0x55,
    ];
    const PUFFS_SAMPLE1: &[u8] = &[
        0x11, 0x22, 0x00, 0x00, 0xA0, 0x04, 0x01, 0x02, 0x03, 0x04, 0x05, 0xFF, 0x81, 0x00, 0x33,
        0x00, 0x00, 0xA0, 0xFF, 0x81, 0x00, 0x00, 0x00, 0xA0, 0x00, 0x01, 0xFF, 0x81, 0x00, 0x44,
        0x55,
    ];
    const DEFLATES_SAMPLE2: &[u8] = &[
        0x63, 0x64, 0x62, 0x66, 0x61, 0x05, 0x00, 0x33, 0x66, 0x01, 0x05, 0x00, 0xFA, 0xFF, 0x01,
        0x02, 0x03, 0x04, 0x05, 0x63, 0x04, 0x00,
    ];
    const PATCH_1_TO_2: &[u8] = &[
        0x50, 0x55, 0x46, 0x31, 0x00, 0x00, 0x00, 0x51, 0x08, 0x01, 0x12, 0x27, 0x0A, 0x04, 0x08,
        0x10, 0x10, 0x32, 0x0A, 0x04, 0x08, 0x50, 0x10, 0x0A, 0x0A, 0x04, 0x08, 0x60, 0x10, 0x12,
        0x12, 0x04, 0x08, 0x10, 0x10, 0x58, 0x12, 0x04, 0x08, 0x78, 0x10, 0x28, 0x12, 0x05, 0x08,
        0xA8, 0x01, 0x10, 0x38, 0x18, 0x1F, 0x1A, 0x24, 0x0A, 0x02, 0x10, 0x32, 0x0A, 0x04, 0x08,
        0x48, 0x10, 0x50, 0x0A, 0x05, 0x08, 0x98, 0x01, 0x10, 0x12, 0x12, 0x02, 0x10, 0x58, 0x12,
        0x04, 0x08, 0x70, 0x10, 0x58, 0x12, 0x05, 0x08, 0xC8, 0x01, 0x10, 0x38, 0x18, 0x21, 0x42,
        0x53, 0x44, 0x46, 0x32, 0x01, 0x01, 0x01, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x42, 0x5A, 0x68, 0x39, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59, 0xD1, 0x20, 0xBB, 0x7E,
        0x00, 0x00, 0x03, 0x60, 0x40, 0x78, 0x0E, 0x08, 0x00, 0x40, 0x00, 0x20, 0x00, 0x31, 0x06,
        0x4C, 0x40, 0x92, 0x8F, 0x46, 0xA7, 0xA8, 0xE0, 0xF3, 0xD6, 0x21, 0x12, 0xF4, 0xBC, 0x43,
        0x32, 0x1F, 0x17, 0x72, 0x45, 0x38, 0x50, 0x90, 0xD1, 0x20, 0xBB, 0x7E, 0x42, 0x5A, 0x68,
        0x39, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59, 0xF1, 0x20, 0x5F, 0x0D, 0x00, 0x00, 0x02, 0x41,
        0x15, 0x42, 0x08, 0x20, 0x00, 0x40, 0x00, 0x00, 0x02, 0x40, 0x00, 0x20, 0x00, 0x22, 0x3D,
        0x23, 0x10, 0x86, 0x03, 0x96, 0x54, 0x11, 0x16, 0x5F, 0x17, 0x72, 0x45, 0x38, 0x50, 0x90,
        0xF1, 0x20, 0x5F, 0x0D, 0x42, 0x5A, 0x68, 0x39, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59, 0x07,
        0xD4, 0xCB, 0x6E, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x20, 0x00, 0x21, 0x18, 0x46,
        0x82, 0xEE, 0x48, 0xA7, 0x0A, 0x12, 0x00, 0xFA, 0x99, 0x6D, 0xC0,
    ];

    fn sample1_layout() -> super::StreamLayout {
        build_stream_layout(
            PUFFS_SAMPLE1.len() as u64,
            vec![
                BitExtent {
                    offset: 16,
                    length: 50,
                },
                BitExtent {
                    offset: 80,
                    length: 10,
                },
                BitExtent {
                    offset: 96,
                    length: 18,
                },
            ],
            vec![
                ByteExtent {
                    offset: 2,
                    length: 11,
                },
                ByteExtent {
                    offset: 15,
                    length: 5,
                },
                ByteExtent {
                    offset: 21,
                    length: 7,
                },
            ],
        )
        .unwrap()
    }

    #[test]
    fn puff_and_huff_match_upstream_vectors() {
        let layout = sample1_layout();
        assert_eq!(
            puff_stream(DEFLATES_SAMPLE1, &layout).unwrap(),
            PUFFS_SAMPLE1
        );
        assert_eq!(
            huff_stream(PUFFS_SAMPLE1, &layout).unwrap(),
            DEFLATES_SAMPLE1
        );
    }

    #[test]
    fn apply_puffpatch_matches_upstream_vector() {
        assert_eq!(
            apply_puffpatch_bytes(DEFLATES_SAMPLE1, PATCH_1_TO_2).unwrap(),
            DEFLATES_SAMPLE2
        );
    }
}
