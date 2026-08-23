#![allow(dead_code)]

const MAGIC: [u8; 4] = [0x28, 0xb5, 0x2f, 0xfd];
const MAX_BLOCK_SIZE: usize = 128 * 1024;
const BLOCK_LAST: u32 = 1;
const BLOCK_RAW: u32 = 0;
const BLOCK_RLE: u32 = 1;

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum ZstdError {
    Truncated,
    InvalidMagic,
    InvalidFrameHeader,
    ContentSizeMismatch,
    InvalidBlockType,
    BlockTooLarge,
    OutputTooLarge,
    TrailingBytes,
}

struct WipedVec(Vec<u8>);

impl WipedVec {
    fn new(capacity: usize) -> Self {
        Self(Vec::with_capacity(capacity))
    }

    fn push_bytes(&mut self, bytes: &[u8]) {
        self.0.extend_from_slice(bytes);
    }

    fn push_repeat(&mut self, value: u8, count: usize) {
        self.0.resize(self.0.len() + count, value);
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn into_inner(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

impl Drop for WipedVec {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

pub(crate) fn decompress(
    bytes: &[u8],
    expected_length: usize,
    maximum_length: usize,
) -> Result<Vec<u8>, ZstdError> {
    if expected_length > maximum_length || bytes.len() < 7 {
        return Err(ZstdError::OutputTooLarge);
    }
    if bytes[..4] != MAGIC {
        return Err(ZstdError::InvalidMagic);
    }
    let descriptor = bytes[4];
    if descriptor & 0x08 != 0 || descriptor & 0x03 != 0 {
        return Err(ZstdError::InvalidFrameHeader);
    }
    let single_segment = descriptor & 0x20 != 0;
    if !single_segment {
        return Err(ZstdError::InvalidFrameHeader);
    }
    let content_size_flag = descriptor >> 6;
    let content_size_length = match content_size_flag {
        0 => 1,
        1 => 2,
        2 => 4,
        _ => 8,
    };
    let content_start = 5usize;
    let content_end = content_start
        .checked_add(content_size_length)
        .ok_or(ZstdError::Truncated)?;
    if content_end > bytes.len() {
        return Err(ZstdError::Truncated);
    }
    let declared = match content_size_length {
        1 => u64::from(bytes[content_start]),
        2 => {
            u64::from(u16::from_le_bytes([
                bytes[content_start],
                bytes[content_start + 1],
            ])) + 256
        }
        4 => u64::from(u32::from_le_bytes([
            bytes[content_start],
            bytes[content_start + 1],
            bytes[content_start + 2],
            bytes[content_start + 3],
        ])),
        8 => u64::from_le_bytes([
            bytes[content_start],
            bytes[content_start + 1],
            bytes[content_start + 2],
            bytes[content_start + 3],
            bytes[content_start + 4],
            bytes[content_start + 5],
            bytes[content_start + 6],
            bytes[content_start + 7],
        ]),
        _ => return Err(ZstdError::InvalidFrameHeader),
    };
    if declared != expected_length as u64 {
        return Err(ZstdError::ContentSizeMismatch);
    }

    let checksum = descriptor & 0x04 != 0;
    let mut offset = content_end;
    let mut output = WipedVec::new(expected_length);
    let mut last = false;
    let max_blocks = expected_length
        .checked_div(MAX_BLOCK_SIZE)
        .and_then(|value| value.checked_add(2))
        .unwrap_or(usize::MAX);
    let mut blocks = 0usize;
    while !last {
        blocks = blocks.checked_add(1).ok_or(ZstdError::OutputTooLarge)?;
        if blocks > max_blocks || offset.checked_add(3).ok_or(ZstdError::Truncated)? > bytes.len() {
            return Err(ZstdError::Truncated);
        }
        let header = u32::from(bytes[offset])
            | (u32::from(bytes[offset + 1]) << 8)
            | (u32::from(bytes[offset + 2]) << 16);
        offset += 3;
        last = header & BLOCK_LAST != 0;
        let block_type = (header >> 1) & 0x03;
        let block_size = (header >> 3) as usize;
        if block_size > MAX_BLOCK_SIZE {
            return Err(ZstdError::BlockTooLarge);
        }
        match block_type {
            BLOCK_RAW => {
                let end = offset.checked_add(block_size).ok_or(ZstdError::Truncated)?;
                if end > bytes.len() {
                    return Err(ZstdError::Truncated);
                }
                output.push_bytes(&bytes[offset..end]);
                offset = end;
            }
            BLOCK_RLE => {
                if offset >= bytes.len() {
                    return Err(ZstdError::Truncated);
                }
                output.push_repeat(bytes[offset], block_size);
                offset += 1;
            }
            _ => return Err(ZstdError::InvalidBlockType),
        }
        if output.len() > expected_length {
            return Err(ZstdError::OutputTooLarge);
        }
    }
    if checksum {
        let end = offset.checked_add(4).ok_or(ZstdError::Truncated)?;
        if end > bytes.len() {
            return Err(ZstdError::Truncated);
        }
        offset = end;
    }
    if offset != bytes.len() {
        return Err(ZstdError::TrailingBytes);
    }
    if output.len() != expected_length {
        return Err(ZstdError::ContentSizeMismatch);
    }
    Ok(output.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(bytes: &[u8], block_type: u32, last: bool, value: u8) -> Vec<u8> {
        let mut output = vec![0x28, 0xb5, 0x2f, 0xfd, 0x20, bytes.len() as u8];
        let header = (if last { 1 } else { 0 }) | (block_type << 1) | ((bytes.len() as u32) << 3);
        output.extend_from_slice(&header.to_le_bytes()[..3]);
        if block_type == BLOCK_RAW {
            output.extend_from_slice(bytes);
        } else {
            output.push(value);
        }
        output
    }

    #[test]
    fn raw_and_rle_frames_are_bounded() {
        let raw = frame(b"raw", BLOCK_RAW, true, 0);
        assert_eq!(decompress(&raw, 3, 32).expect("raw"), b"raw");
        let rle = frame(&[0; 7], BLOCK_RLE, true, b'x');
        assert_eq!(decompress(&rle, 7, 32).expect("rle"), vec![b'x'; 7]);
    }

    #[test]
    fn malformed_or_trailing_frames_fail() {
        let mut raw = frame(b"raw", BLOCK_RAW, true, 0);
        raw.pop();
        assert_eq!(decompress(&raw, 3, 32), Err(ZstdError::Truncated));
        let mut trailing = frame(b"raw", BLOCK_RAW, true, 0);
        trailing.push(0);
        assert_eq!(decompress(&trailing, 3, 32), Err(ZstdError::TrailingBytes));
        let compressed = frame(b"raw", 2, true, 0);
        assert_eq!(
            decompress(&compressed, 3, 32),
            Err(ZstdError::InvalidBlockType)
        );
    }
}
