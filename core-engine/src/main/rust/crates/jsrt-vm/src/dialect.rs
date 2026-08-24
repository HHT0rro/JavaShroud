use crate::crypto::hmac_bytes;
use crate::VmError;

const TABLE_SIZE: usize = 65536;
const UNMAPPED: u16 = 0xFFFF;
const DOMAIN: &[u8] = b"javashroud-aken-r1-vm-dialect-v1";
const STREAM_LEN: usize = 4096;
const FUSED_IADD_DUP: u16 = 0x01F0;

const LIVE_OPCODES: &[u16] = &[
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55,
    0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f, 0x60, 0x61, 0x62, 0x63, 0x64,
    0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75,
    0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0xf2, 0xf3, 0xf6, 0xf7,
    0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
];

pub struct VmDialect {
    encode: Box<[u16]>,
    decode: Box<[u16]>,
    pub commitment: [u8; 32],
    #[allow(dead_code)]
    pub dispatch_family: u8,
    pub fused_opcode: u16,
}

fn expand_stream(crypto_domain_material: &[u8; 32], layout_digest: &[u8; 32]) -> Vec<u8> {
    let mut output = Vec::with_capacity(STREAM_LEN);
    let mut counter = 1u8;
    while output.len() < STREAM_LEN {
        let mut block = hmac_bytes(crypto_domain_material, &[DOMAIN, layout_digest, &[counter]]);
        let take = (STREAM_LEN - output.len()).min(block.len());
        output.extend_from_slice(&block[..take]);
        block.fill(0);
        counter = counter.wrapping_add(1);
    }
    output
}

impl VmDialect {
    pub fn from_material(
        crypto_domain_material: &[u8; 32],
        layout_digest: &[u8; 32],
    ) -> Result<Self, VmError> {
        let mut stream = expand_stream(crypto_domain_material, layout_digest);
        let dialect = Self::from_stream(&stream);
        stream.fill(0);
        Ok(dialect)
    }

    fn from_stream(stream: &[u8]) -> Self {
        let mut live = LIVE_OPCODES.to_vec();
        let mut offset = 0usize;
        let modulus = stream.len().saturating_sub(1).max(1);
        for i in (1..live.len()).rev() {
            let take = ((stream[offset] as u16) << 8) | (stream[offset + 1] as u16);
            offset = (offset + 2) % modulus;
            let j = (take as usize) % (i + 1);
            live.swap(i, j);
        }
        let mut encode = vec![UNMAPPED; TABLE_SIZE];
        let mut decode = vec![UNMAPPED; TABLE_SIZE];
        for (index, semantic) in LIVE_OPCODES.iter().copied().enumerate() {
            let encoded = live[index];
            encode[semantic as usize] = encoded;
            decode[encoded as usize] = semantic;
        }
        let fused = FUSED_IADD_DUP ^ u16::from(stream[0] & 0x7F) | 0x100;
        encode[FUSED_IADD_DUP as usize] = fused;
        decode[fused as usize] = FUSED_IADD_DUP;
        let mut commit_input = Vec::with_capacity(DOMAIN.len() + live.len() * 2 + 2);
        commit_input.extend_from_slice(DOMAIN);
        for opcode in &live {
            commit_input.extend_from_slice(&opcode.to_be_bytes());
        }
        commit_input.push(stream[32]);
        commit_input.push(stream[33] & 3);
        let commitment = crate::crypto::sha256_bytes(&commit_input);
        commit_input.fill(0);
        Self {
            encode: encode.into_boxed_slice(),
            decode: decode.into_boxed_slice(),
            commitment,
            dispatch_family: stream[33] & 3,
            fused_opcode: fused,
        }
    }

    pub fn encode(&self, semantic: u16) -> u16 {
        let mapped = self.encode[semantic as usize];
        if mapped == UNMAPPED {
            semantic
        } else {
            mapped
        }
    }

    pub fn decode(&self, encoded: u16) -> u16 {
        let mapped = self.decode[encoded as usize];
        if mapped == UNMAPPED {
            encoded
        } else {
            mapped
        }
    }
}
