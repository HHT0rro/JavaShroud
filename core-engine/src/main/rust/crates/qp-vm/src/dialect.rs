use crate::crypto::hmac_bytes;
use crate::VmError;

const TABLE_SIZE: usize = 65536;
const UNMAPPED: u16 = 0xFFFF;

const STREAM_LEN: usize = 4096;

/// The per-build semantic opcode corpus. The VM semantic instruction set is
/// supplied by the artifact specialization build (stored there only as
/// XOR-masked shard groups), so no fixed corpus table exists in the compiled
/// artifact and no two builds embed the same plain table.
#[derive(Clone)]
pub struct VmDialectCorpus {
    semantic_opcodes: Vec<u16>,
}

impl VmDialectCorpus {
    pub fn from_opcodes(semantic_opcodes: &[u16]) -> Result<Self, VmError> {
        if semantic_opcodes.is_empty() || semantic_opcodes.len() > TABLE_SIZE {
            return Err(VmError::InvalidHeader("vm dialect corpus"));
        }
        let mut seen = [false; TABLE_SIZE];
        for opcode in semantic_opcodes {
            if seen[*opcode as usize] {
                return Err(VmError::InvalidHeader("vm dialect corpus duplicate"));
            }
            seen[*opcode as usize] = true;
        }
        Ok(Self {
            semantic_opcodes: semantic_opcodes.to_vec(),
        })
    }
}

impl std::fmt::Debug for VmDialectCorpus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VmDialectCorpus")
            .field("opcodes", &self.semantic_opcodes.len())
            .finish()
    }
}

impl Drop for VmDialectCorpus {
    fn drop(&mut self) {
        self.semantic_opcodes.fill(0);
        self.semantic_opcodes.clear();
    }
}

pub struct VmDialect {
    encode: Box<[u16]>,
    decode: Box<[u16]>,
    pub commitment: [u8; 32],
    #[allow(dead_code)]
    pub dispatch_family: u8,
    pub fused_semantic: u16,
    pub fused_opcode: u16,
}

fn expand_stream(crypto_domain_material: &[u8; 32], layout_digest: &[u8; 32]) -> Vec<u8> {
    let mut output = Vec::with_capacity(STREAM_LEN);
    let mut counter = 1u8;
    while output.len() < STREAM_LEN {
        let mut block = hmac_bytes(
            crypto_domain_material,
            &[
                &crate::crypto::DIALECT_DOMAIN_LABEL,
                layout_digest,
                &[counter],
            ],
        );
        let take = (STREAM_LEN - output.len()).min(block.len());
        output.extend_from_slice(&block[..take]);
        block.fill(0);
        counter = counter.wrapping_add(1);
    }
    output
}

impl VmDialect {
    /// Derives the per-artifact dialect. The corpus is mandatory: a build
    /// without a specialization-supplied corpus fails closed instead of
    /// falling back to a fixed instruction-set table.
    pub fn from_material(
        crypto_domain_material: &[u8; 32],
        layout_digest: &[u8; 32],
        corpus: &VmDialectCorpus,
    ) -> Result<Self, VmError> {
        let mut stream = expand_stream(crypto_domain_material, layout_digest);
        let dialect = Self::from_stream(&stream, corpus);
        stream.fill(0);
        Ok(dialect)
    }

    fn from_stream(stream: &[u8], corpus: &VmDialectCorpus) -> Self {
        // The fused superoperator semantic id is itself stream-derived, so no
        // fixed fused anchor exists in the artifact.
        let fused_semantic = 0x100 | u16::from(stream[0] & 0x7F);
        let mut live = corpus.semantic_opcodes.clone();
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
        for (index, semantic) in corpus.semantic_opcodes.iter().copied().enumerate() {
            let encoded = live[index];
            encode[semantic as usize] = encoded;
            decode[encoded as usize] = semantic;
        }
        encode[fused_semantic as usize] = fused_semantic;
        decode[fused_semantic as usize] = fused_semantic;
        let mut commit_input =
            Vec::with_capacity(crate::crypto::DIALECT_DOMAIN_LABEL.len() + live.len() * 2 + 4);
        commit_input.extend_from_slice(&crate::crypto::DIALECT_DOMAIN_LABEL);
        for opcode in &live {
            commit_input.extend_from_slice(&opcode.to_be_bytes());
        }
        commit_input.extend_from_slice(&fused_semantic.to_be_bytes());
        commit_input.push(stream[32]);
        commit_input.push(stream[33] & 3);
        let commitment = crate::crypto::sha256_bytes(&commit_input);
        commit_input.fill(0);
        live.fill(0);
        Self {
            encode: encode.into_boxed_slice(),
            decode: decode.into_boxed_slice(),
            commitment,
            dispatch_family: stream[33] & 3,
            fused_semantic,
            fused_opcode: fused_semantic,
        }
    }

    pub fn encode(&self, semantic: u16) -> u16 {
        self.encode[semantic as usize]
    }

    pub fn decode(&self, encoded: u16) -> u16 {
        self.decode[encoded as usize]
    }
}

impl Drop for VmDialect {
    fn drop(&mut self) {
        self.encode.fill(0);
        self.decode.fill(0);
        self.commitment.fill(0);
        self.dispatch_family = 0;
        self.fused_semantic = 0;
        self.fused_opcode = 0;
    }
}
