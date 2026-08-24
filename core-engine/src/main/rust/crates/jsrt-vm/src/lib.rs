#![forbid(unsafe_code)]
#![allow(clippy::too_many_arguments)]

mod crypto;
mod dialect;
pub mod executor;
mod zstd;

pub use executor::{
    ExecutionLimits, InvokeKind, ObjectOperations, VmExecutor, VmHostError,
    VmValue,
};

pub mod opcode {
    pub const NOP: u16 = 0x00;
    pub const ACONST_NULL: u16 = 0x01;
    pub const ICONST: u16 = 0x02;
    pub const LCONST: u16 = 0x03;
    pub const FCONST: u16 = 0x04;
    pub const DCONST: u16 = 0x05;
    pub const BIPUSH: u16 = 0x06;
    pub const SIPUSH: u16 = 0x07;
    pub const LDC_INT: u16 = 0x08;
    pub const LDC_LONG: u16 = 0x09;
    pub const LDC_FLOAT: u16 = 0x0a;
    pub const LDC_DOUBLE: u16 = 0x0b;
    pub const LDC_STRING: u16 = 0x0c;
    pub const LDC_TYPE: u16 = 0x0d;
    pub const LDC_HANDLE: u16 = 0x0e;
    pub const ILOAD: u16 = 0x10;
    pub const LLOAD: u16 = 0x11;
    pub const FLOAD: u16 = 0x12;
    pub const DLOAD: u16 = 0x13;
    pub const ALOAD: u16 = 0x14;
    pub const ISTORE: u16 = 0x20;
    pub const LSTORE: u16 = 0x21;
    pub const FSTORE: u16 = 0x22;
    pub const DSTORE: u16 = 0x23;
    pub const ASTORE: u16 = 0x24;
    pub const IINC: u16 = 0x25;
    pub const RET: u16 = 0x26;
    pub const POP: u16 = 0x30;
    pub const POP2: u16 = 0x31;
    pub const DUP: u16 = 0x32;
    pub const DUP_X1: u16 = 0x33;
    pub const DUP_X2: u16 = 0x34;
    pub const DUP2: u16 = 0x35;
    pub const SWAP: u16 = 0x36;
    pub const DUP2_X1: u16 = 0xf6;
    pub const DUP2_X2: u16 = 0xf7;
    pub const IADD: u16 = 0x40;
    pub const LADD: u16 = 0x41;
    pub const FADD: u16 = 0x42;
    pub const DADD: u16 = 0x43;
    pub const ISUB: u16 = 0x44;
    pub const LSUB: u16 = 0x45;
    pub const FSUB: u16 = 0x46;
    pub const DSUB: u16 = 0x47;
    pub const IMUL: u16 = 0x48;
    pub const LMUL: u16 = 0x49;
    pub const FMUL: u16 = 0x4a;
    pub const DMUL: u16 = 0x4b;
    pub const IDIV: u16 = 0x4c;
    pub const LDIV: u16 = 0x4d;
    pub const FDIV: u16 = 0x4e;
    pub const DDIV: u16 = 0x4f;
    pub const IREM: u16 = 0x50;
    pub const LREM: u16 = 0x51;
    pub const FREM: u16 = 0xf2;
    pub const DREM: u16 = 0xf3;
    pub const INEG: u16 = 0x52;
    pub const LNEG: u16 = 0x53;
    pub const FNEG: u16 = 0x54;
    pub const DNEG: u16 = 0x55;
    pub const ISHL: u16 = 0x56;
    pub const ISHR: u16 = 0x57;
    pub const IUSHR: u16 = 0x58;
    pub const LSHL: u16 = 0x59;
    pub const LSHR: u16 = 0x5a;
    pub const LUSHR: u16 = 0x5b;
    pub const IAND: u16 = 0x5c;
    pub const LAND: u16 = 0x5d;
    pub const IOR: u16 = 0x5e;
    pub const LOR: u16 = 0x5f;
    pub const LCMP: u16 = 0x60;
    pub const FCMPL: u16 = 0x61;
    pub const FCMPG: u16 = 0x62;
    pub const DCMPL: u16 = 0x63;
    pub const DCMPG: u16 = 0x64;
    pub const IXOR: u16 = 0x68;
    pub const LXOR: u16 = 0x69;
    pub const I2L: u16 = 0x6a;
    pub const I2F: u16 = 0x6b;
    pub const I2D: u16 = 0x6c;
    pub const L2I: u16 = 0x6d;
    pub const L2F: u16 = 0x6e;
    pub const L2D: u16 = 0x6f;
    pub const IFEQ: u16 = 0x70;
    pub const IFNE: u16 = 0x71;
    pub const IFLT: u16 = 0x72;
    pub const IFGE: u16 = 0x73;
    pub const IFGT: u16 = 0x74;
    pub const IFLE: u16 = 0x75;
    pub const IF_ICMPEQ: u16 = 0x76;
    pub const IF_ICMPNE: u16 = 0x77;
    pub const IF_ICMPLT: u16 = 0x78;
    pub const IF_ICMPGE: u16 = 0x79;
    pub const IF_ICMPGT: u16 = 0x7a;
    pub const IF_ICMPLE: u16 = 0x7b;
    pub const IF_ACMPEQ: u16 = 0x7c;
    pub const IF_ACMPNE: u16 = 0x7d;
    pub const GOTO: u16 = 0x7e;
    pub const JSR: u16 = 0x7f;
    pub const IFNULL: u16 = 0x80;
    pub const IFNONNULL: u16 = 0x81;
    pub const IRETURN: u16 = 0x90;
    pub const LRETURN: u16 = 0x91;
    pub const FRETURN: u16 = 0x92;
    pub const DRETURN: u16 = 0x93;
    pub const ARETURN: u16 = 0x94;
    pub const RETURN: u16 = 0x95;
    pub const ATHROW: u16 = 0x96;
    pub const GETSTATIC: u16 = 0xa0;
    pub const PUTSTATIC: u16 = 0xa1;
    pub const GETFIELD: u16 = 0xa2;
    pub const PUTFIELD: u16 = 0xa3;
    pub const INVOKEVIRTUAL: u16 = 0xb0;
    pub const INVOKESPECIAL: u16 = 0xb1;
    pub const INVOKESTATIC: u16 = 0xb2;
    pub const INVOKEINTERFACE: u16 = 0xb3;
    pub const INVOKEDYNAMIC: u16 = 0xb4;
    pub const NEW: u16 = 0xc0;
    pub const NEWARRAY: u16 = 0xc1;
    pub const ANEWARRAY: u16 = 0xc2;
    pub const ARRAYLENGTH: u16 = 0xc3;
    pub const CHECKCAST: u16 = 0xc4;
    pub const INSTANCEOF: u16 = 0xc5;
    pub const MULTIANEWARRAY: u16 = 0xc6;
    pub const F2I: u16 = 0x88;
    pub const F2L: u16 = 0x89;
    pub const F2D: u16 = 0x8a;
    pub const D2I: u16 = 0x8b;
    pub const D2L: u16 = 0x8c;
    pub const D2F: u16 = 0x8d;
    pub const I2B: u16 = 0x8e;
    pub const I2C: u16 = 0x8f;
    pub const I2S: u16 = 0x9a;
    pub const IALOAD: u16 = 0xd0;
    pub const LALOAD: u16 = 0xd1;
    pub const FALOAD: u16 = 0xd2;
    pub const DALOAD: u16 = 0xd3;
    pub const AALOAD: u16 = 0xd4;
    pub const BALOAD: u16 = 0xd5;
    pub const CALOAD: u16 = 0xd6;
    pub const SALOAD: u16 = 0xd7;
    pub const IASTORE: u16 = 0xd8;
    pub const LASTORE: u16 = 0xd9;
    pub const FASTORE: u16 = 0xda;
    pub const DASTORE: u16 = 0xdb;
    pub const AASTORE: u16 = 0xdc;
    pub const BASTORE: u16 = 0xdd;
    pub const CASTORE: u16 = 0xde;
    pub const SASTORE: u16 = 0xdf;
    pub const MONITORENTER: u16 = 0xe0;
    pub const MONITOREXIT: u16 = 0xe1;
    pub const TABLESWITCH: u16 = 0xf0;
    pub const LOOKUPSWITCH: u16 = 0xf1;
    pub const MAXS: u16 = 0xfe;
    pub const UNSUPPORTED: u16 = 0xff;
    pub const LDC_CONDY: u16 = 0xfc;

    pub const REG_OPERAND_CONT: u16 = 0xfc;
    pub const REG_META: u16 = 0xfd;
    pub const REG_SEMANTIC_SHARE: u16 = 0xf7;
    pub const SUPER_CONST: u16 = 0xf8;
    pub const SUPER_INT_ARITH: u16 = 0xf9;
    pub const SUPER_CMP_BRANCH: u16 = 0xfa;
    pub const SUPER_INVOKE: u16 = 0xfb;
}

use crypto::{
    aes128_ctr, ct_eq, vbc4_aes_material, vbc4_hmac, vbc4_hmac_fields, vbc4_session_material,
    vm_build_key,
};
use opcode::*;
use std::fmt;
use std::ops::Range;

pub const VBC4_MAGIC: [u8; 4] = *b"VBC4";
pub const VBC4_AUTH_TAG_SIZE: usize = 32;
pub const VBC4_DIALECT_COMMITMENT_SIZE: usize = 32;
pub const VBC4_HEADER_SIZE: usize =
    4 + 16 + VBC4_DIALECT_COMMITMENT_SIZE + 4 + 16 + 2 + 2 + 4 + 4;
pub const VBC4_MAX_BLOCKS: usize = 12;
pub const VBC4_MAX_FRAME_SIZE: usize = 32 * 1024 * 1024;
pub const VBC4_MAX_SECTION_SIZE: usize = 16 * 1024 * 1024;
pub const VBC4_MAX_CONSTANTS: usize = 65_535;
pub const VBC4_MAX_ROWS_PER_BLOCK: usize = 65_535;
pub const VBC4_MAX_INSTRUCTIONS: usize = 65_535;
pub const VBC4_MAX_OPERANDS_PER_INSTRUCTION: usize = 256;
pub const VBC4_MAX_EXCEPTIONS: usize = 4_096;
pub const VBC4_MAX_STATE_BINDING: usize = 4 * 1024;
pub const VBC4_MAX_METADATA_SIZE: usize = 16 * 1024;

const FLAG_ENCRYPTED_CP: u16 = 0x0001;
const FLAG_BLOCK_ENCRYPTED: u16 = 0x0002;
const FLAG_MAC: u16 = 0x0004;
const FLAG_STATE_BOUND: u16 = 0x0008;
const FLAG_PER_BLOCK_ENCRYPT: u16 = 0x0010;
const FLAG_AUTHENTICATED: u16 = 0x0020;
const FLAG_PER_ENTRY_CP: u16 = 0x0040;
const FLAG_PADDED: u16 = 0x0080;
const FLAG_REGISTER_EXECUTABLE: u16 = 0x0100;
const FLAG_SUPER_OPERATORS: u16 = 0x0200;
const FLAG_ZSTD_SECTIONS: u16 = 0x0400;
const FLAG_BLOCK_DISPATCH: u16 = 0x0800;
const FLAG_NESTED_VM: u16 = 0x1000;
const FLAG_POLYMORPHIC_CP: u16 = 0x2000;
const FLAG_REGISTER_ROW_ENVELOPE: u16 = 0x4000;
const FLAG_MIXED_OPERAND_ENVELOPE: u16 = 0x8000;
const REQUIRED_FLAGS: u16 = FLAG_ENCRYPTED_CP
    | FLAG_BLOCK_ENCRYPTED
    | FLAG_MAC
    | FLAG_STATE_BOUND
    | FLAG_PER_BLOCK_ENCRYPT
    | FLAG_AUTHENTICATED
    | FLAG_PER_ENTRY_CP
    | FLAG_PADDED
    | FLAG_REGISTER_EXECUTABLE
    | FLAG_SUPER_OPERATORS
    | FLAG_ZSTD_SECTIONS
    | FLAG_BLOCK_DISPATCH
    | FLAG_POLYMORPHIC_CP;
const REG_EXECUTABLE: u16 = 0x0001;
const REG_SUPER: u16 = 0x0002;
const REG_FOLDED: u16 = 0x0004;
const REG_SEMANTIC_SPLIT: u16 = 0x0008;
const REG_SEMANTIC_SHARE: u16 = 0x4000;
const REG_CONTINUATION: u16 = 0x8000;
const NESTED_MAGIC: u16 = 0x4e56;
const NESTED_FIELD_OPCODE_BASE: u16 = 0x7000;
const NESTED_COMMIT_OPCODE_BASE: u16 = 0x6000;
const NESTED_COMMIT_SLOT: usize = 0x7f;
const SECTION_CONSTANT_POOL: u32 = 1;
const SECTION_INSTRUCTIONS: u32 = 2;
const SECTION_EXCEPTIONS: u32 = 3;
const SECTION_CONSTANT_POOL_ENTRY: u32 = 9;
const CFG_MASK: u32 = 0xffff;
const CP_SEALED_STRING: u8 = 0x06;
const VBC4_CLEAN_ENTRY_INTEGRITY_HEX: &[u8] = b"10429f6c";

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum VmError {
    Truncated {
        offset: usize,
        requested: usize,
        remaining: usize,
    },
    TrailingBytes {
        remaining: usize,
    },
    FrameTooLarge {
        size: usize,
        maximum: usize,
    },
    LengthTooLarge {
        field: &'static str,
        length: usize,
        maximum: usize,
    },
    InvalidMagic,
    InvalidFlags(u16),
    InvalidHeader(&'static str),
    DialectCommitmentMismatch,
    StateBindingMismatch,
    AuthenticationFailed,
    InvalidSeed,
    InvalidKeyId,
    InvalidCompression,
    InvalidConstantPool(&'static str),
    InvalidMetadata(&'static str),
    InvalidBlock(&'static str),
    InvalidRow(&'static str),
    InvalidOpcode(u16),
    InvalidControlFlow,
    InvalidException(&'static str),
    Unsupported(&'static str),
    Crypto,
    StackUnderflow,
    StackOverflow,
    LocalOutOfBounds,
    OperandOutOfBounds,
    RecursionLimit,
    StepLimit,
    UncaughtException(String),
    HostFailure,
}

impl fmt::Display for VmError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for VmError {}

#[derive(Debug)]
pub struct VmKeyMaterial {
    crypto_domain_material: [u8; 32],
    layout_digest: [u8; 32],
}

impl VmKeyMaterial {
    pub fn new(crypto_domain_material: [u8; 32], layout_digest: [u8; 32]) -> Self {
        Self {
            crypto_domain_material,
            layout_digest,
        }
    }

    pub fn crypto_domain_material(&self) -> &[u8; 32] {
        &self.crypto_domain_material
    }

    pub fn layout_digest(&self) -> &[u8; 32] {
        &self.layout_digest
    }
}

impl Drop for VmKeyMaterial {
    fn drop(&mut self) {
        self.crypto_domain_material.fill(0);
        self.layout_digest.fill(0);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParserLimits {
    pub max_frame_size: usize,
    pub max_section_size: usize,
    pub max_constants: usize,
    pub max_blocks: usize,
    pub max_rows_per_block: usize,
    pub max_instructions: usize,
    pub max_operands_per_instruction: usize,
    pub max_exceptions: usize,
}

impl Default for ParserLimits {
    fn default() -> Self {
        Self {
            max_frame_size: VBC4_MAX_FRAME_SIZE,
            max_section_size: VBC4_MAX_SECTION_SIZE,
            max_constants: VBC4_MAX_CONSTANTS,
            max_blocks: VBC4_MAX_BLOCKS,
            max_rows_per_block: VBC4_MAX_ROWS_PER_BLOCK,
            max_instructions: VBC4_MAX_INSTRUCTIONS,
            max_operands_per_instruction: VBC4_MAX_OPERANDS_PER_INSTRUCTION,
            max_exceptions: VBC4_MAX_EXCEPTIONS,
        }
    }
}

impl ParserLimits {
    fn validate(self) -> Result<Self, VmError> {
        if self.max_frame_size > VBC4_MAX_FRAME_SIZE
            || self.max_section_size > VBC4_MAX_SECTION_SIZE
            || self.max_constants > VBC4_MAX_CONSTANTS
            || self.max_blocks > VBC4_MAX_BLOCKS
            || self.max_rows_per_block > VBC4_MAX_ROWS_PER_BLOCK
            || self.max_instructions > VBC4_MAX_INSTRUCTIONS
            || self.max_operands_per_instruction > VBC4_MAX_OPERANDS_PER_INSTRUCTION
            || self.max_exceptions > VBC4_MAX_EXCEPTIONS
        {
            return Err(VmError::InvalidHeader("parser limit exceeds the R1 bound"));
        }
        Ok(self)
    }
}

pub struct VmParser<'a> {
    material: &'a VmKeyMaterial,
    state_binding: Vec<u8>,
    limits: ParserLimits,
    dialect: dialect::VmDialect,
}

impl<'a> VmParser<'a> {
    pub fn new(material: &'a VmKeyMaterial, state_binding: &[u8]) -> Result<Self, VmError> {
        if state_binding.is_empty() {
            return Err(VmError::StateBindingMismatch);
        }
        if state_binding.len() > VBC4_MAX_STATE_BINDING {
            return Err(VmError::LengthTooLarge {
                field: "state binding",
                length: state_binding.len(),
                maximum: VBC4_MAX_STATE_BINDING,
            });
        }
        Ok(Self {
            material,
            state_binding: state_binding.to_vec(),
            limits: ParserLimits::default(),
            dialect: dialect::VmDialect::from_material(
                material.crypto_domain_material(),
                material.layout_digest(),
            )?,
        })
    }

    pub fn with_limits(mut self, limits: ParserLimits) -> Result<Self, VmError> {
        self.limits = limits.validate()?;
        Ok(self)
    }

    pub fn limits(&self) -> ParserLimits {
        self.limits
    }

    pub fn parse(&self, frame: &[u8]) -> Result<VmProgram, VmError> {
        if frame.len() > self.limits.max_frame_size {
            return Err(VmError::FrameTooLarge {
                size: frame.len(),
                maximum: self.limits.max_frame_size,
            });
        }
        if frame.len() < VBC4_HEADER_SIZE + VBC4_AUTH_TAG_SIZE {
            return Err(VmError::Truncated {
                offset: frame.len(),
                requested: 1,
                remaining: 0,
            });
        }
        let body_length = frame.len() - VBC4_AUTH_TAG_SIZE;
        let mut header = Cursor::new(&frame[..body_length]);
        if header.read_fixed::<4>()? != VBC4_MAGIC {
            return Err(VmError::InvalidMagic);
        }
        let nonce = header.read_fixed::<16>()?;
        let dialect_commitment = header.read_fixed::<VBC4_DIALECT_COMMITMENT_SIZE>()?;
        if !ct_eq(&dialect_commitment, &self.dialect.commitment) {
            return Err(VmError::DialectCommitmentMismatch);
        }
        let key_id = header.read_u32_be()?;
        let wrapped_seed = header.read_fixed::<16>()?;
        let flags = header.read_u16_be()?;
        validate_flags(flags)?;
        let block_count = usize::from(header.read_u16_be()?);
        if block_count == 0 || block_count > self.limits.max_blocks {
            return Err(VmError::LengthTooLarge {
                field: "block count",
                length: block_count,
                maximum: self.limits.max_blocks,
            });
        }
        let cp_plain_size =
            usize::try_from(header.read_u32_be()?).map_err(|_| VmError::LengthTooLarge {
                field: "constant pool",
                length: usize::MAX,
                maximum: self.limits.max_section_size,
            })?;
        let cp_encrypted_size =
            usize::try_from(header.read_u32_be()?).map_err(|_| VmError::LengthTooLarge {
                field: "constant pool",
                length: usize::MAX,
                maximum: self.limits.max_section_size,
            })?;
        if cp_plain_size == 0 || cp_plain_size > self.limits.max_section_size {
            return Err(VmError::LengthTooLarge {
                field: "constant pool plaintext",
                length: cp_plain_size,
                maximum: self.limits.max_section_size,
            });
        }
        if cp_encrypted_size == 0
            || cp_encrypted_size > self.limits.max_section_size
            || cp_encrypted_size > header.remaining()
        {
            return Err(VmError::LengthTooLarge {
                field: "constant pool ciphertext",
                length: cp_encrypted_size,
                maximum: self.limits.max_section_size,
            });
        }

        let session_material = vbc4_session_material(
            self.material.crypto_domain_material(),
            self.material.layout_digest(),
            &self.state_binding,
        );
        let result = self.parse_authenticated(
            frame,
            body_length,
            &mut header,
            nonce,
            key_id,
            wrapped_seed,
            flags,
            block_count,
            cp_plain_size,
            cp_encrypted_size,
            &session_material,
        );
        let mut session_wipe = session_material;
        session_wipe.fill(0);
        result
    }

    fn parse_authenticated(
        &self,
        frame: &[u8],
        body_length: usize,
        cursor: &mut Cursor<'_>,
        nonce: [u8; 16],
        key_id: u32,
        wrapped_seed: [u8; 16],
        flags: u16,
        block_count: usize,
        cp_plain_size: usize,
        cp_encrypted_size: usize,
        session_material: &[u8; 32],
    ) -> Result<VmProgram, VmError> {
        let seed = unwrap_seed(session_material, &nonce, &wrapped_seed, &self.state_binding)?;
        if key_id != key_id_for(session_material, seed, &nonce) {
            return Err(VmError::InvalidKeyId);
        }
        let expected_mac =
            vbc4_hmac_fields(session_material, seed, &[&nonce, &frame[..body_length]]);
        if !ct_eq(&expected_mac, &frame[body_length..]) {
            return Err(VmError::AuthenticationFailed);
        }
        let mut build_key = vm_build_key(
            self.material.crypto_domain_material(),
            self.material.layout_digest(),
        )
        .map_err(|_| VmError::Crypto)?;
        let result = self.parse_sections(
            cursor,
            nonce,
            seed,
            flags,
            block_count,
            cp_plain_size,
            cp_encrypted_size,
            session_material,
            &build_key,
        );
        build_key.fill(0);
        result
    }

    #[allow(clippy::too_many_arguments)]
    fn parse_sections(
        &self,
        cursor: &mut Cursor<'_>,
        nonce: [u8; 16],
        seed: u32,
        flags: u16,
        block_count: usize,
        _cp_plain_size: usize,
        cp_encrypted_size: usize,
        session_material: &[u8; 32],
        build_key: &[u8; 32],
    ) -> Result<VmProgram, VmError> {
        let cp_ciphertext = cursor.read_bytes(cp_encrypted_size)?.to_vec();
        let mut cp_ciphertext_wipe = cp_ciphertext;
        let (cp_key, cp_iv) =
            vbc4_aes_material(session_material, &nonce, seed, SECTION_CONSTANT_POOL, 0);
        let cp_plaintext = aes128_ctr(
            &cp_key,
            &cp_iv,
            &cp_ciphertext_wipe,
            self.limits.max_section_size,
        )
        .map_err(|_| VmError::Crypto)?;
        cp_ciphertext_wipe.fill(0);
        let mut cp_plaintext_wipe = WipedBytes(cp_plaintext);
        let constants = parse_constant_pool(
            &cp_plaintext_wipe,
            self.limits,
            session_material,
            &nonce,
            seed,
            build_key,
        )?;
        cp_plaintext_wipe.wipe();

        let mut records = Vec::with_capacity(block_count);
        let mut seen_ids = vec![false; block_count];
        for _ in 0..block_count {
            let block_id = usize::from(cursor.read_u16_be()?);
            if block_id >= block_count || seen_ids[block_id] {
                return Err(VmError::InvalidBlock(
                    "block id is duplicated or out of range",
                ));
            }
            seen_ids[block_id] = true;
            let _entry_token = cursor.read_u32_be()?;
            let dispatch_token = cursor.read_u32_be()?;
            let next_id = decode_block_dispatch(seed, block_id, block_count, dispatch_token)?;
            records.push(BlockRecord { block_id, next_id });
        }

        let mut blocks: Vec<Option<BlockRows>> = (0..block_count).map(|_| None).collect();
        let mut register_count = None;
        let mut nested_profile = 0u32;
        for record in &records {
            let plain_length = checked_section_length(
                cursor.read_u32_be()?,
                "block plaintext",
                self.limits.max_section_size,
            )?;
            let stored_length = checked_section_length(
                cursor.read_u32_be()?,
                "block stored",
                self.limits.max_section_size,
            )?;
            let encrypted_length = checked_section_length(
                cursor.read_u32_be()?,
                "block ciphertext",
                self.limits.max_section_size,
            )?;
            if plain_length == 0
                || stored_length == 0
                || encrypted_length != stored_length
                || encrypted_length > cursor.remaining()
            {
                return Err(VmError::InvalidBlock("block section lengths are invalid"));
            }
            if stored_length != plain_length && stored_length >= plain_length {
                return Err(VmError::InvalidBlock(
                    "compressed block is not smaller than plaintext",
                ));
            }
            let mut encrypted = cursor.read_bytes(encrypted_length)?.to_vec();
            let (key, iv) = vbc4_aes_material(
                session_material,
                &nonce,
                seed,
                SECTION_INSTRUCTIONS,
                record.block_id as u32,
            );
            let decrypted = aes128_ctr(&key, &iv, &encrypted, self.limits.max_section_size)
                .map_err(|_| VmError::Crypto)?;
            encrypted.fill(0);
            let plain = if stored_length == plain_length {
                if decrypted.len() != plain_length {
                    return Err(VmError::InvalidBlock("raw block length mismatch"));
                }
                decrypted
            } else {
                let mut decrypted_wipe = WipedBytes(decrypted);
                let decoded =
                    zstd::decompress(&decrypted_wipe, plain_length, self.limits.max_section_size)
                        .map_err(|_| VmError::InvalidCompression)?;
                decrypted_wipe.wipe();
                decoded
            };
            let mut plain_wipe = WipedBytes(plain);
            let parsed = parse_block_rows(&plain_wipe, flags, seed, record.block_id, self.limits)?;
            plain_wipe.wipe();
            if let Some(expected) = register_count {
                if expected != parsed.register_count {
                    return Err(VmError::InvalidRow("register count changes between blocks"));
                }
            } else {
                register_count = Some(parsed.register_count);
            }
            if parsed.nested_profile != 0 {
                if nested_profile != 0 && nested_profile != parsed.nested_profile {
                    return Err(VmError::InvalidRow(
                        "nested VM profile changes between blocks",
                    ));
                }
                nested_profile = parsed.nested_profile;
            }
            blocks[record.block_id] = Some(parsed);
        }
        if blocks.iter().any(Option::is_none) {
            return Err(VmError::InvalidBlock("a block section is missing"));
        }
        let chain = validate_block_chain(&records, block_count)?;
        let mut rows = Vec::new();
        for block_id in chain {
            let block = blocks[block_id]
                .take()
                .ok_or(VmError::InvalidBlock("block chain lookup failed"))?;
            if rows
                .len()
                .checked_add(block.rows.len())
                .ok_or(VmError::LengthTooLarge {
                    field: "register rows",
                    length: usize::MAX,
                    maximum: self.limits.max_instructions,
                })?
                > self
                    .limits
                    .max_rows_per_block
                    .saturating_mul(self.limits.max_blocks)
            {
                return Err(VmError::LengthTooLarge {
                    field: "register rows",
                    length: rows.len(),
                    maximum: self.limits.max_instructions,
                });
            }
            rows.extend(block.rows);
        }
        let (mut program, metadata_cp_index) = lower_rows(
            rows,
            register_count.ok_or(VmError::InvalidRow("register count is missing"))?,
            nested_profile,
            constants,
            seed,
            session_material,
            self.limits,
            &self.dialect,
        )?;

        let exception_plain_length = checked_section_length(
            cursor.read_u32_be()?,
            "exception plaintext",
            self.limits.max_section_size,
        )?;
        let exception_stored_length = checked_section_length(
            cursor.read_u32_be()?,
            "exception stored",
            self.limits.max_section_size,
        )?;
        let exception_encrypted_length = checked_section_length(
            cursor.read_u32_be()?,
            "exception ciphertext",
            self.limits.max_section_size,
        )?;
        if exception_plain_length == 0
            || exception_stored_length == 0
            || exception_encrypted_length != exception_stored_length
            || exception_encrypted_length > cursor.remaining()
        {
            return Err(VmError::InvalidException(
                "exception section lengths are invalid",
            ));
        }
        if exception_stored_length != exception_plain_length
            && exception_stored_length >= exception_plain_length
        {
            return Err(VmError::InvalidException(
                "compressed exception section is not smaller than plaintext",
            ));
        }
        let mut encrypted_exception = cursor.read_bytes(exception_encrypted_length)?.to_vec();
        let (exception_key, exception_iv) =
            vbc4_aes_material(session_material, &nonce, seed, SECTION_EXCEPTIONS, 0);
        let decrypted_exception = aes128_ctr(
            &exception_key,
            &exception_iv,
            &encrypted_exception,
            self.limits.max_section_size,
        )
        .map_err(|_| VmError::Crypto)?;
        encrypted_exception.fill(0);
        let exception_plain = if exception_stored_length == exception_plain_length {
            decrypted_exception
        } else {
            let mut decrypted_wipe = WipedBytes(decrypted_exception);
            let decoded = zstd::decompress(
                &decrypted_wipe,
                exception_plain_length,
                self.limits.max_section_size,
            )
            .map_err(|_| VmError::InvalidCompression)?;
            decrypted_wipe.wipe();
            decoded
        };
        let mut exception_plain_wipe = WipedBytes(exception_plain);
        let encoded_exceptions =
            parse_exception_section(&exception_plain_wipe, self.limits, session_material, seed)?;
        exception_plain_wipe.wipe();

        if flags & FLAG_PADDED != 0 {
            let padding_length = checked_section_length(
                cursor.read_u32_be()?,
                "padding",
                self.limits.max_section_size,
            )?;
            cursor.skip(padding_length)?;
        }
        cursor.require_empty()?;
        let instruction_count = program.instructions.len();
        if instruction_count == 0 || instruction_count > self.limits.max_instructions {
            return Err(VmError::LengthTooLarge {
                field: "instructions",
                length: instruction_count,
                maximum: self.limits.max_instructions,
            });
        }
        decode_instruction_targets(&mut program, seed, instruction_count)?;
        let exceptions = decode_exceptions(
            encoded_exceptions,
            instruction_count,
            program.constants.len(),
            seed,
        )?;
        program.exceptions = exceptions;
        program.metadata_cp_index = metadata_cp_index;
        program.flags = flags;
        program.nonce = nonce;
        program.seed = seed;
        let metadata = parse_metadata(&program.constants, metadata_cp_index, nested_profile)?;
        validate_state_binding(
            &self.state_binding,
            &metadata,
            self.material.layout_digest(),
        )?;
        program.metadata = metadata;
        Ok(program)
    }
}

impl<'a> Drop for VmParser<'a> {
    fn drop(&mut self) {
        self.state_binding.fill(0);
    }
}

struct WipedBytes(Vec<u8>);

impl WipedBytes {
    fn wipe(&mut self) {
        self.0.fill(0);
    }
}

impl std::ops::Deref for WipedBytes {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for WipedBytes {
    fn drop(&mut self) {
        self.wipe();
    }
}

pub struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    pub fn position(&self) -> usize {
        self.position
    }

    pub fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.position)
    }

    pub fn read_u8(&mut self) -> Result<u8, VmError> {
        Ok(self.take(1)?[0])
    }

    pub fn read_u16_be(&mut self) -> Result<u16, VmError> {
        Ok(u16::from_be_bytes(self.read_fixed()?))
    }

    pub fn read_u32_be(&mut self) -> Result<u32, VmError> {
        Ok(u32::from_be_bytes(self.read_fixed()?))
    }

    pub fn read_u64_be(&mut self) -> Result<u64, VmError> {
        Ok(u64::from_be_bytes(self.read_fixed()?))
    }

    pub fn read_fixed<const N: usize>(&mut self) -> Result<[u8; N], VmError> {
        let bytes = self.take(N)?;
        let mut output = [0u8; N];
        output.copy_from_slice(bytes);
        Ok(output)
    }

    pub fn read_bytes(&mut self, length: usize) -> Result<&'a [u8], VmError> {
        self.take(length)
    }

    pub fn skip(&mut self, length: usize) -> Result<(), VmError> {
        self.take(length).map(|_| ())
    }

    pub fn require_empty(&self) -> Result<(), VmError> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(VmError::TrailingBytes {
                remaining: self.remaining(),
            })
        }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], VmError> {
        let remaining = self.remaining();
        if length > remaining {
            return Err(VmError::Truncated {
                offset: self.position,
                requested: length,
                remaining,
            });
        }
        let start = self.position;
        self.position += length;
        Ok(&self.bytes[start..self.position])
    }
}

#[derive(Debug)]
pub struct VmString(Vec<u8>);

impl VmString {
    fn from_string(value: String) -> Self {
        Self(value.into_bytes())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).expect("VmString is validated UTF-8")
    }
}

impl fmt::Display for VmString {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Drop for VmString {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

#[derive(Debug)]
pub enum VmConstant {
    Int(i32),
    Long(i64),
    Float(f32),
    Double(f64),
    String(VmString),
}

impl VmConstant {
    pub fn as_string(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value.as_str()),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Instruction {
    pub opcode: u16,
    pub flags: u16,
    operand_range: Range<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExceptionHandler {
    pub start: usize,
    pub end: usize,
    pub handler: usize,
    pub type_cp: Option<usize>,
}

#[derive(Debug)]
pub struct VmMetadata {
    pub entry_token: u64,
    pub return_tag: u8,
    pub method_local_profile: u32,
    pub method_identity: [u8; 32],
    pub owner_identity: [u8; 32],
    pub argument_tags: Vec<u8>,
    pub resource_path: VmString,
    pub is_static: bool,
    pub native_vm_profile_id: u32,
    pub dispatch_profile_tag: u32,
}

impl Drop for VmMetadata {
    fn drop(&mut self) {
        self.method_identity.fill(0);
        self.owner_identity.fill(0);
        self.argument_tags.fill(0);
    }
}

#[derive(Debug)]
pub struct VmProgram {
    constants: Vec<VmConstant>,
    instructions: Vec<Instruction>,
    operands: Vec<i32>,
    exceptions: Vec<ExceptionHandler>,
    metadata: VmMetadata,
    metadata_cp_index: usize,
    register_count: usize,
    max_stack: usize,
    max_locals: usize,
    flags: u16,
    nonce: [u8; 16],
    seed: u32,
}

impl VmProgram {
    pub fn constants(&self) -> &[VmConstant] {
        &self.constants
    }

    pub fn instructions(&self) -> &[Instruction] {
        &self.instructions
    }

    pub fn instruction_operands(&self, instruction: &Instruction) -> &[i32] {
        &self.operands[instruction.operand_range.clone()]
    }

    pub fn exceptions(&self) -> &[ExceptionHandler] {
        &self.exceptions
    }

    pub fn metadata(&self) -> &VmMetadata {
        &self.metadata
    }

    pub fn register_count(&self) -> usize {
        self.register_count
    }

    pub fn max_stack(&self) -> usize {
        self.max_stack
    }

    pub fn max_locals(&self) -> usize {
        self.max_locals
    }

    pub fn flags(&self) -> u16 {
        self.flags
    }

    pub fn metadata_cp_index(&self) -> usize {
        self.metadata_cp_index
    }
}

impl Drop for VmProgram {
    fn drop(&mut self) {
        self.operands.fill(0);
        self.nonce.fill(0);
        self.seed = 0;
    }
}

#[derive(Clone, Copy)]
struct BlockRecord {
    block_id: usize,
    next_id: usize,
}

struct BlockRows {
    register_count: usize,
    nested_profile: u32,
    rows: Vec<RawRow>,
}

#[derive(Clone, Copy, Debug)]
struct RawRow {
    opcode: u16,
    flags: u16,
    dst: u16,
    src_a: u16,
    src_b: u16,
    operand: i32,
}

struct EncodedException {
    start: u16,
    end: u16,
    handler: u16,
    type_cp: u16,
}

fn validate_flags(flags: u16) -> Result<(), VmError> {
    if flags & REQUIRED_FLAGS != REQUIRED_FLAGS {
        return Err(VmError::InvalidFlags(flags));
    }
    let modes = flags & (FLAG_NESTED_VM | FLAG_REGISTER_ROW_ENVELOPE | FLAG_MIXED_OPERAND_ENVELOPE);
    if modes.count_ones() > 1 {
        return Err(VmError::InvalidFlags(flags));
    }
    Ok(())
}

fn validate_state_binding(
    state_binding: &[u8],
    metadata: &VmMetadata,
    layout_digest: &[u8; 32],
) -> Result<(), VmError> {
    let fields: Vec<&[u8]> = state_binding.split(|byte| *byte == 0).collect();
    if fields.len() != 4 || fields.iter().any(|field| field.is_empty()) {
        return Err(VmError::StateBindingMismatch);
    }

    let expected_entry_token = format!("{:x}", metadata.entry_token);
    let mut expected_layout_hex = [0u8; 64];
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (index, byte) in layout_digest.iter().copied().enumerate() {
        expected_layout_hex[index * 2] = HEX[usize::from(byte >> 4)];
        expected_layout_hex[index * 2 + 1] = HEX[usize::from(byte & 0x0f)];
    }
    let valid = fields[0] == expected_entry_token.as_bytes()
        && fields[1] == metadata.resource_path.as_str().as_bytes()
        && fields[2] == VBC4_CLEAN_ENTRY_INTEGRITY_HEX
        && fields[3] == expected_layout_hex;
    expected_layout_hex.fill(0);
    if valid {
        Ok(())
    } else {
        Err(VmError::StateBindingMismatch)
    }
}

fn checked_section_length(
    value: u32,
    field: &'static str,
    maximum: usize,
) -> Result<usize, VmError> {
    let length = usize::try_from(value).map_err(|_| VmError::LengthTooLarge {
        field,
        length: usize::MAX,
        maximum,
    })?;
    if length > maximum {
        return Err(VmError::LengthTooLarge {
            field,
            length,
            maximum,
        });
    }
    Ok(length)
}

fn unwrap_seed(
    session_material: &[u8; 32],
    nonce: &[u8; 16],
    wrapped: &[u8; 16],
    state_binding: &[u8],
) -> Result<u32, VmError> {
    let mask = vbc4_hmac(
        session_material,
        0,
        &[&nonce[..], state_binding],
        b"vbc4-seed-wrap",
    );
    let mut seed_bytes = [0u8; 4];
    for index in 0..4 {
        seed_bytes[index] = wrapped[index] ^ mask[index];
    }
    let seed = u32::from_be_bytes(seed_bytes);
    let token = vbc4_hmac(
        session_material,
        seed,
        &[&nonce[..], state_binding],
        b"vbc4-seed-token",
    );
    let valid = ct_eq(&wrapped[4..], &token[..12]);
    seed_bytes.fill(0);
    if !valid {
        return Err(VmError::InvalidSeed);
    }
    Ok(seed)
}

fn key_id_for(session_material: &[u8; 32], seed: u32, nonce: &[u8; 16]) -> u32 {
    let digest = vbc4_hmac(session_material, seed, &[&nonce[..]], b"vbc4-key-id");
    u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]])
}

fn parse_constant_pool(
    bytes: &[u8],
    limits: ParserLimits,
    session_material: &[u8; 32],
    nonce: &[u8; 16],
    seed: u32,
    build_key: &[u8; 32],
) -> Result<Vec<VmConstant>, VmError> {
    let mut cursor = Cursor::new(bytes);
    let count = usize::from(cursor.read_u16_be()?);
    if count == 0 || count > limits.max_constants {
        return Err(VmError::LengthTooLarge {
            field: "constant count",
            length: count,
            maximum: limits.max_constants,
        });
    }
    let mut constants = Vec::with_capacity(count);
    for entry_id in 0..count {
        let plain_length = checked_section_length(
            cursor.read_u32_be()?,
            "constant plaintext",
            limits.max_section_size,
        )?;
        let stored_encoded = cursor.read_u32_be()?;
        let compressed = stored_encoded & 0x8000_0000 != 0;
        let stored_length =
            usize::try_from(stored_encoded & 0x7fff_ffff).map_err(|_| VmError::LengthTooLarge {
                field: "constant stored",
                length: usize::MAX,
                maximum: limits.max_section_size,
            })?;
        let encrypted_length = checked_section_length(
            cursor.read_u32_be()?,
            "constant ciphertext",
            limits.max_section_size,
        )?;
        if plain_length == 0
            || stored_length == 0
            || encrypted_length != stored_length
            || encrypted_length > cursor.remaining()
        {
            return Err(VmError::InvalidConstantPool("constant lengths are invalid"));
        }
        if compressed {
            if stored_length >= plain_length {
                return Err(VmError::InvalidConstantPool(
                    "compressed constant is not smaller than plaintext",
                ));
            }
        } else if stored_length != plain_length {
            return Err(VmError::InvalidConstantPool("raw constant length mismatch"));
        }
        let mut encrypted = cursor.read_bytes(encrypted_length)?.to_vec();
        let (key, iv) = vbc4_aes_material(
            session_material,
            nonce,
            seed,
            SECTION_CONSTANT_POOL_ENTRY,
            entry_id as u32,
        );
        let decrypted = aes128_ctr(&key, &iv, &encrypted, limits.max_section_size)
            .map_err(|_| VmError::Crypto)?;
        encrypted.fill(0);
        let plain = if compressed {
            let mut decrypted_wipe = WipedBytes(decrypted);
            let decoded = zstd::decompress(&decrypted_wipe, plain_length, limits.max_section_size)
                .map_err(|_| VmError::InvalidCompression)?;
            decrypted_wipe.wipe();
            decoded
        } else {
            decrypted
        };
        let mut plain_wipe = WipedBytes(plain);
        let constant = parse_constant(&plain_wipe, build_key)?;
        plain_wipe.wipe();
        constants.push(constant);
    }
    cursor.require_empty()?;
    Ok(constants)
}

fn parse_constant(bytes: &[u8], build_key: &[u8; 32]) -> Result<VmConstant, VmError> {
    let mut cursor = Cursor::new(bytes);
    let kind = cursor.read_u8()?;
    let value = match kind {
        0x02 if bytes.len() == 5 => VmConstant::Int(cursor.read_u32_be()? as i32),
        0x03 if bytes.len() == 9 => VmConstant::Long(cursor.read_u64_be()? as i64),
        0x04 if bytes.len() == 5 => VmConstant::Float(f32::from_bits(cursor.read_u32_be()?)),
        0x05 if bytes.len() == 9 => VmConstant::Double(f64::from_bits(cursor.read_u64_be()?)),
        CP_SEALED_STRING => VmConstant::String(parse_sealed_string(&bytes[1..], build_key)?),
        0x01 => {
            return Err(VmError::InvalidConstantPool(
                "plain string constants are retired",
            ))
        }
        _ => {
            return Err(VmError::InvalidConstantPool(
                "constant type or length is invalid",
            ))
        }
    };
    if !matches!(value, VmConstant::String(_)) {
        cursor.require_empty()?;
    }
    Ok(value)
}

fn parse_sealed_string(bytes: &[u8], build_key: &[u8; 32]) -> Result<VmString, VmError> {
    let mut cursor = Cursor::new(bytes);
    let nonce = cursor.read_fixed::<16>()?;
    let ciphertext_length = usize::from(cursor.read_u16_be()?);
    if ciphertext_length > 0xffff || ciphertext_length > cursor.remaining().saturating_sub(32) {
        return Err(VmError::InvalidConstantPool(
            "sealed string length is invalid",
        ));
    }
    let ciphertext = cursor.read_bytes(ciphertext_length)?.to_vec();
    let tag = cursor.read_fixed::<32>()?;
    cursor.require_empty()?;
    let expected = crypto::hmac_bytes(
        build_key,
        &[b"javashroud-vbc4-cp-string-tag-v2", &nonce, &ciphertext],
    );
    if !ct_eq(&expected, &tag) {
        let mut ciphertext_wipe = ciphertext;
        ciphertext_wipe.fill(0);
        return Err(VmError::AuthenticationFailed);
    }
    let (key, iv) = crypto::cp_string_material(
        build_key,
        b"javashroud-vbc4-cp-string-key-v2",
        b"javashroud-vbc4-cp-string-iv-v2",
        &nonce,
    );
    let mut ciphertext_wipe = ciphertext;
    let plain = aes128_ctr(&key, &iv, &ciphertext_wipe, 0xffff).map_err(|_| VmError::Crypto)?;
    ciphertext_wipe.fill(0);
    let mut plain_wipe = WipedBytes(plain);
    let result = decode_modified_utf8(&plain_wipe);
    plain_wipe.wipe();
    result
}

fn decode_modified_utf8(bytes: &[u8]) -> Result<VmString, VmError> {
    let mut units = Vec::with_capacity(bytes.len());
    let mut offset = 0usize;
    while offset < bytes.len() {
        let first = bytes[offset];
        let (unit, width) = if (1..=0x7f).contains(&first) {
            (u16::from(first), 1)
        } else if first == 0xc0 {
            if offset + 1 >= bytes.len() || bytes[offset + 1] != 0x80 {
                return Err(VmError::InvalidConstantPool(
                    "modified UTF-8 NUL is malformed",
                ));
            }
            (0, 2)
        } else if (0xc0..=0xdf).contains(&first) {
            if offset + 1 >= bytes.len() || bytes[offset + 1] & 0xc0 != 0x80 {
                return Err(VmError::InvalidConstantPool(
                    "modified UTF-8 two-byte sequence is malformed",
                ));
            }
            let value = (u16::from(first & 0x1f) << 6) | u16::from(bytes[offset + 1] & 0x3f);
            if value < 0x80 {
                return Err(VmError::InvalidConstantPool(
                    "modified UTF-8 sequence is overlong",
                ));
            }
            (value, 2)
        } else if (0xe0..=0xef).contains(&first) {
            if offset + 2 >= bytes.len()
                || bytes[offset + 1] & 0xc0 != 0x80
                || bytes[offset + 2] & 0xc0 != 0x80
            {
                return Err(VmError::InvalidConstantPool(
                    "modified UTF-8 three-byte sequence is malformed",
                ));
            }
            let value = (u16::from(first & 0x0f) << 12)
                | (u16::from(bytes[offset + 1] & 0x3f) << 6)
                | u16::from(bytes[offset + 2] & 0x3f);
            if value < 0x800 {
                return Err(VmError::InvalidConstantPool(
                    "modified UTF-8 sequence is overlong",
                ));
            }
            (value, 3)
        } else {
            return Err(VmError::InvalidConstantPool(
                "modified UTF-8 sequence is unsupported",
            ));
        };
        units.push(unit);
        offset += width;
    }
    let value = String::from_utf16(&units)
        .map_err(|_| VmError::InvalidConstantPool("modified UTF-8 contains an invalid surrogate"));
    units.fill(0);
    value.map(VmString::from_string)
}

fn decode_block_dispatch(
    seed: u32,
    block_id: usize,
    block_count: usize,
    token: u32,
) -> Result<usize, VmError> {
    let rotation = ((block_id * 5 + 7) & 31) as u32;
    let mask = seed.rotate_left(rotation)
        ^ (block_id as u32).wrapping_mul(0x045d_9f3b)
        ^ (block_count as u32).wrapping_mul(0x119d_e1f3);
    let payload = token ^ mask;
    let next_id = (payload & 0xffff) as usize;
    if next_id > block_count {
        return Err(VmError::InvalidBlock(
            "dispatch edge target is out of range",
        ));
    }
    let state = dispatch_state_candidates(seed, block_id, next_id, block_count);
    if ((payload >> 16) as u16) != state {
        return Err(VmError::InvalidBlock("dispatch edge authentication failed"));
    }
    Ok(next_id)
}

fn dispatch_state_candidates(
    seed: u32,
    block_id: usize,
    next_id: usize,
    block_count: usize,
) -> u16 {
    let mixed = seed.rotate_left(((block_id * 3 + 11) & 31) as u32)
        ^ (block_id as u32).wrapping_mul(0x632b_e59b)
        ^ (next_id as u32).wrapping_mul(0x8515_7af5)
        ^ (block_count as u32).wrapping_mul(0x9e37_79b9);
    let state = (mixed ^ (mixed >> 16)) as u16;
    if state == 0 {
        1
    } else {
        state
    }
}

fn validate_block_chain(
    records: &[BlockRecord],
    block_count: usize,
) -> Result<Vec<usize>, VmError> {
    let mut next = vec![usize::MAX; block_count];
    for record in records {
        next[record.block_id] = record.next_id;
    }
    let mut visited = vec![false; block_count];
    let mut chain = Vec::with_capacity(block_count);
    let mut current = 0usize;
    for index in 0..block_count {
        if current >= block_count || visited[current] {
            return Err(VmError::InvalidBlock(
                "dispatch chain repeats or leaves the block set",
            ));
        }
        visited[current] = true;
        chain.push(current);
        let following = next[current];
        if index + 1 < block_count {
            if following >= block_count {
                return Err(VmError::InvalidBlock("dispatch chain terminates early"));
            }
        } else if following != block_count {
            return Err(VmError::InvalidBlock(
                "dispatch chain has an invalid terminator",
            ));
        }
        current = following;
    }
    if visited.iter().any(|seen| !seen) {
        return Err(VmError::InvalidBlock(
            "dispatch chain does not visit every block",
        ));
    }
    Ok(chain)
}

fn parse_block_rows(
    bytes: &[u8],
    flags: u16,
    seed: u32,
    block_id: usize,
    limits: ParserLimits,
) -> Result<BlockRows, VmError> {
    let mut cursor = Cursor::new(bytes);
    if flags & FLAG_NESTED_VM != 0 {
        return parse_nested_rows(&mut cursor, seed, block_id, limits);
    }
    let register_count = usize::from(cursor.read_u16_be()?);
    let row_count = usize::from(cursor.read_u16_be()?);
    if register_count == 0 || row_count == 0 || row_count > limits.max_rows_per_block {
        return Err(VmError::InvalidRow("register or row count is invalid"));
    }
    let mode = flags & (FLAG_REGISTER_ROW_ENVELOPE | FLAG_MIXED_OPERAND_ENVELOPE);
    if mode != 0 {
        let observed = cursor.read_u32_be()?;
        let expected = if mode == FLAG_REGISTER_ROW_ENVELOPE {
            register_row_dialect(seed, block_id, row_count)
        } else {
            register_row_dialect(seed, block_id, row_count)
                ^ register_row_mix_word(seed, block_id, row_count, 0x61, 0x4f)
        };
        if observed != expected {
            return Err(VmError::InvalidRow(
                "row dialect does not match the authenticated seed",
            ));
        }
    }
    let mut rows = Vec::with_capacity(row_count);
    for row_index in 0..row_count {
        let row = match mode {
            0 => read_plain_row(&mut cursor)?,
            FLAG_REGISTER_ROW_ENVELOPE => {
                read_envelope_row(&mut cursor, seed, block_id, row_index)?
            }
            FLAG_MIXED_OPERAND_ENVELOPE => read_mixed_row(&mut cursor, seed, block_id, row_index)?,
            _ => return Err(VmError::InvalidRow("row envelope mode is invalid")),
        };
        rows.push(row);
    }
    if cursor.read_u16_be()? != 0 {
        return Err(VmError::InvalidRow("stack instruction stream is not empty"));
    }
    cursor.require_empty()?;
    Ok(BlockRows {
        register_count,
        nested_profile: 0,
        rows,
    })
}

fn read_plain_row(cursor: &mut Cursor<'_>) -> Result<RawRow, VmError> {
    Ok(RawRow {
        opcode: cursor.read_u16_be()?,
        flags: cursor.read_u16_be()?,
        dst: cursor.read_u16_be()?,
        src_a: cursor.read_u16_be()?,
        src_b: cursor.read_u16_be()?,
        operand: cursor.read_u32_be()? as i32,
    })
}

fn register_row_mix_word(
    seed: u32,
    block_id: usize,
    row_index: usize,
    slot: usize,
    field: usize,
) -> u32 {
    let mut state = seed
        ^ (block_id as u32).wrapping_mul(0x045d_9f3b)
        ^ (row_index as u32).wrapping_mul(0x7feb_352d)
        ^ (slot as u32).wrapping_mul(0x846c_a68b)
        ^ (field as u32).wrapping_mul(0x2c1b_3c6d);
    state ^= state >> 16;
    state = state.wrapping_mul(0x7feb_352d);
    state ^= state >> 13;
    state = state.wrapping_mul(0x846c_a68b);
    state ^ (state >> 16)
}

fn register_row_dialect(seed: u32, block_id: usize, row_count: usize) -> u32 {
    register_row_mix_word(seed, block_id, row_count, 0x23, 0x4d)
}

fn register_row_order(seed: u32, block_id: usize, row_index: usize) -> [usize; 6] {
    let mut order = [0, 1, 2, 3, 4, 5];
    for index in (1..=5).rev() {
        let swap =
            (register_row_mix_word(seed, block_id, row_index, index, 0x71) as usize) % (index + 1);
        order.swap(index, swap);
    }
    order
}

fn read_envelope_row(
    cursor: &mut Cursor<'_>,
    seed: u32,
    block_id: usize,
    row_index: usize,
) -> Result<RawRow, VmError> {
    let order = register_row_order(seed, block_id, row_index);
    let mut fields = [0u32; 6];
    for (slot, field) in order.into_iter().enumerate() {
        let mask = register_row_mix_word(seed, block_id, row_index, slot, field);
        fields[field] = if field == 5 {
            cursor.read_u32_be()? ^ mask
        } else {
            u32::from(cursor.read_u16_be()?) ^ (mask & 0xffff)
        };
    }
    Ok(raw_row_from_fields(fields))
}

fn mixed_row_token(seed: u32, block_id: usize, row_index: usize, shape: usize) -> u16 {
    let payload = (register_row_mix_word(seed, block_id, row_index, shape, 0x5e)
        ^ (shape as u32).wrapping_mul(0x045d_9f3b))
        & 0x3fff;
    (((shape as u16) & 0x3) << 14) | payload as u16
}

fn read_mixed_row(
    cursor: &mut Cursor<'_>,
    seed: u32,
    block_id: usize,
    row_index: usize,
) -> Result<RawRow, VmError> {
    let token = cursor.read_u16_be()?;
    let shape = usize::from(token >> 14);
    if shape > 2 || token != mixed_row_token(seed, block_id, row_index, shape) {
        return Err(VmError::InvalidRow("mixed operand row token is invalid"));
    }
    match shape {
        0 => read_plain_row(cursor),
        1 => read_envelope_row(cursor, seed, block_id, row_index),
        2 => {
            let operand =
                cursor.read_u32_be()? ^ register_row_mix_word(seed, block_id, row_index, 0x42, 5);
            let src_b = cursor.read_u16_be()?
                ^ (register_row_mix_word(seed, block_id, row_index, 0x43, 4) as u16);
            let src_a = cursor.read_u16_be()?
                ^ (register_row_mix_word(seed, block_id, row_index, 0x44, 3) as u16);
            let dst = cursor.read_u16_be()?
                ^ (register_row_mix_word(seed, block_id, row_index, 0x45, 2) as u16);
            let flags = cursor.read_u16_be()?
                ^ (register_row_mix_word(seed, block_id, row_index, 0x46, 1) as u16);
            let opcode = cursor.read_u16_be()?
                ^ (register_row_mix_word(seed, block_id, row_index, 0x47, 0) as u16);
            Ok(RawRow {
                opcode,
                flags,
                dst,
                src_a,
                src_b,
                operand: operand as i32,
            })
        }
        _ => Err(VmError::InvalidRow("mixed operand row shape is invalid")),
    }
}

fn raw_row_from_fields(fields: [u32; 6]) -> RawRow {
    RawRow {
        opcode: fields[0] as u16,
        flags: fields[1] as u16,
        dst: fields[2] as u16,
        src_a: fields[3] as u16,
        src_b: fields[4] as u16,
        operand: fields[5] as i32,
    }
}

fn parse_nested_rows(
    cursor: &mut Cursor<'_>,
    seed: u32,
    block_id: usize,
    limits: ParserLimits,
) -> Result<BlockRows, VmError> {
    let register_count = usize::from(cursor.read_u16_be()?);
    if cursor.read_u16_be()? != NESTED_MAGIC {
        return Err(VmError::InvalidRow("nested VM magic is invalid"));
    }
    let row_count = usize::from(cursor.read_u16_be()?);
    let profile = cursor.read_u32_be()?;
    let dialect = cursor.read_u32_be()?;
    let micro_count = usize::from(cursor.read_u16_be()?);
    if register_count == 0
        || profile == 0
        || row_count == 0
        || row_count > limits.max_rows_per_block
        || micro_count != row_count.saturating_mul(7)
    {
        return Err(VmError::InvalidRow("nested VM bounds are invalid"));
    }
    let expected_dialect = nested_mix(
        seed,
        profile,
        block_id,
        row_count,
        0x23,
        seed.rotate_left(9) ^ profile.rotate_left(3),
    );
    if dialect != expected_dialect {
        return Err(VmError::InvalidRow("nested VM dialect is invalid"));
    }
    let mut rows = Vec::with_capacity(row_count);
    for row_index in 0..row_count {
        let order = nested_field_order(seed, profile, block_id, row_index, dialect);
        let mut fields = [0i32; 6];
        for (slot, field) in order.into_iter().enumerate() {
            let micro_opcode = cursor.read_u16_be()?;
            let encoded_field = cursor.read_u16_be()?;
            let encoded_value = cursor.read_u32_be()?;
            let mix = nested_mix(seed, profile, block_id, row_index, slot, dialect);
            let value_mask = nested_mix(seed, profile, block_id, row_index, slot + 0x51, dialect);
            if micro_opcode != NESTED_FIELD_OPCODE_BASE | (mix as u16 & 0x0fff)
                || encoded_field != (field as u16 ^ (mix >> 16) as u16)
            {
                return Err(VmError::InvalidRow("nested VM field micro-op is invalid"));
            }
            fields[field] = (encoded_value ^ value_mask) as i32;
        }
        let commit_mix = nested_mix(
            seed,
            profile,
            block_id,
            row_index,
            NESTED_COMMIT_SLOT,
            dialect,
        );
        if cursor.read_u16_be()? != NESTED_COMMIT_OPCODE_BASE | (commit_mix as u16 & 0x0fff)
            || cursor.read_u16_be()? != row_index as u16 ^ (commit_mix >> 16) as u16
        {
            return Err(VmError::InvalidRow("nested VM commit micro-op is invalid"));
        }
        let checksum = cursor.read_u32_be()?;
        if checksum != nested_checksum(seed, profile, block_id, row_index, dialect, fields) {
            return Err(VmError::InvalidRow("nested VM row checksum is invalid"));
        }
        rows.push(raw_row_from_fields(fields.map(|value| value as u32)));
    }
    cursor.require_empty()?;
    Ok(BlockRows {
        register_count,
        nested_profile: profile,
        rows,
    })
}

fn nested_mix(
    seed: u32,
    profile: u32,
    block_id: usize,
    row_index: usize,
    slot: usize,
    dialect: u32,
) -> u32 {
    let mut value = seed
        ^ profile
        ^ dialect
        ^ (block_id as u32).wrapping_mul(0x045d_9f3b)
        ^ (row_index as u32).wrapping_mul(0x7feb_352d)
        ^ (slot as u32).wrapping_mul(0x846c_a68b);
    value ^= value >> 16;
    value = value.wrapping_mul(0x7feb_352d);
    value ^= value >> 13;
    value = value.wrapping_mul(0x846c_a68b);
    value ^ (value >> 16)
}

fn nested_field_order(
    seed: u32,
    profile: u32,
    block_id: usize,
    row_index: usize,
    dialect: u32,
) -> [usize; 6] {
    let mut order = [0, 1, 2, 3, 4, 5];
    for index in (1..=5).rev() {
        let mix = nested_mix(seed, profile, block_id, row_index, index + 0x31, dialect);
        order.swap(index, (mix as usize & 0x7fff_ffff) % (index + 1));
    }
    order
}

fn nested_checksum(
    seed: u32,
    profile: u32,
    block_id: usize,
    row_index: usize,
    dialect: u32,
    fields: [i32; 6],
) -> u32 {
    let mut value = nested_mix(
        seed,
        profile,
        block_id,
        row_index,
        NESTED_COMMIT_SLOT,
        dialect,
    );
    for (index, field) in fields.into_iter().enumerate() {
        value = nested_mix(
            value ^ field as u32,
            profile,
            block_id,
            row_index,
            index + 0x91,
            dialect,
        );
    }
    value
}

fn canonical_opcode(opcode: u16) -> u16 {
    const ALIASES: &[(u16, &[u16])] = &[
        (ICONST, &[0xe8, 0xe2]),
        (IADD, &[0xe9, 0xe3]),
        (ISUB, &[0xea, 0xe4]),
        (ILOAD, &[0xeb, 0xe5]),
        (ISTORE, &[0xec, 0xe6]),
        (IRETURN, &[0xed, 0xe7]),
        (IMUL, &[0x37]),
        (IXOR, &[0x38]),
        (IAND, &[0x39]),
        (IOR, &[0x3a]),
        (ISHL, &[0x3b]),
        (ISHR, &[0x3c]),
        (IUSHR, &[0x3d]),
        (INEG, &[0x3e]),
        (LADD, &[0x3f]),
        (ALOAD, &[0x15]),
        (LLOAD, &[0x16]),
        (FLOAD, &[0x17]),
        (DLOAD, &[0x18]),
        (ASTORE, &[0x27]),
        (LSTORE, &[0x28]),
        (FSTORE, &[0x29]),
        (DSTORE, &[0x2a]),
        (IALOAD, &[0xa4]),
        (IASTORE, &[0xa5]),
        (AALOAD, &[0xa6]),
        (AASTORE, &[0xa7]),
        (GETFIELD, &[0xa8]),
        (PUTFIELD, &[0xa9]),
        (GETSTATIC, &[0xaa]),
        (PUTSTATIC, &[0xab]),
        (GOTO, &[0x82]),
        (IFEQ, &[0x83]),
        (IFNE, &[0x84]),
        (IF_ICMPEQ, &[0x85]),
        (IF_ICMPNE, &[0x86]),
        (IFNULL, &[0x87]),
        (IFNONNULL, &[0x97]),
        (DUP, &[0x98]),
        (POP, &[0x99]),
        (SWAP, &[0x9b]),
        (BIPUSH, &[0x0f]),
        (SIPUSH, &[0x19]),
        (LCONST, &[0x1a]),
        (FCONST, &[0x1b]),
        (DCONST, &[0x1c]),
        (IREM, &[0x1d]),
        (LREM, &[0x1e]),
        (LAND, &[0x1f]),
        (LOR, &[0x2b]),
        (LXOR, &[0x2c]),
        (IFLT, &[0x2d]),
        (IFGE, &[0x2e]),
        (IFGT, &[0x2f]),
        (IFLE, &[0xf4]),
        (IF_ICMPLT, &[0xf5]),
        (IF_ICMPGE, &[0x65]),
        (IF_ICMPGT, &[0x66]),
        (IF_ICMPLE, &[0x67]),
        (IF_ACMPEQ, &[0x9c]),
        (IF_ACMPNE, &[0x9d]),
        (LRETURN, &[0x9e]),
        (FRETURN, &[0x9f]),
        (DRETURN, &[0xac]),
        (ARETURN, &[0xad]),
        (RETURN, &[0xae]),
        (ATHROW, &[0xaf]),
        (I2L, &[0xb5]),
        (I2F, &[0xb6]),
        (I2D, &[0xb7]),
        (L2I, &[0xb8]),
        (L2F, &[0xb9]),
        (L2D, &[0xba]),
        (F2I, &[0xbb]),
        (F2L, &[0xbc]),
        (F2D, &[0xbd]),
        (D2I, &[0xbe]),
        (D2L, &[0xbf]),
        (D2F, &[0xc7]),
        (I2B, &[0xc8]),
        (I2C, &[0xc9]),
        (I2S, &[0xca]),
        (NEW, &[0xcb]),
        (NEWARRAY, &[0xcc]),
        (ANEWARRAY, &[0xcd]),
        (ARRAYLENGTH, &[0xce]),
        (CHECKCAST, &[0xcf]),
        (INSTANCEOF, &[0xee]),
        (MULTIANEWARRAY, &[0xef]),
    ];
    for (canonical, aliases) in ALIASES {
        if opcode == *canonical || aliases.contains(&opcode) {
            return *canonical;
        }
    }
    opcode
}

fn is_known_opcode(opcode: u16) -> bool {
    matches!(
        canonical_opcode(opcode),
        NOP | ACONST_NULL
            | ICONST
            | LCONST
            | FCONST
            | DCONST
            | BIPUSH
            | SIPUSH
            | LDC_INT
            | LDC_LONG
            | LDC_FLOAT
            | LDC_DOUBLE
            | LDC_STRING
            | LDC_TYPE
            | LDC_HANDLE
            | LDC_CONDY
            | ILOAD
            | LLOAD
            | FLOAD
            | DLOAD
            | ALOAD
            | ISTORE
            | LSTORE
            | FSTORE
            | DSTORE
            | ASTORE
            | IINC
            | RET
            | POP
            | POP2
            | DUP
            | DUP_X1
            | DUP_X2
            | DUP2
            | SWAP
            | DUP2_X1
            | DUP2_X2
            | IADD
            | LADD
            | FADD
            | DADD
            | ISUB
            | LSUB
            | FSUB
            | DSUB
            | IMUL
            | LMUL
            | FMUL
            | DMUL
            | IDIV
            | LDIV
            | FDIV
            | DDIV
            | IREM
            | LREM
            | FREM
            | DREM
            | INEG
            | LNEG
            | FNEG
            | DNEG
            | ISHL
            | ISHR
            | IUSHR
            | LSHL
            | LSHR
            | LUSHR
            | IAND
            | LAND
            | IOR
            | LOR
            | IXOR
            | LXOR
            | LCMP
            | FCMPL
            | FCMPG
            | DCMPL
            | DCMPG
            | I2L
            | I2F
            | I2D
            | L2I
            | L2F
            | L2D
            | F2I
            | F2L
            | F2D
            | D2I
            | D2L
            | D2F
            | I2B
            | I2C
            | I2S
            | IFEQ
            | IFNE
            | IFLT
            | IFGE
            | IFGT
            | IFLE
            | IF_ICMPEQ
            | IF_ICMPNE
            | IF_ICMPLT
            | IF_ICMPGE
            | IF_ICMPGT
            | IF_ICMPLE
            | IF_ACMPEQ
            | IF_ACMPNE
            | GOTO
            | JSR
            | IFNULL
            | IFNONNULL
            | IRETURN
            | LRETURN
            | FRETURN
            | DRETURN
            | ARETURN
            | RETURN
            | ATHROW
            | GETSTATIC
            | PUTSTATIC
            | GETFIELD
            | PUTFIELD
            | INVOKEVIRTUAL
            | INVOKESPECIAL
            | INVOKESTATIC
            | INVOKEINTERFACE
            | INVOKEDYNAMIC
            | NEW
            | NEWARRAY
            | ANEWARRAY
            | ARRAYLENGTH
            | CHECKCAST
            | INSTANCEOF
            | MULTIANEWARRAY
            | IALOAD
            | LALOAD
            | FALOAD
            | DALOAD
            | AALOAD
            | BALOAD
            | CALOAD
            | SALOAD
            | IASTORE
            | LASTORE
            | FASTORE
            | DASTORE
            | AASTORE
            | BASTORE
            | CASTORE
            | SASTORE
            | MONITORENTER
            | MONITOREXIT
            | TABLESWITCH
            | LOOKUPSWITCH
            | MAXS
    )
}

fn allowed_super(super_opcode: u16, original: u16) -> bool {
    match super_opcode {
        SUPER_CONST => matches!(original, ICONST | BIPUSH | SIPUSH),
        SUPER_INT_ARITH => matches!(
            original,
            IADD | ISUB | IMUL | IAND | IOR | IXOR | ISHL | ISHR | IUSHR
        ),
        SUPER_CMP_BRANCH => matches!(original, IFEQ | IFNE | IF_ICMPEQ | IF_ICMPNE),
        SUPER_INVOKE => matches!(
            original,
            INVOKESTATIC | INVOKEVIRTUAL | INVOKESPECIAL | INVOKEINTERFACE
        ),
        _ => false,
    }
}

fn folded_allowed(first: u16, second: u16, super_opcode: u16) -> bool {
    match super_opcode {
        SUPER_INT_ARITH => {
            matches!(first, ICONST | BIPUSH | SIPUSH)
                && matches!(
                    second,
                    IADD | ISUB | IMUL | IAND | IOR | IXOR | ISHL | ISHR | IUSHR
                )
        }
        SUPER_CMP_BRANCH => {
            matches!(first, LCMP | FCMPL | FCMPG | DCMPL | DCMPG)
                && matches!(second, IFEQ | IFNE | IFLT | IFGE | IFGT | IFLE)
        }
        _ => false,
    }
}

fn lower_rows(
    mut rows: Vec<RawRow>,
    register_count: usize,
    nested_profile: u32,
    constants: Vec<VmConstant>,
    seed: u32,
    session_material: &[u8; 32],
    limits: ParserLimits,
    dialect: &dialect::VmDialect,
) -> Result<(VmProgram, usize), VmError> {
    let mut operands = Vec::new();
    let mut instructions = Vec::new();
    let mut metadata_cp_index = None;
    let mut max_stack = 1usize;
    let mut max_locals = 1usize;
    let mut logical_index = 0usize;
    let mut row_index = 0usize;
    while row_index < rows.len() {
        let mut row = rows[row_index];
        if row.flags & REG_SEMANTIC_SHARE != 0 {
            return Err(VmError::InvalidRow("semantic share row is detached"));
        }
        if row.flags & REG_CONTINUATION != 0 {
            return Err(VmError::InvalidRow(
                "continuation row has no primary instruction",
            ));
        }
        if row.flags & !(REG_EXECUTABLE | REG_SUPER | REG_FOLDED | REG_SEMANTIC_SPLIT) != 0 {
            return Err(VmError::InvalidRow("register row flags are invalid"));
        }
        if row.flags & REG_EXECUTABLE == 0 {
            return Err(VmError::InvalidRow(
                "non-executable register row is present",
            ));
        }
        if row.flags & REG_SEMANTIC_SPLIT != 0 {
            if row_index + 1 >= rows.len()
                || rows[row_index + 1].opcode != opcode::REG_SEMANTIC_SHARE
                || rows[row_index + 1].flags != REG_SEMANTIC_SHARE
            {
                return Err(VmError::InvalidRow("semantic split share is missing"));
            }
            let share = rows[row_index + 1];
            let checksum = semantic_share_checksum(
                seed,
                logical_index,
                share.dst,
                share.src_a,
                share.operand as u32,
            );
            if u32::from(share.src_b) != u32::from(checksum) {
                return Err(VmError::InvalidRow("semantic split checksum is invalid"));
            }
            row.opcode ^= share.dst;
            row.src_a ^= share.src_a;
            row.operand ^= share.operand;
            row.flags &= !REG_SEMANTIC_SPLIT;
            row_index += 1;
        }
        let mask = opcode_mask(session_material, seed, logical_index);
        let decoded_raw = dialect.decode(row.opcode ^ u16::from(mask));
        let decoded = if (SUPER_CONST..=SUPER_INVOKE).contains(&decoded_raw) {
            decoded_raw
        } else {
            canonical_opcode(decoded_raw)
        };
        if decoded == UNSUPPORTED
            || (!is_known_opcode(decoded)
                && decoded != REG_META
                && !(SUPER_CONST..=SUPER_INVOKE).contains(&decoded))
        {
            return Err(VmError::InvalidOpcode(decoded));
        }
        if decoded == REG_META {
            if row.flags & (REG_SUPER | REG_FOLDED) != 0
                || metadata_cp_index.replace(row.operand as usize).is_some()
                || row.operand < 0
                || row.operand as usize >= constants.len()
            {
                return Err(VmError::InvalidRow("metadata row is invalid"));
            }
            if row.dst != 0 {
                return Err(VmError::InvalidRow("metadata row has operands"));
            }
            logical_index += 1;
            row_index += 1;
            continue;
        }
        if row.flags & REG_FOLDED != 0 {
            if row.flags & REG_SUPER == 0
                || !folded_allowed(
                    canonical_opcode(row.src_a),
                    canonical_opcode(row.src_b),
                    decoded,
                )
            {
                return Err(VmError::InvalidRow("folded super row is invalid"));
            }
            let first = canonical_opcode(row.src_a);
            let second = canonical_opcode(row.src_b);
            if matches!(decoded, SUPER_INT_ARITH) {
                add_instruction(&mut instructions, &mut operands, first, 0, &[row.operand]);
                add_instruction(&mut instructions, &mut operands, second, 0, &[]);
            } else {
                add_instruction(&mut instructions, &mut operands, first, 0, &[]);
                add_instruction(&mut instructions, &mut operands, second, 0, &[row.operand]);
            }
            logical_index = logical_index
                .checked_add(2)
                .ok_or(VmError::LengthTooLarge {
                    field: "logical instructions",
                    length: usize::MAX,
                    maximum: limits.max_instructions,
                })?;
            row_index += 1;
            continue;
        }
        let opcode = if row.flags & REG_SUPER != 0 {
            let original = canonical_opcode(row.src_b);
            if row.src_b == 0 || !allowed_super(decoded, original) {
                return Err(VmError::InvalidRow("super row original opcode is invalid"));
            }
            original
        } else {
            if (SUPER_CONST..=SUPER_INVOKE).contains(&decoded) {
                return Err(VmError::InvalidRow("super opcode lacks its super flag"));
            }
            decoded
        };
        let operand_count = usize::from(row.dst);
        if operand_count > limits.max_operands_per_instruction {
            return Err(VmError::LengthTooLarge {
                field: "instruction operands",
                length: operand_count,
                maximum: limits.max_operands_per_instruction,
            });
        }
        let mut instruction_operands = Vec::with_capacity(operand_count);
        if operand_count > 0 {
            instruction_operands.push(row.operand);
            for extra in 1..operand_count {
                let index = row_index + extra;
                if index >= rows.len() {
                    return Err(VmError::InvalidRow("instruction continuation is truncated"));
                }
                let continuation = rows[index];
                if continuation.flags != REG_CONTINUATION
                    || continuation.opcode != REG_OPERAND_CONT
                    || continuation.dst as usize != extra
                    || continuation.src_a != row.src_a
                {
                    return Err(VmError::InvalidRow("instruction continuation is malformed"));
                }
                instruction_operands.push(continuation.operand);
            }
            row_index += operand_count;
        } else {
            row_index += 1;
        }
        add_instruction(
            &mut instructions,
            &mut operands,
            opcode,
            row.flags,
            &instruction_operands,
        );
        if opcode == MAXS && instruction_operands.len() >= 2 {
            if instruction_operands[0] < 0 || instruction_operands[1] < 0 {
                return Err(VmError::InvalidRow("VM_MAXS values are negative"));
            }
            max_stack = usize::try_from(instruction_operands[0]).unwrap_or(0).max(1);
            max_locals = usize::try_from(instruction_operands[1]).unwrap_or(0).max(1);
        }
        logical_index = logical_index
            .checked_add(1)
            .ok_or(VmError::LengthTooLarge {
                field: "logical instructions",
                length: usize::MAX,
                maximum: limits.max_instructions,
            })?;
        if instructions.len() > limits.max_instructions {
            return Err(VmError::LengthTooLarge {
                field: "instructions",
                length: instructions.len(),
                maximum: limits.max_instructions,
            });
        }
    }
    let metadata_cp_index =
        metadata_cp_index.ok_or(VmError::InvalidRow("metadata row is missing"))?;
    if instructions.is_empty() {
        return Err(VmError::InvalidRow(
            "executable instruction stream is empty",
        ));
    }
    for row in &mut rows {
        *row = RawRow {
            opcode: 0,
            flags: 0,
            dst: 0,
            src_a: 0,
            src_b: 0,
            operand: 0,
        };
    }
    Ok((
        VmProgram {
            constants,
            instructions,
            operands,
            exceptions: Vec::new(),
            metadata: VmMetadata {
                entry_token: 0,
                return_tag: b'V',
                method_local_profile: nested_profile,
                method_identity: [0; 32],
                owner_identity: [0; 32],
                argument_tags: Vec::new(),
                resource_path: VmString::from_string(String::new()),
                is_static: true,
                native_vm_profile_id: 0,
                dispatch_profile_tag: 1,
            },
            metadata_cp_index,
            register_count,
            max_stack,
            max_locals,
            flags: 0,
            nonce: [0; 16],
            seed: 0,
        },
        metadata_cp_index,
    ))
}

fn add_instruction(
    instructions: &mut Vec<Instruction>,
    operands: &mut Vec<i32>,
    opcode: u16,
    flags: u16,
    values: &[i32],
) {
    let start = operands.len();
    operands.extend_from_slice(values);
    instructions.push(Instruction {
        opcode,
        flags,
        operand_range: start..operands.len(),
    });
}

fn opcode_mask(session_material: &[u8; 32], seed: u32, index: usize) -> u8 {
    let section = 7u32.to_be_bytes();
    let index_bytes = (index as u32).to_be_bytes();
    let digest = vbc4_hmac(
        session_material,
        seed,
        &[&section, &index_bytes, &index_bytes],
        b"vbc4-opcode",
    );
    digest[0]
}

fn semantic_share_checksum(
    seed: u32,
    logical_index: usize,
    opcode_share: u16,
    source_share: u16,
    operand_share: u32,
) -> u16 {
    let mut mixed = seed
        ^ (logical_index as u32).wrapping_mul(0x045d_9f3b)
        ^ (u32::from(opcode_share)).wrapping_mul(0x7feb_352d)
        ^ (u32::from(source_share)).wrapping_mul(0x27d4_eb2d)
        ^ operand_share;
    mixed ^= mixed >> 16;
    mixed = mixed.wrapping_mul(0x7feb_352d);
    mixed ^= mixed >> 13;
    mixed = mixed.wrapping_mul(0x846c_a68b);
    (mixed ^ (mixed >> 16)) as u16
}

fn cfg_multiplier(seed: u32, instruction_count: usize) -> u32 {
    (seed ^ (instruction_count as u32).rotate_left(7) ^ 0x6d2b_79f5) & CFG_MASK | 1
}

fn cfg_offset(seed: u32, instruction_count: usize) -> u32 {
    (seed.rotate_left(13) ^ (instruction_count as u32).wrapping_mul(0x045d_9f3b) ^ 0x27d4_eb2d)
        & CFG_MASK
}

fn modular_inverse(value: u32) -> Option<u32> {
    let mut t = 0i64;
    let mut next_t = 1i64;
    let mut remainder = 0x1_0000i64;
    let mut next_remainder = i64::from(value & CFG_MASK);
    while next_remainder != 0 {
        let quotient = remainder / next_remainder;
        (t, next_t) = (next_t, t - quotient * next_t);
        (remainder, next_remainder) = (next_remainder, remainder - quotient * next_remainder);
    }
    if remainder != 1 {
        return None;
    }
    Some(((t % 0x1_0000 + 0x1_0000) % 0x1_0000) as u32)
}

fn cfg_decode(seed: u32, instruction_count: usize, encoded: i32) -> Result<usize, VmError> {
    if !(0..=CFG_MASK as i32).contains(&encoded) {
        return Err(VmError::InvalidControlFlow);
    }
    let inverse = modular_inverse(cfg_multiplier(seed, instruction_count))
        .ok_or_else(|| {
            VmError::InvalidControlFlow
        })?;
    let normalized = (encoded as u32).wrapping_sub(cfg_offset(seed, instruction_count)) & CFG_MASK;
    let decoded = (normalized.wrapping_mul(inverse)) & CFG_MASK;
    if decoded as usize > instruction_count {
        // Let the caller report the owning opcode/operand context before the
        // fail-closed range rejection.
    }
    Ok(decoded as usize)
}

fn is_target_operand(opcode: u16, index: usize) -> bool {
    match opcode {
        GOTO | JSR | IFEQ | IFNE | IFLT | IFGE | IFGT | IFLE | IF_ICMPEQ | IF_ICMPNE
        | IF_ICMPLT | IF_ICMPGE | IF_ICMPGT | IF_ICMPLE | IF_ACMPEQ | IF_ACMPNE | IFNULL
        | IFNONNULL => index == 0,
        TABLESWITCH => index == 2 || index >= 3,
        LOOKUPSWITCH => index == 1 || (index >= 3 && index % 2 == 1),
        _ => false,
    }
}

fn decode_instruction_targets(
    program: &mut VmProgram,
    seed: u32,
    instruction_count: usize,
) -> Result<(), VmError> {
    for instruction in &program.instructions {
        for index in instruction.operand_range.clone() {
            let operand_index = index - instruction.operand_range.start;
            if is_target_operand(instruction.opcode, operand_index) {
                let encoded = program.operands[index];
                let decoded_target = match cfg_decode(seed, instruction_count, encoded) {
                    Ok(value) => value,
                    Err(error) => {
                        return Err(error);
                    }
                };
                program.operands[index] = decoded_target as i32;
                if program.operands[index] as usize >= instruction_count {
                    return Err(VmError::InvalidControlFlow);
                }
            }
        }
    }
    Ok(())
}

fn parse_exception_section(
    bytes: &[u8],
    limits: ParserLimits,
    session_material: &[u8; 32],
    seed: u32,
) -> Result<Vec<EncodedException>, VmError> {
    let mut cursor = Cursor::new(bytes);
    let count = usize::from(cursor.read_u16_be()?);
    if count > limits.max_exceptions {
        return Err(VmError::LengthTooLarge {
            field: "exception count",
            length: count,
            maximum: limits.max_exceptions,
        });
    }
    let mut output = Vec::with_capacity(count);
    for index in 0..count {
        let token = cursor.read_u32_be()?;
        let expected = exception_token(session_material, seed, index);
        if token != expected {
            return Err(VmError::InvalidException("exception token is invalid"));
        }
        let raw_start = cursor.read_u16_be()?;
        let raw_end = cursor.read_u16_be()?;
        let raw_handler = cursor.read_u16_be()?;
        let start = raw_start ^ exception_mask(session_material, seed, index, 0, expected);
        let end = raw_end ^ exception_mask(session_material, seed, index, 1, expected);
        let handler = raw_handler ^ exception_mask(session_material, seed, index, 2, expected);
        let type_cp =
            cursor.read_u16_be()? ^ exception_mask(session_material, seed, index, 3, expected);
        output.push(EncodedException {
            start,
            end,
            handler,
            type_cp,
        });
    }
    cursor.require_empty()?;
    Ok(output)
}

fn exception_token(session_material: &[u8; 32], seed: u32, index: usize) -> u32 {
    let index_bytes = (index as u32).to_be_bytes();
    let digest = vbc4_hmac(
        session_material,
        seed,
        &[&index_bytes],
        b"vbc4-exception-token",
    );
    u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]])
}

fn exception_mask(
    session_material: &[u8; 32],
    seed: u32,
    index: usize,
    field: u32,
    token: u32,
) -> u16 {
    let index_bytes = (index as u32).to_be_bytes();
    let field_bytes = field.to_be_bytes();
    let token_bytes = token.to_be_bytes();
    let digest = vbc4_hmac(
        session_material,
        seed,
        &[&index_bytes, &field_bytes, &token_bytes],
        b"vbc4-exception-mask",
    );
    // Kotlin's readMacInt(material) takes the first four bytes as a big-endian
    // Int and then masks with 0xFFFF, i.e. the low two bytes (digest[2..4]).
    u16::from_be_bytes([digest[2], digest[3]])
}

fn decode_exceptions(
    encoded: Vec<EncodedException>,
    instruction_count: usize,
    constant_count: usize,
    seed: u32,
) -> Result<Vec<ExceptionHandler>, VmError> {
    let mut output = Vec::with_capacity(encoded.len());
    for entry in encoded {
        let start = cfg_decode(seed, instruction_count, i32::from(entry.start))?;
        let end = cfg_decode(seed, instruction_count, i32::from(entry.end))?;
        let handler = cfg_decode(seed, instruction_count, i32::from(entry.handler))?;
        if start >= end || end > instruction_count || handler >= instruction_count {
            return Err(VmError::InvalidException("exception range is invalid"));
        }
        let type_cp = if entry.type_cp == 0 {
            None
        } else {
            let index = usize::from(entry.type_cp - 1);
            if index >= constant_count {
                return Err(VmError::InvalidException(
                    "exception type constant is out of range",
                ));
            }
            Some(index)
        };
        output.push(ExceptionHandler {
            start,
            end,
            handler,
            type_cp,
        });
    }
    Ok(output)
}

fn parse_metadata(
    constants: &[VmConstant],
    metadata_cp_index: usize,
    nested_profile: u32,
) -> Result<VmMetadata, VmError> {
    let text = constants
        .get(metadata_cp_index)
        .and_then(VmConstant::as_string)
        .ok_or(VmError::InvalidMetadata(
            "metadata constant is not a string",
        ))?;
    if text.len() > VBC4_MAX_METADATA_SIZE {
        return Err(VmError::LengthTooLarge {
            field: "metadata",
            length: text.len(),
            maximum: VBC4_MAX_METADATA_SIZE,
        });
    }
    let fields: Vec<&str> = text.split('|').collect();
    if fields.len() != 10 {
        return Err(VmError::InvalidMetadata("metadata field count is invalid"));
    }
    let entry_token =
        parse_hex_u64(fields[0]).ok_or(VmError::InvalidMetadata("entry token is invalid"))?;
    let return_tag = fields[1]
        .as_bytes()
        .first()
        .copied()
        .filter(|_| fields[1].len() == 1)
        .ok_or(VmError::InvalidMetadata("return tag is invalid"))?;
    if !b"VZBCSIJFDL[".contains(&return_tag) {
        return Err(VmError::InvalidMetadata("return tag is invalid"));
    }
    let method_local_profile =
        parse_hex_u32(fields[2]).ok_or(VmError::InvalidMetadata("method profile is invalid"))?;
    let method_identity = parse_hex_digest(fields[3])
        .ok_or(VmError::InvalidMetadata("method identity is invalid"))?;
    let owner_identity =
        parse_hex_digest(fields[4]).ok_or(VmError::InvalidMetadata("owner identity is invalid"))?;
    if !fields[5].bytes().all(|byte| b"ZBCSIJFDL[".contains(&byte)) {
        return Err(VmError::InvalidMetadata("argument tags are invalid"));
    }
    if fields[6].is_empty()
        || fields[6].len() > VBC4_MAX_STATE_BINDING
        || fields[6].bytes().any(|byte| byte == 0)
    {
        return Err(VmError::InvalidMetadata("resource path is invalid"));
    }
    let is_static = match fields[7] {
        "0" => false,
        "1" => true,
        _ => return Err(VmError::InvalidMetadata("static flag is invalid")),
    };
    let native_vm_profile_id =
        parse_hex_u32(fields[8]).ok_or(VmError::InvalidMetadata("native profile is invalid"))?;
    let dispatch_profile_tag =
        parse_hex_u32(fields[9]).ok_or(VmError::InvalidMetadata("dispatch profile is invalid"))?;
    if dispatch_profile_tag == 0
        || nested_profile != 0
            && (method_local_profile == 0 || nested_profile != method_local_profile)
    {
        return Err(VmError::InvalidMetadata("profile binding is invalid"));
    }
    Ok(VmMetadata {
        entry_token,
        return_tag,
        method_local_profile,
        method_identity,
        owner_identity,
        argument_tags: fields[5].as_bytes().to_vec(),
        resource_path: VmString::from_string(fields[6].to_owned()),
        is_static,
        native_vm_profile_id,
        dispatch_profile_tag,
    })
}

fn parse_hex_u32(value: &str) -> Option<u32> {
    if value.is_empty() || value.len() > 8 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    u32::from_str_radix(value, 16).ok()
}

fn parse_hex_u64(value: &str) -> Option<u64> {
    if value.is_empty() || value.len() > 16 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(value, 16).ok()
}

fn parse_hex_digest(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut digest = [0u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        digest[index] = (hex_digit(chunk[0])? << 4) | hex_digit(chunk[1])?;
    }
    Some(digest)
}

fn hex_digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

pub struct ProgramBuilder {
    constants: Vec<VmConstant>,
    instructions: Vec<(u16, u16, Vec<i32>)>,
    exceptions: Vec<ExceptionHandler>,
    max_stack: usize,
    max_locals: usize,
}

impl ProgramBuilder {
    pub fn new() -> Self {
        Self {
            constants: Vec::new(),
            instructions: Vec::new(),
            exceptions: Vec::new(),
            max_stack: 64,
            max_locals: 16,
        }
    }

    pub fn constant_string(mut self, value: impl Into<String>) -> Self {
        self.constants
            .push(VmConstant::String(VmString::from_string(value.into())));
        self
    }

    pub fn constant_int(mut self, value: i32) -> Self {
        self.constants.push(VmConstant::Int(value));
        self
    }

    pub fn constant_long(mut self, value: i64) -> Self {
        self.constants.push(VmConstant::Long(value));
        self
    }

    pub fn constant_float(mut self, value: f32) -> Self {
        self.constants.push(VmConstant::Float(value));
        self
    }

    pub fn constant_double(mut self, value: f64) -> Self {
        self.constants.push(VmConstant::Double(value));
        self
    }

    pub fn instruction(mut self, opcode: u16, operands: &[i32]) -> Self {
        self.instructions.push((opcode, 0, operands.to_vec()));
        self
    }

    pub fn instruction_with_flags(mut self, opcode: u16, flags: u16, operands: &[i32]) -> Self {
        self.instructions.push((opcode, flags, operands.to_vec()));
        self
    }

    pub fn exception(
        mut self,
        start: usize,
        end: usize,
        handler: usize,
        type_cp: Option<usize>,
    ) -> Self {
        self.exceptions.push(ExceptionHandler {
            start,
            end,
            handler,
            type_cp,
        });
        self
    }

    pub fn max_stack(mut self, value: usize) -> Self {
        self.max_stack = value;
        self
    }

    pub fn max_locals(mut self, value: usize) -> Self {
        self.max_locals = value;
        self
    }

    pub fn finish(self) -> VmProgram {
        let mut operands = Vec::new();
        let mut instructions = Vec::with_capacity(self.instructions.len());
        for (opcode, flags, values) in self.instructions {
            add_instruction(&mut instructions, &mut operands, opcode, flags, &values);
        }
        VmProgram {
            constants: self.constants,
            instructions,
            operands,
            exceptions: self.exceptions,
            metadata: VmMetadata {
                entry_token: 1,
                return_tag: b'V',
                method_local_profile: 0,
                method_identity: [0; 32],
                owner_identity: [0; 32],
                argument_tags: Vec::new(),
                resource_path: VmString::from_string(String::new()),
                is_static: true,
                native_vm_profile_id: 0,
                dispatch_profile_tag: 1,
            },
            metadata_cp_index: 0,
            register_count: 1,
            max_stack: self.max_stack.max(1),
            max_locals: self.max_locals.max(1),
            flags: 0,
            nonce: [0; 16],
            seed: 0,
        }
    }
}

impl Default for ProgramBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Encode a current VBC4 frame whose program is `iconst 7; ireturn`.
pub fn encode_iconst7_frame(material: &VmKeyMaterial) -> Result<Vec<u8>, VmError> {
    fn push_u16(output: &mut Vec<u8>, value: u16) {
        output.extend_from_slice(&value.to_be_bytes());
    }
    fn push_u32(output: &mut Vec<u8>, value: u32) {
        output.extend_from_slice(&value.to_be_bytes());
    }
    fn row(
        session: &[u8; 32],
        seed: u32,
        opcode: u16,
        index: usize,
        dst: u16,
        operand: i32,
        dialect: &dialect::VmDialect,
    ) -> [u8; 14] {
        let masked = dialect.encode(opcode) ^ u16::from(opcode_mask(session, seed, index));
        let mut output = [0u8; 14];
        output[0..2].copy_from_slice(&masked.to_be_bytes());
        output[2..4].copy_from_slice(&REG_EXECUTABLE.to_be_bytes());
        output[4..6].copy_from_slice(&dst.to_be_bytes());
        output[6..8].copy_from_slice(&0u16.to_be_bytes());
        output[8..10].copy_from_slice(&0u16.to_be_bytes());
        output[10..14].copy_from_slice(&(operand as u32).to_be_bytes());
        output
    }

    let dialect = dialect::VmDialect::from_material(
        material.crypto_domain_material(),
        material.layout_digest(),
    )?;
    let mut state_binding = iconst7_frame_state_binding(material);
    let session = vbc4_session_material(
        material.crypto_domain_material(),
        material.layout_digest(),
        &state_binding,
    );
    let seed = 0x1020_3040u32;
    let nonce = [0x33; 16];
    let build_key = vm_build_key(material.crypto_domain_material(), material.layout_digest())
        .map_err(|_| VmError::InvalidHeader("vm build key"))?;
    let identity = "0".repeat(64);
    let metadata = format!("1|I|0|{identity}|{identity}||resource|1|0|1");
    let string_nonce = [0x44; 16];
    let (string_key, string_iv) = crypto::cp_string_material(
        &build_key,
        b"javashroud-vbc4-cp-string-key-v2",
        b"javashroud-vbc4-cp-string-iv-v2",
        &string_nonce,
    );
    let ciphertext = aes128_ctr(&string_key, &string_iv, metadata.as_bytes(), 0xffff)
        .map_err(|_| VmError::InvalidHeader("cp string cipher"))?;
    let tag = crypto::hmac_bytes(
        &build_key,
        &[
            b"javashroud-vbc4-cp-string-tag-v2",
            &string_nonce,
            &ciphertext,
        ],
    );
    let mut entry_plain = vec![CP_SEALED_STRING];
    entry_plain.extend_from_slice(&string_nonce);
    push_u16(&mut entry_plain, ciphertext.len() as u16);
    entry_plain.extend_from_slice(&ciphertext);
    entry_plain.extend_from_slice(&tag);
    let (entry_key, entry_iv) =
        vbc4_aes_material(&session, &nonce, seed, SECTION_CONSTANT_POOL_ENTRY, 0);
    let entry_cipher = aes128_ctr(&entry_key, &entry_iv, &entry_plain, VBC4_MAX_SECTION_SIZE)
        .map_err(|_| VmError::InvalidHeader("cp entry cipher"))?;
    let mut cp_container = Vec::new();
    push_u16(&mut cp_container, 1);
    push_u32(&mut cp_container, entry_plain.len() as u32);
    push_u32(&mut cp_container, entry_plain.len() as u32);
    push_u32(&mut cp_container, entry_cipher.len() as u32);
    cp_container.extend_from_slice(&entry_cipher);
    let (cp_key, cp_iv) = vbc4_aes_material(&session, &nonce, seed, SECTION_CONSTANT_POOL, 0);
    let cp_cipher = aes128_ctr(&cp_key, &cp_iv, &cp_container, VBC4_MAX_SECTION_SIZE)
        .map_err(|_| VmError::InvalidHeader("cp cipher"))?;

    let mut block_plain = Vec::new();
    push_u16(&mut block_plain, 1);
    push_u16(&mut block_plain, 4);
    block_plain.extend_from_slice(&row(&session, seed, REG_META, 0, 0, 0, &dialect));
    block_plain.extend_from_slice(&row(&session, seed, ICONST, 1, 1, 7, &dialect));
    block_plain.extend_from_slice(&row(&session, seed, IRETURN, 2, 0, 0, &dialect));
    block_plain.extend_from_slice(&row(&session, seed, MAXS, 3, 0, 0, &dialect));
    push_u16(&mut block_plain, 0);
    let (block_key, block_iv) = vbc4_aes_material(&session, &nonce, seed, SECTION_INSTRUCTIONS, 0);
    let block_cipher = aes128_ctr(&block_key, &block_iv, &block_plain, VBC4_MAX_SECTION_SIZE)
        .map_err(|_| VmError::InvalidHeader("block cipher"))?;

    let mut exception_plain = Vec::new();
    push_u16(&mut exception_plain, 0);
    let (exception_key, exception_iv) =
        vbc4_aes_material(&session, &nonce, seed, SECTION_EXCEPTIONS, 0);
    let exception_cipher = aes128_ctr(
        &exception_key,
        &exception_iv,
        &exception_plain,
        VBC4_MAX_SECTION_SIZE,
    )
    .map_err(|_| VmError::InvalidHeader("exception cipher"))?;
    let dispatch_state = dispatch_state_candidates(seed, 0, 1, 1);
    let dispatch_mask = seed.rotate_left(7) ^ 0x119d_e1f3;
    let dispatch_token = ((u32::from(dispatch_state) << 16) | 1) ^ dispatch_mask;
    let flags = REQUIRED_FLAGS | FLAG_POLYMORPHIC_CP;
    let wrapped_mask = vbc4_hmac(
        &session,
        0,
        &[&nonce, &state_binding],
        b"vbc4-seed-wrap",
    );
    let token = vbc4_hmac(
        &session,
        seed,
        &[&nonce, &state_binding],
        b"vbc4-seed-token",
    );
    let seed_bytes = seed.to_be_bytes();
    let mut wrapped = [0u8; 16];
    for index in 0..4 {
        wrapped[index] = seed_bytes[index] ^ wrapped_mask[index];
    }
    wrapped[4..].copy_from_slice(&token[..12]);
    let key_id = key_id_for(&session, seed, &nonce);
    let mut body = Vec::new();
    body.extend_from_slice(&VBC4_MAGIC);
    body.extend_from_slice(&nonce);
    body.extend_from_slice(&dialect.commitment);
    push_u32(&mut body, key_id);
    body.extend_from_slice(&wrapped);
    push_u16(&mut body, flags);
    push_u16(&mut body, 1);
    push_u32(&mut body, cp_container.len() as u32);
    push_u32(&mut body, cp_cipher.len() as u32);
    body.extend_from_slice(&cp_cipher);
    push_u16(&mut body, 0);
    push_u32(&mut body, 0);
    push_u32(&mut body, dispatch_token);
    push_u32(&mut body, block_plain.len() as u32);
    push_u32(&mut body, block_cipher.len() as u32);
    push_u32(&mut body, block_cipher.len() as u32);
    body.extend_from_slice(&block_cipher);
    push_u32(&mut body, exception_plain.len() as u32);
    push_u32(&mut body, exception_cipher.len() as u32);
    push_u32(&mut body, exception_cipher.len() as u32);
    body.extend_from_slice(&exception_cipher);
    push_u32(&mut body, 8);
    body.extend_from_slice(&[0; 8]);
    let mac = vbc4_hmac_fields(&session, seed, &[&nonce, &body]);
    body.extend_from_slice(&mac);
    state_binding.fill(0);
    Ok(body)
}

/// State binding used by [`encode_iconst7_frame`].  The helper exists solely
/// for current-format Rust integration fixtures; production callers receive a
/// route-bound value from the sealed native bridge.
pub fn iconst7_frame_state_binding(material: &VmKeyMaterial) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut binding = Vec::with_capacity(1 + 1 + 8 + 1 + 8 + 1 + 64);
    binding.extend_from_slice(b"1");
    binding.push(0);
    binding.extend_from_slice(b"resource");
    binding.push(0);
    binding.extend_from_slice(VBC4_CLEAN_ENTRY_INTEGRITY_HEX);
    binding.push(0);
    for byte in material.layout_digest() {
        binding.push(HEX[usize::from(byte >> 4)]);
        binding.push(HEX[usize::from(byte & 0x0f)]);
    }
    binding
}

#[cfg(test)]
mod parser_tests {
    use super::*;
    use crate::executor::NoObjectOperations;

    fn valid_frame() -> (VmKeyMaterial, Vec<u8>, Vec<u8>) {
        let material = VmKeyMaterial::new([0x11; 32], [0x22; 32]);
        let body = encode_iconst7_frame(&material).expect("encode");
        let binding = iconst7_frame_state_binding(&material);
        (material, body, binding)
    }

    #[test]
    fn current_vbc4_frame_authenticates_and_executes() {
        let (material, frame, binding) = valid_frame();
        let parser = VmParser::new(&material, &binding).expect("parser");
        let program = parser.parse(&frame).expect("VBC4");
        assert_eq!(program.metadata().resource_path.as_str(), "resource");
        assert_eq!(program.instructions().len(), 3);
        let mut executor = VmExecutor::new(NoObjectOperations);
        assert_eq!(executor.execute(&program, &[]), Ok(VmValue::Int(7)));
    }

    #[test]
    fn vm_dialect_differs_across_materials_and_round_trips() {
        let first = dialect::VmDialect::from_material(&[0x11; 32], &[0x22; 32]).expect("first");
        let second = dialect::VmDialect::from_material(&[0x33; 32], &[0x22; 32]).expect("second");
        assert_ne!(first.encode(ICONST), second.encode(ICONST));
        assert_ne!(first.commitment, second.commitment);
        assert_eq!(first.decode(first.encode(ICONST)), ICONST);
        assert_eq!(first.decode(first.encode(IADD)), IADD);
        assert_eq!(first.decode(first.encode(SUPER_INT_ARITH)), SUPER_INT_ARITH);
        assert!(first.fused_opcode >= 0x100);
        assert_eq!(first.encode(ICONST), 0x53);
        assert_eq!(first.encode(IADD), 0x5f);
        assert_eq!(first.encode(IRETURN), 0x44);
        assert_eq!(first.encode(REG_META), 0xf3);
    }

    #[test]
    fn foreign_dialect_material_fails_closed_on_current_frame() {
        let (material, frame, binding) = valid_frame();
        let foreign = VmKeyMaterial::new([0x44; 32], [0x22; 32]);
        let parser = VmParser::new(&foreign, &binding).expect("parser");
        assert!(parser.parse(&frame).is_err());
        let _ = material;
    }

    #[test]
    fn authentication_precedes_semantic_parsing_and_truncation_is_rejected() {
        let (material, frame, binding) = valid_frame();
        let parser = VmParser::new(&material, &binding).expect("parser");
        for end in 0..frame.len() {
            assert!(
                parser.parse(&frame[..end]).is_err(),
                "accepted truncated frame at {end}"
            );
        }
        let mut tampered = frame;
        tampered[VBC4_HEADER_SIZE] ^= 1;
        assert!(matches!(
            parser.parse(&tampered),
            Err(VmError::AuthenticationFailed)
        ));
    }

    #[test]
    fn dialect_commitment_mismatch_fails_before_semantic_parsing() {
        let (material, mut frame, binding) = valid_frame();
        frame[20] ^= 1;
        let parser = VmParser::new(&material, &binding).expect("parser");
        assert!(matches!(
            parser.parse(&frame),
            Err(VmError::DialectCommitmentMismatch)
        ));
    }

    #[test]
    fn state_binding_mismatch_fails_closed() {
        let (material, frame, mut binding) = valid_frame();
        binding[0] ^= 1;
        let parser = VmParser::new(&material, &binding).expect("parser");
        assert!(matches!(parser.parse(&frame), Err(VmError::InvalidSeed)));
    }
}
