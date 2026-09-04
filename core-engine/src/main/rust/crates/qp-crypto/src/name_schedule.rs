//! Build-local derived names. Role constants stay in this module.

use crate::{hmac_sha256, DIGEST_SIZE};

pub const QP_SCHEDULE_VERSION: u8 = 2;
pub const QP_NAME_SEED_SIZE: usize = 16;
pub const QP_COMMITMENT_SIZE: usize = 32;
pub const QP_INFO_PREFIX: u8 = 0x51;

pub const ROLE_FRAME: u8 = 0x11;
pub const ROLE_DIRECTORY: u8 = 0x12;
pub const ROLE_RESOURCE: u8 = 0x13;
pub const ROLE_TOKEN: u8 = 0x14;
pub const ROLE_NATIVE: u8 = 0x15;
pub const ROLE_TEXT: u8 = 0x16;
pub const ROLE_CLASS: u8 = 0x17;
pub const ROLE_VM: u8 = 0x18;
pub const ROLE_DEBUG: u8 = 0x19;
pub const ROLE_ROOT: u8 = 0x1A;
pub const ROLE_JNI: u8 = 0x1B;
pub const ROLE_CRYPTO: u8 = 0x1C;

pub const LANE_RUNTIME_BINDING: u8 = 0;
pub const LANE_FRAME_AUTH: u8 = 1;
pub const LANE_DIR_RUNTIME: u8 = 2;
pub const LANE_DIR_RECORD: u8 = 3;
pub const LANE_DIR_ROOT: u8 = 4;
pub const LANE_RESOURCE_DIR: u8 = 5;
pub const LANE_RESOURCE_FRAME: u8 = 6;
pub const LANE_DEFENSE: u8 = 7;
pub const LANE_SPECIALIZATION: u8 = 8;
pub const LANE_TOKEN_AAD: u8 = 9;
pub const LANE_TOKEN_KEY: u8 = 10;
pub const LANE_RESOURCE_AUTH: u8 = 11;

pub const FORMAT_VERSION: u8 = 5;

pub const TEST_NAME_SEED: [u8; QP_NAME_SEED_SIZE] =
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
pub const TEST_COMMITMENT: [u8; QP_COMMITMENT_SIZE] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];
pub const RETIRED_FRAME_MAGIC: [u8; 4] = [0x4a, 0x53, 0x52, 0x31];
pub const RETIRED_VM_MAGIC: [u8; 4] = [0x56, 0x42, 0x43, 0x35];
pub const RETIRED_TOKEN_MAGIC: [u8; 4] = [0x49, 0x54, 0x4b, 0x31];

struct InstalledSchedule {
    seed: [u8; QP_NAME_SEED_SIZE],
    commitment: [u8; QP_COMMITMENT_SIZE],
    version: u8,
}

static INSTALLED: std::sync::Mutex<Option<InstalledSchedule>> = std::sync::Mutex::new(None);

pub fn install_name_schedule(
    seed: &[u8],
    commitment: &[u8],
    version: u8,
) -> Result<(), NameScheduleError> {
    let schedule = QpNameSchedule::new(seed, commitment, version)?;
    drop(schedule);
    let mut stored_seed = [0u8; QP_NAME_SEED_SIZE];
    let mut stored_commitment = [0u8; QP_COMMITMENT_SIZE];
    stored_seed.copy_from_slice(seed);
    stored_commitment.copy_from_slice(commitment);
    *INSTALLED.lock().expect("name schedule lock") = Some(InstalledSchedule {
        seed: stored_seed,
        commitment: stored_commitment,
        version,
    });
    Ok(())
}

pub fn active_name_schedule() -> Result<QpNameSchedule, NameScheduleError> {
    let guard = INSTALLED.lock().expect("name schedule lock");
    match &*guard {
        Some(installed) => QpNameSchedule::new(&installed.seed, &installed.commitment, installed.version),
        None => QpNameSchedule::new(&TEST_NAME_SEED, &TEST_COMMITMENT, QP_SCHEDULE_VERSION),
    }
}

pub fn derived_frame_magic() -> Result<[u8; 4], NameScheduleError> {
    active_name_schedule()?.derive_magic(ROLE_FRAME, 0, 0)
}

pub fn derived_vm_magic() -> Result<[u8; 4], NameScheduleError> {
    vm_name_schedule()?.derive_magic(ROLE_VM, 0, 0)
}

fn vm_name_schedule() -> Result<QpNameSchedule, NameScheduleError> {
    let seed = match &*INSTALLED.lock().expect("name schedule lock") {
        Some(installed) => installed.seed,
        None => TEST_NAME_SEED,
    };
    let mut salt = [0u8; QP_COMMITMENT_SIZE];
    salt[..QP_NAME_SEED_SIZE].copy_from_slice(&seed);
    salt[QP_NAME_SEED_SIZE..].copy_from_slice(&seed);
    QpNameSchedule::new(&seed, &salt, QP_SCHEDULE_VERSION)
}

pub fn derived_token_magic() -> Result<[u8; 4], NameScheduleError> {
    active_name_schedule()?.derive_magic(ROLE_TOKEN, 0, 0)
}

pub fn derived_runtime_binding_domain() -> Result<[u8; 16], NameScheduleError> {
    active_name_schedule()?.derive_domain(ROLE_CRYPTO, LANE_RUNTIME_BINDING, 0)
}

pub fn derived_frame_auth_domain() -> Result<[u8; 16], NameScheduleError> {
    active_name_schedule()?.derive_domain(ROLE_CRYPTO, LANE_FRAME_AUTH, 0)
}

const URL_SAFE: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const RESOURCE_ROOT_BYTES: usize = 9;
const JNI_NAME_MIN: usize = 8;
const JNI_NAME_MAX: usize = 12;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum NameScheduleError {
    InvalidSeedLength { actual: usize },
    InvalidCommitmentLength { actual: usize },
    InvalidLength { actual: usize },
}

#[derive(Clone)]
pub struct QpNameSchedule {
    name_seed: [u8; QP_NAME_SEED_SIZE],
    artifact_commitment: [u8; QP_COMMITMENT_SIZE],
    schedule_version: u8,
}

impl QpNameSchedule {
    pub fn new(
        name_seed: &[u8],
        artifact_commitment: &[u8],
        schedule_version: u8,
    ) -> Result<Self, NameScheduleError> {
        if name_seed.len() != QP_NAME_SEED_SIZE {
            return Err(NameScheduleError::InvalidSeedLength {
                actual: name_seed.len(),
            });
        }
        if artifact_commitment.len() != QP_COMMITMENT_SIZE {
            return Err(NameScheduleError::InvalidCommitmentLength {
                actual: artifact_commitment.len(),
            });
        }
        let mut seed = [0u8; QP_NAME_SEED_SIZE];
        let mut commitment = [0u8; QP_COMMITMENT_SIZE];
        seed.copy_from_slice(name_seed);
        commitment.copy_from_slice(artifact_commitment);
        Ok(Self {
            name_seed: seed,
            artifact_commitment: commitment,
            schedule_version,
        })
    }

    pub fn schedule_version(&self) -> u8 {
        self.schedule_version
    }

    pub fn derive(
        &self,
        role_id: u8,
        lane_id: u8,
        ordinal: u32,
        length: usize,
    ) -> Result<Vec<u8>, NameScheduleError> {
        let mut info = [
            QP_INFO_PREFIX,
            self.schedule_version,
            role_id,
            lane_id,
            0,
            0,
            0,
            0,
        ];
        info[4..8].copy_from_slice(&ordinal.to_be_bytes());
        let derived = hkdf_sha256(&self.name_seed, &self.artifact_commitment, &info, length)?;
        info.fill(0);
        Ok(derived)
    }

    pub fn derive_magic(
        &self,
        role_id: u8,
        lane_id: u8,
        ordinal: u32,
    ) -> Result<[u8; 4], NameScheduleError> {
        let raw = self.derive(role_id, lane_id, ordinal, DIGEST_SIZE)?;
        let mut magic = [0u8; 4];
        magic.copy_from_slice(&raw[..4]);
        Ok(magic)
    }

    pub fn derive_domain(
        &self,
        role_id: u8,
        lane_id: u8,
        ordinal: u32,
    ) -> Result<[u8; 16], NameScheduleError> {
        let raw = self.derive(role_id, lane_id, ordinal, DIGEST_SIZE)?;
        let mut domain = [0u8; 16];
        domain.copy_from_slice(&raw[..16]);
        Ok(domain)
    }

    pub fn derive_resource_root(
        &self,
        lane_id: u8,
        ordinal: u32,
    ) -> Result<String, NameScheduleError> {
        let raw = self.derive(ROLE_ROOT, lane_id, ordinal, DIGEST_SIZE)?;
        Ok(encode_url_safe(&raw[..RESOURCE_ROOT_BYTES]))
    }

    pub fn derive_page_path_token(
        &self,
        role_id: u8,
        page_index: u8,
        ordinal: u32,
    ) -> Result<String, NameScheduleError> {
        let raw = self.derive(role_id, page_index, ordinal, DIGEST_SIZE)?;
        Ok(encode_url_safe(&raw[..RESOURCE_ROOT_BYTES]))
    }

    pub fn derive_jni_name(&self, lane_id: u8, ordinal: u32) -> Result<String, NameScheduleError> {
        let raw = self.derive(ROLE_JNI, lane_id, ordinal, DIGEST_SIZE)?;
        let n = JNI_NAME_MIN + (raw[0] as usize % (JNI_NAME_MAX - JNI_NAME_MIN + 1));
        let mut name = String::with_capacity(1 + n);
        name.push('q');
        for index in 0..n {
            let ch = b'a' + (raw[index + 1] % 26);
            name.push(char::from(ch));
        }
        Ok(name)
    }

    pub fn wipe(&mut self) {
        self.name_seed.fill(0);
        self.artifact_commitment.fill(0);
    }
}

impl Drop for QpNameSchedule {
    fn drop(&mut self) {
        self.wipe();
    }
}

pub fn hkdf_sha256(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    length: usize,
) -> Result<Vec<u8>, NameScheduleError> {
    if length == 0 || length > 255 * DIGEST_SIZE {
        return Err(NameScheduleError::InvalidLength { actual: length });
    }
    let zero_salt = [0u8; DIGEST_SIZE];
    let extract_key: &[u8] = if salt.is_empty() { &zero_salt } else { salt };
    let mut prk = hmac_sha256(extract_key, &[ikm]).into_bytes();
    let mut output = Vec::with_capacity(length);
    let mut previous = [0u8; DIGEST_SIZE];
    let mut has_previous = false;
    let mut counter = 1u8;
    while output.len() < length {
        let block = if has_previous {
            hmac_sha256(&prk, &[&previous, info, &[counter]]).into_bytes()
        } else {
            hmac_sha256(&prk, &[info, &[counter]]).into_bytes()
        };
        previous = block;
        has_previous = true;
        let take = (length - output.len()).min(DIGEST_SIZE);
        output.extend_from_slice(&previous[..take]);
        counter = counter.wrapping_add(1);
    }
    prk.fill(0);
    previous.fill(0);
    Ok(output)
}

fn encode_url_safe(raw: &[u8]) -> String {
    let bit_count = raw.len() * 8;
    let char_count = (bit_count + 5) / 6;
    let mut chars = String::with_capacity(char_count);
    let mut bit_buffer: u32 = 0;
    let mut bits = 0u32;
    for &byte in raw {
        bit_buffer = (bit_buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 6 {
            bits -= 6;
            let index = ((bit_buffer >> bits) & 0x3f) as usize;
            chars.push(char::from(URL_SAFE[index]));
        }
    }
    if bits > 0 {
        let index = ((bit_buffer << (6 - bits)) & 0x3f) as usize;
        chars.push(char::from(URL_SAFE[index]));
    }
    chars
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> QpNameSchedule {
        let seed: Vec<u8> = (0u8..16).collect();
        let commit: Vec<u8> = (32u8..64).collect();
        QpNameSchedule::new(&seed, &commit, QP_SCHEDULE_VERSION).expect("fixture")
    }

    #[test]
    fn kotlin_parity_vectors() {
        let schedule = fixture();
        assert_eq!(
            schedule
                .derive_magic(ROLE_FRAME, 0, 0)
                .expect("frame")
                .as_slice(),
            &hex("c444fd0b")
        );
        assert_eq!(
            schedule
                .derive_domain(ROLE_CRYPTO, 1, 0)
                .expect("crypto")
                .as_slice(),
            &hex("b77c46797eeebbe0fe19d82e58a2b24b")
        );
        assert_eq!(
            schedule
                .derive_domain(ROLE_DIRECTORY, 0, 0)
                .expect("directory")
                .as_slice(),
            &hex("26e3cd817882d394bc071f2669c467d3")
        );
        assert_eq!(
            schedule
                .derive_domain(ROLE_TOKEN, 2, 0)
                .expect("token")
                .as_slice(),
            &hex("94c8b4b1d7e6b18090cafc75658c27c7")
        );
        assert_eq!(
            schedule.derive_resource_root(0, 0).expect("root"),
            "2BVHBcHeWtGD"
        );
        assert_eq!(
            schedule.derive_jni_name(0, 0).expect("jni"),
            "qchmbfhvjdx"
        );
        assert_eq!(
            schedule
                .derive_page_path_token(ROLE_RESOURCE, 7, 0)
                .expect("page"),
            "d-rmCtejnK9C"
        );
    }

    #[test]
    fn different_seeds_diverge() {
        let left = fixture();
        let mut seed: Vec<u8> = (0u8..16).collect();
        seed[0] ^= 1;
        let commit: Vec<u8> = (32u8..64).collect();
        let right = QpNameSchedule::new(&seed, &commit, QP_SCHEDULE_VERSION).expect("right");
        assert_ne!(
            left.derive_magic(ROLE_FRAME, 0, 0).unwrap(),
            right.derive_magic(ROLE_FRAME, 0, 0).unwrap()
        );
        assert_ne!(
            left.derive_jni_name(0, 0).unwrap(),
            right.derive_jni_name(0, 0).unwrap()
        );
        assert_ne!(
            left.derive_resource_root(0, 0).unwrap(),
            right.derive_resource_root(0, 0).unwrap()
        );
    }

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&text[index..index + 2], 16).expect("hex"))
            .collect()
    }
}
