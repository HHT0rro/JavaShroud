use crate::{sha256, Digest, PageError, DIGEST_SIZE};

const LANE_COUNT: usize = 8;
const WORD_FAMILY_COUNT: u8 = 8;
const PAGE_NONCE_SIZE: usize = 12;
const PLAN_NONCE_SIZE: usize = 16;
const LANE_SALT_SIZE: usize = 16;
const LANE_TAG_SIZE: usize = 16;
const PLAN_TAG_SIZE: usize = 32;
const MIN_TOKEN_SIZE: usize = 17;
const MAX_TOKEN_SIZE: usize = 48;
const STATIC_BINDING_DOMAIN: &[u8] = b"bound-page-static";
const LANE_MASK_DOMAIN: &[u8] = b"bound-page-lane-mask";
const LANE_TAG_DOMAIN: &[u8] = b"bound-page-lane-tag";
const PLAN_TAG_DOMAIN: &[u8] = b"bound-page-plan-tag";

pub fn recover_bound_page_dek(opaque: &[u8]) -> Result<[u8; DIGEST_SIZE], PageError> {
    let parsed = parse(opaque)?;
    let mut dek = [0u8; DIGEST_SIZE];
    for lane in &parsed.lanes {
        let mask = lane_mask(
            &parsed.static_binding,
            lane.word_index,
            lane.family,
            &lane.token,
            &lane.salt,
        );
        let word = decode_word(lane.encoded_word, mask, lane.family, lane.word_index)?;
        let offset = usize::from(lane.word_index) * 4;
        dek[offset..offset + 4].copy_from_slice(&word.to_be_bytes());
    }
    Ok(dek)
}

struct Lane {
    word_index: u8,
    family: u8,
    token: Vec<u8>,
    salt: [u8; LANE_SALT_SIZE],
    encoded_word: i32,
}

struct Parsed {
    static_binding: [u8; DIGEST_SIZE],
    lanes: Vec<Lane>,
}

fn parse(opaque: &[u8]) -> Result<Parsed, PageError> {
    if opaque.len() < minimum_encoded_size() || opaque.len() > 128 * 1024 {
        return Err(PageError::InvalidInput("bound decryptor length is invalid"));
    }
    let mut cursor = Cursor::new(opaque);
    let _dispatch = cursor.read_u8()?;
    if cursor.read_u8()? != LANE_COUNT as u8 {
        return Err(PageError::InvalidInput("bound lane count is invalid"));
    }
    cursor.skip(PAGE_NONCE_SIZE)?;
    cursor.skip(PLAN_NONCE_SIZE)?;
    let static_binding = cursor.read_fixed::<DIGEST_SIZE>()?;
    cursor.skip(DIGEST_SIZE)?;
    let mut lanes = Vec::with_capacity(LANE_COUNT);
    let mut seen = 0u8;
    for _ in 0..LANE_COUNT {
        let word_index = cursor.read_u8()?;
        let family = cursor.read_u8()?;
        if word_index >= LANE_COUNT as u8 || family >= WORD_FAMILY_COUNT {
            return Err(PageError::InvalidInput("bound lane metadata is invalid"));
        }
        let token = cursor.read_framed(MAX_TOKEN_SIZE)?;
        if token.len() < MIN_TOKEN_SIZE {
            return Err(PageError::InvalidInput("bound lane token is invalid"));
        }
        let salt = cursor.read_fixed::<LANE_SALT_SIZE>()?;
        let encoded_word = cursor.read_i32()?;
        let tag = cursor.read_fixed::<LANE_TAG_SIZE>()?;
        let expected = lane_tag(
            &static_binding,
            word_index,
            family,
            &token,
            &salt,
            encoded_word,
        );
        if !crate::constant_time_equals(&tag, &expected) {
            return Err(PageError::AuthenticationFailed);
        }
        seen |= 1 << word_index;
        lanes.push(Lane {
            word_index,
            family,
            token,
            salt,
            encoded_word,
        });
    }
    if seen != 0xFF {
        return Err(PageError::InvalidInput(
            "bound lanes do not cover the current page",
        ));
    }
    let tag_offset = cursor.offset;
    let plan_tag = cursor.read_fixed::<PLAN_TAG_SIZE>()?;
    cursor.require_empty()?;
    let expected_plan = domain_digest(PLAN_TAG_DOMAIN, &[&opaque[..tag_offset]]);
    if !crate::constant_time_equals(&plan_tag, &expected_plan) {
        return Err(PageError::AuthenticationFailed);
    }
    let _ = STATIC_BINDING_DOMAIN;
    Ok(Parsed {
        static_binding,
        lanes,
    })
}

pub fn wrap_bound_page_dek(
    dek: &[u8; 32],
    static_binding: &[u8; 32],
) -> Result<Vec<u8>, PageError> {
    let mut body = Vec::new();
    body.push(1);
    body.push(LANE_COUNT as u8);
    body.extend_from_slice(&[0x11; PAGE_NONCE_SIZE]);
    body.extend_from_slice(&[0x22; PLAN_NONCE_SIZE]);
    body.extend_from_slice(static_binding);
    body.extend_from_slice(&[0x33; DIGEST_SIZE]);
    for word_index in 0..LANE_COUNT as u8 {
        let family = word_index % WORD_FAMILY_COUNT;
        let token = vec![0xAA; MIN_TOKEN_SIZE];
        let salt = [0xBB; LANE_SALT_SIZE];
        let value = i32::from_be_bytes(
            dek[usize::from(word_index) * 4..usize::from(word_index) * 4 + 4]
                .try_into()
                .expect("word"),
        );
        let mask = lane_mask(static_binding, word_index, family, &token, &salt);
        let encoded_word = encode_word(value, mask, family, word_index)?;
        body.push(word_index);
        body.push(family);
        body.extend_from_slice(&(token.len() as u32).to_be_bytes());
        body.extend_from_slice(&token);
        body.extend_from_slice(&salt);
        body.extend_from_slice(&encoded_word.to_be_bytes());
        body.extend_from_slice(&lane_tag(
            static_binding,
            word_index,
            family,
            &token,
            &salt,
            encoded_word,
        ));
    }
    let tag = domain_digest(PLAN_TAG_DOMAIN, &[&body]);
    body.extend_from_slice(&tag);
    Ok(body)
}

fn lane_mask(
    static_binding: &[u8; DIGEST_SIZE],
    word_index: u8,
    family: u8,
    token: &[u8],
    salt: &[u8],
) -> i32 {
    let digest = domain_digest(
        LANE_MASK_DOMAIN,
        &[
            static_binding,
            &i32::from(word_index).to_be_bytes(),
            &i32::from(family).to_be_bytes(),
            &(token.len() as u32).to_be_bytes(),
            token,
            &(salt.len() as u32).to_be_bytes(),
            salt,
        ],
    );
    i32::from_be_bytes(digest[..4].try_into().expect("mask"))
}

fn lane_tag(
    static_binding: &[u8; DIGEST_SIZE],
    word_index: u8,
    family: u8,
    token: &[u8],
    salt: &[u8],
    encoded_word: i32,
) -> [u8; LANE_TAG_SIZE] {
    let digest = domain_digest(
        LANE_TAG_DOMAIN,
        &[
            static_binding,
            &i32::from(word_index).to_be_bytes(),
            &i32::from(family).to_be_bytes(),
            &(token.len() as u32).to_be_bytes(),
            token,
            &(salt.len() as u32).to_be_bytes(),
            salt,
            &encoded_word.to_be_bytes(),
        ],
    );
    let mut tag = [0u8; LANE_TAG_SIZE];
    tag.copy_from_slice(&digest[..LANE_TAG_SIZE]);
    tag
}

fn encode_word(value: i32, mask: i32, family: u8, word_index: u8) -> Result<i32, PageError> {
    let rotation = rotation(mask, family, word_index);
    let tweak = tweak(mask, family, word_index);
    Ok(match family {
        0 => value ^ mask,
        1 => rotl(value.wrapping_add(mask), rotation),
        2 => rotr(value ^ mask, rotation).wrapping_add(tweak),
        3 => rotl(value.wrapping_add(tweak), rotation) ^ mask,
        4 => rotr(value.wrapping_sub(mask), rotation) ^ tweak,
        5 => (value ^ rotl(mask, u32::from(word_index) + 1)).wrapping_add(0x7F4A_7C15u32 as i32),
        6 => rotl(value ^ tweak, rotation).wrapping_sub(mask),
        7 => rotl(value.wrapping_add(mask), rotation) ^ tweak,
        _ => return Err(PageError::InvalidInput("bound lane family is invalid")),
    })
}

fn decode_word(encoded: i32, mask: i32, family: u8, word_index: u8) -> Result<i32, PageError> {
    let rotation = rotation(mask, family, word_index);
    let tweak = tweak(mask, family, word_index);
    Ok(match family {
        0 => encoded ^ mask,
        1 => rotr(encoded, rotation).wrapping_sub(mask),
        2 => rotl(encoded.wrapping_sub(tweak), rotation) ^ mask,
        3 => rotr(encoded ^ mask, rotation).wrapping_sub(tweak),
        4 => rotl(encoded ^ tweak, rotation).wrapping_add(mask),
        5 => (encoded.wrapping_sub(0x7F4A_7C15u32 as i32)) ^ rotl(mask, u32::from(word_index) + 1),
        6 => rotr(encoded.wrapping_add(mask), rotation) ^ tweak,
        7 => rotr(encoded ^ tweak, rotation).wrapping_sub(mask),
        _ => return Err(PageError::InvalidInput("bound lane family is invalid")),
    })
}

fn rotation(mask: i32, family: u8, word_index: u8) -> u32 {
    (((mask ^ (i32::from(family).wrapping_mul(0x045D_9F3B)) ^ i32::from(word_index)) as u32) & 31)
        + 1
}

fn tweak(mask: i32, family: u8, word_index: u8) -> i32 {
    rotl(
        mask ^ (0x9E37_79B9u32 as i32).wrapping_mul(i32::from(word_index) + 1),
        (u32::from(word_index) + u32::from(family)) & 31,
    )
}

fn rotl(value: i32, amount: u32) -> i32 {
    (value as u32).rotate_left(amount) as i32
}

fn rotr(value: i32, amount: u32) -> i32 {
    (value as u32).rotate_right(amount) as i32
}

fn domain_digest(domain: &[u8], fields: &[&[u8]]) -> Digest {
    let mut material =
        Vec::with_capacity(domain.len() + fields.iter().map(|field| field.len()).sum::<usize>());
    material.extend_from_slice(domain);
    for field in fields {
        material.extend_from_slice(field);
    }
    sha256(&material)
}

fn minimum_encoded_size() -> usize {
    2 + PAGE_NONCE_SIZE
        + PLAN_NONCE_SIZE
        + DIGEST_SIZE
        + DIGEST_SIZE
        + LANE_COUNT * (2 + 4 + MIN_TOKEN_SIZE + LANE_SALT_SIZE + 4 + LANE_TAG_SIZE)
        + PLAN_TAG_SIZE
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_u8(&mut self) -> Result<u8, PageError> {
        self.require(1)?;
        let value = self.bytes[self.offset];
        self.offset += 1;
        Ok(value)
    }

    fn read_i32(&mut self) -> Result<i32, PageError> {
        let bytes = self.read_fixed::<4>()?;
        Ok(i32::from_be_bytes(bytes))
    }

    fn read_fixed<const N: usize>(&mut self) -> Result<[u8; N], PageError> {
        self.require(N)?;
        let mut output = [0u8; N];
        output.copy_from_slice(&self.bytes[self.offset..self.offset + N]);
        self.offset += N;
        Ok(output)
    }

    fn read_framed(&mut self, maximum: usize) -> Result<Vec<u8>, PageError> {
        let length = self.read_i32()? as usize;
        if length == 0 || length > maximum {
            return Err(PageError::InvalidInput("bound framed length is invalid"));
        }
        self.require(length)?;
        let value = self.bytes[self.offset..self.offset + length].to_vec();
        self.offset += length;
        Ok(value)
    }

    fn skip(&mut self, length: usize) -> Result<(), PageError> {
        self.require(length)?;
        self.offset += length;
        Ok(())
    }

    fn require_empty(&self) -> Result<(), PageError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(PageError::InvalidInput(
                "bound descriptor has trailing bytes",
            ))
        }
    }

    fn require(&self, length: usize) -> Result<(), PageError> {
        if self.offset + length <= self.bytes.len() {
            Ok(())
        } else {
            Err(PageError::InvalidInput("bound descriptor is truncated"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_lane_family_inverts() {
        let mask = 0x1357_9BDFu32 as i32;
        for family in 0..WORD_FAMILY_COUNT {
            for word_index in 0..LANE_COUNT as u8 {
                let value = 0x1020_3040i32.wrapping_mul(i32::from(word_index) + 3);
                let encoded = encode_word(value, mask, family, word_index).expect("encode");
                assert_eq!(
                    decode_word(encoded, mask, family, word_index).expect("decode"),
                    value,
                    "family {family} word {word_index}"
                );
            }
        }
    }
}
