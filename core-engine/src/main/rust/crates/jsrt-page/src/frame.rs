use jsrt_crypto::{authentication_tag, constant_time_eq, CryptoError, RuntimeBindingDigest};
use jsrt_crypto::{
    Binding, BindingError, Digest, DIGEST_SIZE, MAX_PAYLOAD_SIZE, PROTOCOL_MAGIC, PROTOCOL_VERSION,
};
use std::fmt;

pub const AUTH_TAG_SIZE: usize = DIGEST_SIZE;
pub const MAX_FRAME_SIZE: usize =
    1 + 4 + DIGEST_SIZE + MAX_PAYLOAD_SIZE + AUTH_TAG_SIZE + PROTOCOL_MAGIC.len();

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    Truncated {
        position: usize,
        requested: usize,
        remaining: usize,
    },
    InvalidMagic,
    UnsupportedVersion(u8),
    LengthOverflow,
    FrameTooLarge {
        size: usize,
        max: usize,
    },
    TrailingBytes {
        remaining: usize,
    },
    AuthenticationFailed,
    InvalidBinding(BindingError),
    Crypto(CryptoError),
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated {
                position,
                requested,
                remaining,
            } => write!(
                formatter,
                "frame truncated at {position}: requested {requested} bytes, {remaining} remain"
            ),
            Self::InvalidMagic => formatter.write_str("unsupported runtime frame magic"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported runtime frame version {version}")
            }
            Self::LengthOverflow => {
                formatter.write_str("runtime frame length overflows the host size")
            }
            Self::FrameTooLarge { size, max } => {
                write!(formatter, "runtime frame is too large: {size} > {max}")
            }
            Self::TrailingBytes { remaining } => {
                write!(formatter, "runtime frame has {remaining} trailing bytes")
            }
            Self::AuthenticationFailed => {
                formatter.write_str("runtime frame authentication failed")
            }
            Self::InvalidBinding(error) => error.fmt(formatter),
            Self::Crypto(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for ProtocolError {}

impl From<BindingError> for ProtocolError {
    fn from(error: BindingError) -> Self {
        Self::InvalidBinding(error)
    }
}

impl From<CryptoError> for ProtocolError {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error)
    }
}

/// Bounds-checked reader used by every R1 wire parser.  It never advances the
/// cursor when a requested range is unavailable.
pub struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

#[allow(dead_code)]
impl<'a> Cursor<'a> {
    pub const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    pub const fn position(&self) -> usize {
        self.position
    }

    pub const fn remaining(&self) -> usize {
        self.bytes.len() - self.position
    }

    pub fn read_u8(&mut self) -> Result<u8, ProtocolError> {
        Ok(self.take(1)?[0])
    }

    pub fn read_u16_be(&mut self) -> Result<u16, ProtocolError> {
        Ok(u16::from_be_bytes(self.read_fixed()?))
    }

    pub fn read_u32_be(&mut self) -> Result<u32, ProtocolError> {
        Ok(u32::from_be_bytes(self.read_fixed()?))
    }

    pub fn read_fixed<const N: usize>(&mut self) -> Result<[u8; N], ProtocolError> {
        let bytes = self.take(N)?;
        let mut output = [0; N];
        output.copy_from_slice(bytes);
        Ok(output)
    }

    pub fn read_bytes(&mut self, length: usize) -> Result<&'a [u8], ProtocolError> {
        self.take(length)
    }

    pub fn read_frame(&mut self, max_length: usize) -> Result<&'a [u8], ProtocolError> {
        let length =
            usize::try_from(self.read_u32_be()?).map_err(|_| ProtocolError::LengthOverflow)?;
        if length > max_length {
            return Err(ProtocolError::FrameTooLarge {
                size: length,
                max: max_length,
            });
        }
        self.read_bytes(length)
    }

    pub fn require_empty(&self) -> Result<(), ProtocolError> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(ProtocolError::TrailingBytes {
                remaining: self.remaining(),
            })
        }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ProtocolError> {
        if length > self.remaining() {
            return Err(ProtocolError::Truncated {
                position: self.position,
                requested: length,
                remaining: self.remaining(),
            });
        }
        let start = self.position;
        self.position += length;
        Ok(&self.bytes[start..self.position])
    }
}

#[derive(Debug)]
pub struct FrameWriter {
    bytes: Vec<u8>,
    max_size: usize,
}

impl FrameWriter {
    pub fn new(max_size: usize) -> Self {
        Self {
            bytes: Vec::new(),
            max_size,
        }
    }

    pub fn position(&self) -> usize {
        self.bytes.len()
    }

    pub fn write_u8(&mut self, value: u8) -> Result<(), ProtocolError> {
        self.ensure_capacity(1)?;
        self.bytes.push(value);
        Ok(())
    }

    pub fn write_u16_be(&mut self, value: u16) -> Result<(), ProtocolError> {
        self.write_bytes(&value.to_be_bytes())
    }

    pub fn write_u32_be(&mut self, value: u32) -> Result<(), ProtocolError> {
        self.write_bytes(&value.to_be_bytes())
    }

    pub fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), ProtocolError> {
        self.ensure_capacity(bytes.len())?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    pub fn write_frame(&mut self, bytes: &[u8]) -> Result<(), ProtocolError> {
        let length = u32::try_from(bytes.len()).map_err(|_| ProtocolError::LengthOverflow)?;
        self.write_u32_be(length)?;
        self.write_bytes(bytes)
    }

    pub fn finish(self) -> Vec<u8> {
        self.bytes
    }

    fn ensure_capacity(&self, additional: usize) -> Result<(), ProtocolError> {
        let size = self
            .bytes
            .len()
            .checked_add(additional)
            .ok_or(ProtocolError::LengthOverflow)?;
        if size > self.max_size {
            return Err(ProtocolError::FrameTooLarge {
                size,
                max: self.max_size,
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedFrame {
    binding_digest: Digest,
    payload: Vec<u8>,
}

impl AuthenticatedFrame {
    pub fn binding_digest(&self) -> &Digest {
        &self.binding_digest
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn into_payload(self) -> Vec<u8> {
        self.payload
    }
}

pub struct RuntimeEnvelope;

impl RuntimeEnvelope {
    /// Encode only the current R1 format.  No retired version or compatibility
    /// branch is accepted by this API.
    pub fn encode(binding: &Binding, payload: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        if payload.len() > MAX_PAYLOAD_SIZE {
            return Err(ProtocolError::FrameTooLarge {
                size: payload.len(),
                max: MAX_PAYLOAD_SIZE,
            });
        }
        let digest = RuntimeBindingDigest::compute(binding);
        let tag = authentication_tag(digest.as_digest(), payload)?;
        let payload_length =
            u32::try_from(payload.len()).map_err(|_| ProtocolError::LengthOverflow)?;
        let mut writer = FrameWriter::new(MAX_FRAME_SIZE);
        writer.write_bytes(&PROTOCOL_MAGIC)?;
        writer.write_u8(PROTOCOL_VERSION)?;
        writer.write_u32_be(payload_length)?;
        writer.write_bytes(digest.as_bytes())?;
        writer.write_bytes(payload)?;
        writer.write_bytes(tag.as_ref())?;
        Ok(writer.finish())
    }

    /// Authenticate the fixed wire frame before returning any payload bytes.
    /// The first pass reads only bounded framing fields; no payload structure is
    /// interpreted until both the binding digest and authentication tag match.
    pub fn open(binding: &Binding, frame: &[u8]) -> Result<AuthenticatedFrame, ProtocolError> {
        let view = locate(frame)?;
        let expected_digest = RuntimeBindingDigest::compute(binding);
        let expected_tag = authentication_tag(expected_digest.as_digest(), view.payload)?;
        let tag_matches = constant_time_eq(view.auth_tag, expected_tag.as_ref());
        let digest_matches = constant_time_eq(view.binding_digest, expected_digest.as_bytes());
        if !tag_matches || !digest_matches {
            return Err(ProtocolError::AuthenticationFailed);
        }
        Ok(AuthenticatedFrame {
            binding_digest: Digest::from_slice(view.binding_digest).expect("fixed digest length"),
            payload: view.payload.to_vec(),
        })
    }
}

struct FrameView<'a> {
    binding_digest: &'a [u8],
    payload: &'a [u8],
    auth_tag: &'a [u8],
}

fn locate(frame: &[u8]) -> Result<FrameView<'_>, ProtocolError> {
    if frame.len() > MAX_FRAME_SIZE {
        return Err(ProtocolError::FrameTooLarge {
            size: frame.len(),
            max: MAX_FRAME_SIZE,
        });
    }
    let mut cursor = Cursor::new(frame);
    let magic = cursor.read_fixed::<4>()?;
    if magic != PROTOCOL_MAGIC {
        return Err(ProtocolError::InvalidMagic);
    }
    let version = cursor.read_u8()?;
    if version != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedVersion(version));
    }
    let payload_length =
        usize::try_from(cursor.read_u32_be()?).map_err(|_| ProtocolError::LengthOverflow)?;
    if payload_length > MAX_PAYLOAD_SIZE {
        return Err(ProtocolError::FrameTooLarge {
            size: payload_length,
            max: MAX_PAYLOAD_SIZE,
        });
    }
    let binding_digest = cursor.read_bytes(DIGEST_SIZE)?;
    let payload = cursor.read_bytes(payload_length)?;
    let auth_tag = cursor.read_bytes(AUTH_TAG_SIZE)?;
    cursor.require_empty()?;
    Ok(FrameView {
        binding_digest,
        payload,
        auth_tag,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsrt_crypto::Binding;

    fn binding() -> Binding {
        Binding::from_slice(b"runtime-binding").expect("binding")
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0);
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let high = (pair[0] as char).to_digit(16).expect("hex high");
                let low = (pair[1] as char).to_digit(16).expect("hex low");
                ((high << 4) | low) as u8
            })
            .collect()
    }

    #[test]
    fn kotlin_vector_is_the_current_r1_frame() {
        let binding = Binding::from_slice(b"binding").expect("binding");
        let frame = RuntimeEnvelope::encode(&binding, b"payload").expect("encode");
        assert_eq!(
            frame,
            decode_hex(concat!(
                "4a5352310200000007",
                "45a9b7e01030eaeb2a9abd080287f1018a9d7d06ed25faa60f325e390c3976fa",
                "7061796c6f6164",
                "c404e2bf95078737d5f0bec3e9a0f13523f2b4bf7fedf314721aa428e1539415",
            ))
        );
        assert_eq!(
            RuntimeEnvelope::open(&binding, &frame)
                .expect("open")
                .payload(),
            b"payload"
        );
    }

    #[test]
    fn cursor_and_writer_are_explicit_and_bounds_checked() {
        let mut writer = FrameWriter::new(32);
        writer.write_u8(0xA5).expect("u8");
        writer.write_u16_be(0x1234).expect("u16");
        writer.write_frame(b"payload").expect("frame");
        let bytes = writer.finish();
        let mut cursor = Cursor::new(&bytes);
        assert_eq!(cursor.read_u8().expect("u8"), 0xA5);
        assert_eq!(cursor.read_u16_be().expect("u16"), 0x1234);
        assert_eq!(cursor.read_frame(7).expect("payload"), b"payload");
        cursor.require_empty().expect("no trailing bytes");
        assert!(matches!(
            Cursor::new(&[1]).read_u32_be(),
            Err(ProtocolError::Truncated { .. })
        ));
    }

    #[test]
    fn authenticated_round_trip_happens_after_digest_check() {
        let frame = RuntimeEnvelope::encode(&binding(), b"opaque payload").expect("encode");
        let opened = RuntimeEnvelope::open(&binding(), &frame).expect("open");
        assert_eq!(opened.payload(), b"opaque payload");
        assert_eq!(
            opened.binding_digest(),
            RuntimeBindingDigest::compute(&binding()).as_digest()
        );
    }

    #[test]
    fn tampering_and_retired_headers_fail_closed() {
        let binding = binding();
        let frame = RuntimeEnvelope::encode(&binding, b"payload").expect("encode");
        let mut tampered = frame.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert_eq!(
            RuntimeEnvelope::open(&binding, &tampered),
            Err(ProtocolError::AuthenticationFailed)
        );

        let mut retired = frame;
        retired[4] = 0;
        assert_eq!(
            RuntimeEnvelope::open(&binding, &retired),
            Err(ProtocolError::UnsupportedVersion(0))
        );
    }

    #[test]
    fn malformed_payload_is_not_returned_before_authentication() {
        let binding = binding();
        let mut frame = RuntimeEnvelope::encode(&binding, b"payload").expect("encode");
        let payload_start = 4 + 1 + 4 + DIGEST_SIZE;
        frame[payload_start] = 0xff;
        let last = frame.len() - 1;
        frame[last] ^= 0x44;
        assert_eq!(
            RuntimeEnvelope::open(&binding, &frame),
            Err(ProtocolError::AuthenticationFailed)
        );
    }
}
