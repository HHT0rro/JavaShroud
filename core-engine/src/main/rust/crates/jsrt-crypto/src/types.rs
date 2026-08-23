use core::fmt;

pub const PROTOCOL_MAGIC: [u8; 4] = *b"JSR1";
pub const PROTOCOL_VERSION: u8 = 1;
pub const DIGEST_SIZE: usize = 32;
pub const MAX_BINDING_SIZE: usize = 4096;
pub const MAX_PAYLOAD_SIZE: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct Digest([u8; DIGEST_SIZE]);

impl Digest {
    pub const ZERO: Self = Self([0; DIGEST_SIZE]);

    pub const fn from_bytes(bytes: [u8; DIGEST_SIZE]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != DIGEST_SIZE {
            return None;
        }
        let mut value = [0; DIGEST_SIZE];
        value.copy_from_slice(bytes);
        Some(Self(value))
    }

    pub const fn as_bytes(&self) -> &[u8; DIGEST_SIZE] {
        &self.0
    }

    pub fn into_bytes(self) -> [u8; DIGEST_SIZE] {
        self.0
    }
}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("Digest")
            .field(&hex(self.as_ref()))
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct Binding(Vec<u8>);

impl Binding {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, BindingError> {
        if bytes.is_empty() {
            return Err(BindingError::Empty);
        }
        if bytes.len() > MAX_BINDING_SIZE {
            return Err(BindingError::TooLarge { size: bytes.len() });
        }
        Ok(Self(bytes.to_vec()))
    }

    pub fn from_vec(mut bytes: Vec<u8>) -> Result<Self, BindingError> {
        if bytes.is_empty() {
            return Err(BindingError::Empty);
        }
        if bytes.len() > MAX_BINDING_SIZE {
            bytes.fill(0);
            return Err(BindingError::TooLarge { size: bytes.len() });
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Binding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Binding")
            .field("length", &self.0.len())
            .finish()
    }
}

impl Drop for Binding {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BindingError {
    Empty,
    TooLarge { size: usize },
}

impl fmt::Display for BindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("runtime binding is empty"),
            Self::TooLarge { size } => {
                write!(formatter, "runtime binding is too large: {size} bytes")
            }
        }
    }
}

impl std::error::Error for BindingError {}

fn hex(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        output.push(TABLE[(byte >> 4) as usize] as char);
        output.push(TABLE[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_is_bounded_and_owned() {
        let source = [1, 2, 3];
        let binding = Binding::from_slice(&source).expect("valid binding");
        assert_eq!(binding.as_bytes(), source);
        assert_eq!(binding.len(), 3);
        assert!(!binding.is_empty());
        assert_eq!(Binding::from_slice(&[]), Err(BindingError::Empty));
        assert!(matches!(
            Binding::from_slice(&vec![0; MAX_BINDING_SIZE + 1]),
            Err(BindingError::TooLarge { .. })
        ));
    }

    #[test]
    fn digest_rejects_wrong_length() {
        assert_eq!(Digest::from_slice(&[0; DIGEST_SIZE - 1]), None);
        assert_eq!(
            Digest::from_slice(&[0; DIGEST_SIZE])
                .expect("digest")
                .as_ref(),
            &[0; DIGEST_SIZE]
        );
    }
}
