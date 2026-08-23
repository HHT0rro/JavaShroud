use std::fmt;

pub const PAGE_HANDLE_SIZE: usize = 24;
pub const MAX_CALL_SITE_PROOF_SIZE: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PageKind {
    Vm,
    String,
    Class,
    Native,
}

impl PageKind {
    pub const fn id(self) -> u8 {
        match self {
            Self::Vm => 1,
            Self::String => 2,
            Self::Class => 3,
            Self::Native => 4,
        }
    }
}

#[derive(Clone, Eq, Hash, PartialEq)]
pub struct PageHandle([u8; PAGE_HANDLE_SIZE]);

impl PageHandle {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, PageError> {
        if bytes.len() != PAGE_HANDLE_SIZE {
            return Err(PageError::InvalidHandleLength { size: bytes.len() });
        }
        let mut value = [0; PAGE_HANDLE_SIZE];
        value.copy_from_slice(bytes);
        Ok(Self(value))
    }

    pub const fn as_bytes(&self) -> &[u8; PAGE_HANDLE_SIZE] {
        &self.0
    }
}

impl fmt::Debug for PageHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PageHandle")
            .field("length", &PAGE_HANDLE_SIZE)
            .finish()
    }
}

impl Drop for PageHandle {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct CallSiteProof(Vec<u8>);

impl CallSiteProof {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, PageError> {
        if bytes.is_empty() {
            return Err(PageError::EmptyProof);
        }
        if bytes.len() > MAX_CALL_SITE_PROOF_SIZE {
            return Err(PageError::ProofTooLarge { size: bytes.len() });
        }
        Ok(Self(bytes.to_vec()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for CallSiteProof {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

impl fmt::Debug for CallSiteProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CallSiteProof")
            .field("length", &self.0.len())
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PageRequest {
    handle: PageHandle,
    page_index: u32,
    proof: CallSiteProof,
    kind: PageKind,
}

impl PageRequest {
    pub fn new(
        handle: &[u8],
        page_index: u32,
        proof: &[u8],
        kind: PageKind,
    ) -> Result<Self, PageError> {
        Ok(Self {
            handle: PageHandle::from_slice(handle)?,
            page_index,
            proof: CallSiteProof::from_slice(proof)?,
            kind,
        })
    }

    pub const fn handle(&self) -> &PageHandle {
        &self.handle
    }

    pub const fn page_index(&self) -> u32 {
        self.page_index
    }

    pub const fn proof(&self) -> &CallSiteProof {
        &self.proof
    }

    pub const fn kind(&self) -> PageKind {
        self.kind
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PageError {
    InvalidHandleLength { size: usize },
    EmptyProof,
    ProofTooLarge { size: usize },
}

impl fmt::Display for PageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHandleLength { size } => {
                write!(
                    formatter,
                    "page handle must be {PAGE_HANDLE_SIZE} bytes, got {size}"
                )
            }
            Self::EmptyProof => formatter.write_str("page call-site proof is empty"),
            Self::ProofTooLarge { size } => write!(
                formatter,
                "page call-site proof is too large: {size} > {MAX_CALL_SITE_PROOF_SIZE}"
            ),
        }
    }
}

impl std::error::Error for PageError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_request_owns_only_bounded_typed_inputs() {
        let handle = [7; PAGE_HANDLE_SIZE];
        let proof = [9; 3];
        let request = PageRequest::new(&handle, 4, &proof, PageKind::Class).expect("request");
        assert_eq!(request.handle().as_bytes(), &handle);
        assert_eq!(request.page_index(), 4);
        assert_eq!(request.proof().as_bytes(), &proof);
        assert_eq!(request.kind(), PageKind::Class);
    }

    #[test]
    fn malformed_page_inputs_fail_before_any_route_logic() {
        assert_eq!(
            PageRequest::new(&[0; PAGE_HANDLE_SIZE - 1], 0, &[1], PageKind::Vm),
            Err(PageError::InvalidHandleLength {
                size: PAGE_HANDLE_SIZE - 1
            })
        );
        assert_eq!(
            PageRequest::new(&[0; PAGE_HANDLE_SIZE], 0, &[], PageKind::Vm),
            Err(PageError::EmptyProof)
        );
        assert!(matches!(
            PageRequest::new(
                &[0; PAGE_HANDLE_SIZE],
                0,
                &[0; MAX_CALL_SITE_PROOF_SIZE + 1],
                PageKind::Vm
            ),
            Err(PageError::ProofTooLarge { .. })
        ));
    }
}
