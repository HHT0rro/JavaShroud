use crate::page::{PageKind, PageRequest};
use jsrt_page::{PageEnvelope, PageError as WirePageError, PageLease};
use std::fmt;

const MAX_ATTACHED_PAGES: usize = 4096;

pub struct AttachedPage {
    envelope: PageEnvelope,
    encoded: Vec<u8>,
    dek: Vec<u8>,
}

impl Drop for AttachedPage {
    fn drop(&mut self) {
        self.envelope.wipe();
        self.encoded.fill(0);
        self.dek.fill(0);
    }
}

#[derive(Default)]
pub struct TypedPageRouter {
    pages: Vec<AttachedPage>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct OpenedPage {
    kind: PageKind,
    payload: Vec<u8>,
}

impl OpenedPage {
    pub const fn kind(&self) -> PageKind {
        self.kind
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn into_payload(mut self) -> Vec<u8> {
        let mut payload = Vec::new();
        std::mem::swap(&mut payload, &mut self.payload);
        payload
    }
}

impl Drop for OpenedPage {
    fn drop(&mut self) {
        self.payload.fill(0);
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RouterError {
    TooManyPages,
    InvalidRequest(&'static str),
    AuthenticationFailed,
    RouteUnavailable { kind: PageKind },
    Wire(String),
}

impl fmt::Display for RouterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyPages => formatter.write_str("AKEN-R1 page catalog is full"),
            Self::InvalidRequest(reason) => {
                write!(formatter, "AKEN-R1 page request is invalid: {reason}")
            }
            Self::AuthenticationFailed => formatter.write_str("AKEN-R1 page authentication failed"),
            Self::RouteUnavailable { kind } => match kind {
                PageKind::Vm => formatter.write_str("AKEN VM page route is unavailable"),
                _ => formatter.write_str("AKEN typed page route is unavailable"),
            },
            Self::Wire(reason) => write!(formatter, "AKEN-R1 page wire error: {reason}"),
        }
    }
}

impl std::error::Error for RouterError {}

impl From<WirePageError> for RouterError {
    fn from(error: WirePageError) -> Self {
        Self::Wire(error.to_string())
    }
}

impl TypedPageRouter {
    pub fn new() -> Self {
        Self { pages: Vec::new() }
    }

    pub fn len(&self) -> usize {
        self.pages.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pages.is_empty()
    }

    pub fn install(
        &mut self,
        envelope: PageEnvelope,
        encoded: Vec<u8>,
        dek: Vec<u8>,
    ) -> Result<(), RouterError> {
        if encoded.is_empty() || dek.is_empty() {
            return Err(RouterError::InvalidRequest(
                "attached page is missing ciphertext or key",
            ));
        }
        if self.pages.len() >= MAX_ATTACHED_PAGES {
            return Err(RouterError::TooManyPages);
        }
        self.pages.push(AttachedPage {
            envelope,
            encoded,
            dek,
        });
        Ok(())
    }

    pub fn open(&self, entry_token: i64, request: &PageRequest) -> Result<OpenedPage, RouterError> {
        let page_index = i32::try_from(request.page_index())
            .map_err(|_| RouterError::InvalidRequest("page index does not fit the wire type"))?;
        let encoded_handle = request.handle().as_bytes();
        let proof = request.proof().as_bytes();
        let Some(attached) = self.pages.iter().find(|page| {
            page.envelope.kind().id() == request.kind().id()
                && page.envelope.matches_typed_bridge_request(
                    entry_token,
                    encoded_handle,
                    page_index,
                    proof,
                )
        }) else {
            return Err(RouterError::RouteUnavailable {
                kind: request.kind(),
            });
        };
        let descriptor = attached
            .envelope
            .inline_descriptor()?
            .ok_or(RouterError::AuthenticationFailed)?;
        let descriptor = jsrt_page::PageDescriptor::decode(&descriptor)?;
        if !attached.envelope.matches_descriptor(&descriptor) {
            return Err(RouterError::AuthenticationFailed);
        }
        let mut lease = PageLease::open(attached.encoded.clone(), attached.dek.clone());
        lease
            .authenticate_with_descriptor(&descriptor)
            .map_err(|_| RouterError::AuthenticationFailed)?;
        let payload = lease
            .consume()
            .map_err(|_| RouterError::AuthenticationFailed)?;
        Ok(OpenedPage {
            kind: request.kind(),
            payload,
        })
    }

    pub fn install_catalog(
        &mut self,
        directory: &jsrt_page::ArtifactDirectory,
        stored_pages: &std::collections::BTreeMap<String, Vec<u8>>,
        dek: &[u8],
    ) -> Result<usize, RouterError> {
        let mut installed = 0usize;
        for entry in &directory.entries {
            let Some(encoded) = stored_pages.get(&entry.relative_path) else {
                continue;
            };
            if encoded.len() != entry.stored_length as usize {
                return Err(RouterError::InvalidRequest(
                    "catalog stored page length does not match the directory",
                ));
            }
            let envelope = jsrt_page::PageEnvelope::decode(&entry.envelope)?;
            self.install(envelope, encoded.clone(), dek.to_vec())?;
            installed = installed.checked_add(1).ok_or(RouterError::TooManyPages)?;
        }
        Ok(installed)
    }

    pub fn clear(&mut self) {
        self.pages.clear();
    }
}

impl Drop for TypedPageRouter {
    fn drop(&mut self) {
        self.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::page::{PageRequest, PAGE_HANDLE_SIZE};
    use jsrt_page::{
        encode_page, EvaluatorPlan, LeafIdentity, PageDescriptor, PageEnvelope, PageHandle,
        PageKind as WireKind, PageLayout, PageProof, PageRoute, CANONICAL_CODEC_VARIANT,
        DIGEST_SIZE, ENCODED_HANDLE_SIZE, FINGERPRINT_SIZE, LOCATOR_TOKEN_SIZE, NONCE_SIZE,
    };

    fn attached_string_page() -> (
        PageEnvelope,
        Vec<u8>,
        Vec<u8>,
        [u8; PAGE_HANDLE_SIZE],
        Vec<u8>,
    ) {
        let fingerprint = [0x22; FINGERPRINT_SIZE];
        let encoded_handle = [0x11; ENCODED_HANDLE_SIZE];
        let locator = [0x12; LOCATOR_TOKEN_SIZE];
        let handle = PageHandle::new(
            WireKind::StringPage,
            3,
            encoded_handle,
            locator,
            fingerprint,
        )
        .expect("handle");
        let leaf = LeafIdentity::from_handle(&handle, b"logical-page-identity").expect("leaf");
        let layout =
            PageLayout::new("unit", 12, 8, false, &[9, 8, 7, 6, 5, 4, 3, 2]).expect("layout");
        let layout_variant = layout.variant();
        let route = PageRoute::new(
            leaf.clone(),
            "META-INF/jsrt/page",
            7,
            123,
            CANONICAL_CODEC_VARIANT,
            &layout_variant,
            "META-INF/jsrt/page",
        )
        .expect("route");
        let proof = PageProof::new(
            leaf,
            &[0x10; DIGEST_SIZE],
            &[0x13; DIGEST_SIZE],
            &[0x14; DIGEST_SIZE],
            vec![[0x15; DIGEST_SIZE], [0x16; DIGEST_SIZE]],
            vec![false, true],
            b"call-site-proof",
            CANONICAL_CODEC_VARIANT,
            &layout_variant,
        )
        .expect("proof");
        let evaluator = EvaluatorPlan::new(b"opaque-evaluator", &fingerprint).expect("evaluator");
        let descriptor = PageDescriptor::new(route, proof, 1024, evaluator).expect("descriptor");
        let envelope =
            PageEnvelope::create(0, &handle, &descriptor, b"call-site-proof").expect("envelope");
        let encoded = encode_page(
            b"hello-r1",
            &[0x40; 32],
            &[0x10; DIGEST_SIZE],
            b"logical-page-identity",
            3,
            WireKind::StringPage,
            &fingerprint,
            CANONICAL_CODEC_VARIANT,
            &layout,
            &locator,
            &[0x50; NONCE_SIZE],
            &[0x61; 12],
            &[0x62; 8],
        )
        .expect("encode");
        (
            envelope,
            encoded,
            vec![0x40; 32],
            encoded_handle,
            b"call-site-proof".to_vec(),
        )
    }

    #[test]
    fn empty_router_fails_closed_without_a_java_fallback() {
        let router = TypedPageRouter::new();
        let request = PageRequest::new(
            &[0x11; PAGE_HANDLE_SIZE],
            3,
            b"call-site-proof",
            PageKind::String,
        )
        .expect("request");
        assert_eq!(
            router.open(0, &request),
            Err(RouterError::RouteUnavailable {
                kind: PageKind::String
            })
        );
    }

    #[test]
    fn installed_page_opens_only_after_envelope_and_lease_authentication() {
        let (envelope, encoded, dek, handle, proof) = attached_string_page();
        let mut router = TypedPageRouter::new();
        router.install(envelope, encoded, dek).expect("install");
        let request = PageRequest::new(&handle, 3, &proof, PageKind::String).expect("request");
        let opened = router.open(0, &request).expect("open");
        assert_eq!(opened.kind(), PageKind::String);
        assert_eq!(opened.payload(), b"hello-r1");

        let tampered = PageRequest::new(&handle, 3, b"wrong-proof", PageKind::String).expect("bad");
        assert_eq!(
            router.open(0, &tampered),
            Err(RouterError::RouteUnavailable {
                kind: PageKind::String
            })
        );
        let wrong_kind = PageRequest::new(&handle, 3, &proof, PageKind::Vm).expect("vm");
        assert_eq!(
            router.open(0, &wrong_kind),
            Err(RouterError::RouteUnavailable { kind: PageKind::Vm })
        );
    }

    #[test]
    fn catalog_install_opens_pages_from_an_authenticated_directory() {
        let (envelope, encoded, dek, handle, proof) = attached_string_page();
        let envelope_bytes = envelope.encode().expect("envelope bytes");
        let descriptor = envelope
            .inline_descriptor()
            .expect("inline")
            .expect("descriptor");
        let runtime = jsrt_page::DirectoryRuntimeBinding::new(
            [1; 32],
            [2; 32],
            [3; 32],
            "x86_64-pc-windows-gnu",
            [4; 32],
            "aken-r1-rust-ffi-v1",
        )
        .expect("runtime");
        let entry = jsrt_page::ArtifactDirectoryEntry {
            kind: WireKind::StringPage,
            page_index: 3,
            encoded_handle: handle,
            locator: [0x12; 16],
            relative_path: "pages/page-3.bin".to_string(),
            offset: 0,
            stored_length: encoded.len() as i32,
            descriptor,
            envelope: envelope_bytes,
            binding_digest: [0; 32],
        };
        let encoded_dir = jsrt_page::encode_directory(&jsrt_page::ArtifactDirectory {
            runtime,
            entries: vec![entry],
            root_digest: [0; 32],
        })
        .expect("dir");
        let directory = jsrt_page::decode_directory(&encoded_dir).expect("decode dir");
        let mut stored = std::collections::BTreeMap::new();
        stored.insert("pages/page-3.bin".to_string(), encoded);
        let mut router = TypedPageRouter::new();
        assert_eq!(
            router
                .install_catalog(&directory, &stored, &dek)
                .expect("catalog"),
            1
        );
        let request = PageRequest::new(&handle, 3, &proof, PageKind::String).expect("request");
        assert_eq!(
            router.open(0, &request).expect("open").payload(),
            b"hello-r1"
        );
    }
}
