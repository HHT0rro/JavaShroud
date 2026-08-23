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
    dek: Vec<u8>,
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

    pub fn dek(&self) -> &[u8] {
        &self.dek
    }

    pub fn execute_vm(&self) -> Result<Option<i32>, RouterError> {
        if self.kind != PageKind::Vm {
            return Err(RouterError::RouteUnavailable { kind: self.kind });
        }
        if self.dek.len() != 32 {
            return Err(RouterError::InvalidRequest("VM page key length is invalid"));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&self.dek);
        let material = jsrt_vm::VmKeyMaterial::new(key, key);
        let parser = jsrt_vm::VmParser::new(&material, b"")
            .map_err(|_| RouterError::AuthenticationFailed)?;
        let program = parser
            .parse(&self.payload)
            .map_err(|_| RouterError::AuthenticationFailed)?;
        let mut executor = jsrt_vm::VmExecutor::new(jsrt_vm::NoObjectOperations);
        match executor.execute(&program, &[]) {
            Ok(jsrt_vm::VmValue::Int(value)) => Ok(Some(value)),
            Ok(jsrt_vm::VmValue::Null) => Ok(None),
            Ok(_) => Ok(None),
            Err(_) => Err(RouterError::RouteUnavailable { kind: PageKind::Vm }),
        }
    }
}

impl Drop for OpenedPage {
    fn drop(&mut self) {
        self.payload.fill(0);
        self.dek.fill(0);
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
        if encoded.is_empty() {
            return Err(RouterError::InvalidRequest(
                "attached page is missing ciphertext",
            ));
        }
        if !dek.is_empty() && dek.len() != 32 {
            return Err(RouterError::InvalidRequest(
                "attached page key length is invalid",
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
        let mut dek = attached.dek.clone();
        if dek.is_empty() {
            dek = descriptor.evaluator_plan().recover_page_dek()?.to_vec();
        }
        let mut lease = PageLease::open(attached.encoded.clone(), dek.clone());
        lease
            .authenticate_with_descriptor(&descriptor)
            .map_err(|_| RouterError::AuthenticationFailed)?;
        let payload = lease
            .consume()
            .map_err(|_| RouterError::AuthenticationFailed)?;
        Ok(OpenedPage {
            kind: request.kind(),
            payload,
            dek,
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

    pub fn install_sidecar(&mut self, root: &std::path::Path) -> Result<usize, RouterError> {
        let directory_bytes = std::fs::read(root.join("directory.jsr1"))
            .map_err(|_| RouterError::InvalidRequest("catalog sidecar directory is missing"))?;
        let dek = std::fs::read(root.join("dek.bin")).unwrap_or_default();
        if !dek.is_empty() && dek.len() != 32 {
            return Err(RouterError::InvalidRequest(
                "catalog sidecar key length is invalid",
            ));
        }
        let directory = jsrt_page::decode_directory(&directory_bytes)?;
        let mut stored = std::collections::BTreeMap::new();
        for entry in &directory.entries {
            let encoded = std::fs::read(root.join(&entry.relative_path))
                .map_err(|_| RouterError::InvalidRequest("catalog sidecar page is missing"))?;
            stored.insert(entry.relative_path.clone(), encoded);
        }
        self.install_catalog(&directory, &stored, &dek)
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
        attached_typed_page(WireKind::StringPage, 3, 0x11, b"hello-r1")
    }

    fn attached_typed_page(
        kind: WireKind,
        page_index: i32,
        handle_fill: u8,
        payload: &[u8],
    ) -> (
        PageEnvelope,
        Vec<u8>,
        Vec<u8>,
        [u8; PAGE_HANDLE_SIZE],
        Vec<u8>,
    ) {
        let fingerprint = [0x22; FINGERPRINT_SIZE];
        let encoded_handle = [handle_fill; ENCODED_HANDLE_SIZE];
        let locator = [0x12u8.wrapping_add(handle_fill); LOCATOR_TOKEN_SIZE];
        let handle = PageHandle::new(kind, page_index, encoded_handle, locator, fingerprint)
            .expect("handle");
        let identity = format!("logical-page-{page_index}");
        let leaf = LeafIdentity::from_handle(&handle, identity.as_bytes()).expect("leaf");
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
        let wrapped_dek =
            jsrt_page::wrap_bound_page_dek(&[0x40; 32], &fingerprint).expect("wrap dek");
        let evaluator = EvaluatorPlan::new(&wrapped_dek, &fingerprint).expect("evaluator");
        let descriptor = PageDescriptor::new(route, proof, 1024, evaluator).expect("descriptor");
        let envelope =
            PageEnvelope::create(0, &handle, &descriptor, b"call-site-proof").expect("envelope");
        let encoded = encode_page(
            payload,
            &[0x40; 32],
            &[0x10; DIGEST_SIZE],
            identity.as_bytes(),
            page_index,
            kind,
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

    #[test]
    fn catalog_sidecar_round_trips_from_the_filesystem() {
        let (envelope, encoded, _dek, handle, proof) = attached_string_page();
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
        let encoded_dir = jsrt_page::encode_directory(&jsrt_page::ArtifactDirectory {
            runtime,
            entries: vec![jsrt_page::ArtifactDirectoryEntry {
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
            }],
            root_digest: [0; 32],
        })
        .expect("dir");
        let root = std::env::temp_dir().join(format!("jsrt-r1-sidecar-{}", std::process::id()));
        std::fs::create_dir_all(root.join("pages")).expect("pages dir");
        std::fs::write(root.join("directory.jsr1"), encoded_dir).expect("directory");
        std::fs::write(root.join("pages/page-3.bin"), encoded).expect("page");
        let mut router = TypedPageRouter::new();
        assert_eq!(router.install_sidecar(&root).expect("sidecar"), 1);
        let request = PageRequest::new(&handle, 3, &proof, PageKind::String).expect("request");
        assert_eq!(
            router.open(0, &request).expect("open").payload(),
            b"hello-r1"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn catalog_sidecar_opens_string_class_and_native_pages() {
        let vm_material = jsrt_vm::VmKeyMaterial::new([0x40; 32], [0x40; 32]);
        let vm_frame = jsrt_vm::encode_iconst7_frame(&vm_material).expect("vbc4");
        let pages = [
            (
                "pages/page-3.bin",
                attached_typed_page(WireKind::StringPage, 3, 0x11, b"hello-r1"),
            ),
            (
                "pages/page-4.bin",
                attached_typed_page(WireKind::EncryptedClassPage, 4, 0x21, b"class-r1"),
            ),
            (
                "pages/page-5.bin",
                attached_typed_page(WireKind::NativeChunk, 5, 0x31, b"native-r1"),
            ),
            (
                "pages/page-6.bin",
                attached_typed_page(WireKind::Vbc4Method, 6, 0x41, &vm_frame),
            ),
        ];
        let runtime = jsrt_page::DirectoryRuntimeBinding::new(
            [1; 32],
            [2; 32],
            [3; 32],
            "x86_64-pc-windows-gnu",
            [4; 32],
            "aken-r1-rust-ffi-v1",
        )
        .expect("runtime");
        let mut entries = Vec::new();
        for (path, (envelope, encoded, _, handle, _)) in &pages {
            let envelope_bytes = envelope.encode().expect("envelope");
            let descriptor = envelope
                .inline_descriptor()
                .expect("inline")
                .expect("descriptor");
            entries.push(jsrt_page::ArtifactDirectoryEntry {
                kind: match *path {
                    "pages/page-3.bin" => WireKind::StringPage,
                    "pages/page-4.bin" => WireKind::EncryptedClassPage,
                    "pages/page-5.bin" => WireKind::NativeChunk,
                    _ => WireKind::Vbc4Method,
                },
                page_index: match *path {
                    "pages/page-3.bin" => 3,
                    "pages/page-4.bin" => 4,
                    "pages/page-5.bin" => 5,
                    _ => 6,
                },
                encoded_handle: *handle,
                locator: [0x12u8.wrapping_add(handle[0]); 16],
                relative_path: (*path).to_string(),
                offset: 0,
                stored_length: encoded.len() as i32,
                descriptor,
                envelope: envelope_bytes,
                binding_digest: [0; 32],
            });
        }
        let encoded_dir = jsrt_page::encode_directory(&jsrt_page::ArtifactDirectory {
            runtime,
            entries,
            root_digest: [0; 32],
        })
        .expect("dir");
        let root =
            std::env::temp_dir().join(format!("jsrt-r1-typed-sidecar-{}", std::process::id()));
        std::fs::create_dir_all(root.join("pages")).expect("pages dir");
        std::fs::write(root.join("directory.jsr1"), encoded_dir).expect("directory");
        for (path, (_, encoded, _, handle, proof)) in &pages {
            std::fs::write(root.join(path), encoded).expect("page");
            let stem = path.rsplit('/').next().expect("stem").replace(".bin", "");
            std::fs::write(root.join(format!("{stem}.handle")), handle).expect("handle");
            std::fs::write(root.join(format!("{stem}.proof")), proof).expect("proof");
            if *path == "pages/page-3.bin" {
                std::fs::write(root.join("handle.bin"), handle).expect("string handle");
                std::fs::write(root.join("proof.bin"), proof).expect("string proof");
            }
        }
        let mut router = TypedPageRouter::new();
        assert_eq!(router.install_sidecar(&root).expect("sidecar"), 4);
        let kinds = [
            (PageKind::String, 3, 0x11, b"hello-r1".as_slice()),
            (PageKind::Class, 4, 0x21, b"class-r1".as_slice()),
            (PageKind::Native, 5, 0x31, b"native-r1".as_slice()),
        ];
        for (kind, index, fill, payload) in kinds {
            let request =
                PageRequest::new(&[fill; PAGE_HANDLE_SIZE], index, b"call-site-proof", kind)
                    .expect("request");
            assert_eq!(router.open(0, &request).expect("open").payload(), payload);
        }
        let vm_request = PageRequest::new(
            &[0x41; PAGE_HANDLE_SIZE],
            6,
            b"call-site-proof",
            PageKind::Vm,
        )
        .expect("vm request");
        assert_eq!(
            router.open(0, &vm_request).expect("vm open").execute_vm(),
            Ok(Some(7))
        );
        let dest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../../test/resources/aken-r1-sidecar");
        if dest.join("directory.jsr1").exists() {
            let _ = std::fs::remove_dir_all(&dest);
            std::fs::create_dir_all(dest.join("pages")).expect("export pages");
            copy_dir(&root, &dest);
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    fn copy_dir(from: &std::path::Path, to: &std::path::Path) {
        for entry in std::fs::read_dir(from).expect("read") {
            let entry = entry.expect("entry");
            let dest = to.join(entry.file_name());
            if entry.file_type().expect("ty").is_dir() {
                std::fs::create_dir_all(&dest).expect("dir");
                copy_dir(&entry.path(), &dest);
            } else {
                std::fs::copy(entry.path(), dest).expect("copy");
            }
        }
    }
}
