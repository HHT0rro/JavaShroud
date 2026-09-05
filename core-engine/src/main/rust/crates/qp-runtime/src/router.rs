use crate::lifecycle::SensitiveBytes;
use crate::page::{PageKind, PageRequest};
use qp_crypto::constant_time_eq;
use qp_page::{BorrowedPageLease, PageCipherSchedule, PageEnvelope, PageError as WirePageError};
use std::collections::HashMap;
use std::fmt;

const MAX_ATTACHED_PAGES: usize = 4096;

pub struct AttachedPage {
    envelope: PageEnvelope,
    encoded: Vec<u8>,
    /// Descriptor decoded and authenticated once at catalog installation.
    ///
    /// Re-decoding the same descriptor for every typed page open made hot
    /// StringPage call sites pay the complete wire/parser cost on each access.
    /// The descriptor remains artifact-bound and immutable after installation;
    /// its child owners wipe evaluator/proof material on drop.
    descriptor: qp_page::PageDescriptor,
}

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
struct RouteIndexKey {
    kind_id: u8,
    encoded_handle: [u8; qp_page::ENCODED_HANDLE_SIZE],
}

impl Drop for AttachedPage {
    fn drop(&mut self) {
        self.envelope.wipe();
        self.encoded.fill(0);
    }
}

/// Transient page-key material derived for one open. It is wiped on drop and
/// never stored on an attached page.
pub struct PageKeyMaterial([u8; 32]);

impl PageKeyMaterial {
    pub fn from_material(material: &[u8; 32]) -> Self {
        Self(*material)
    }

    fn materialize(&self) -> Result<PageCipherSchedule, RouterError> {
        let mut material = TransientMaterial([0u8; 32]);
        material.0.copy_from_slice(&self.0);
        PageCipherSchedule::from_material(&material.0)
            .map_err(|_| RouterError::AuthenticationFailed)
    }
}

impl Drop for PageKeyMaterial {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

/// All inputs of the structured binary page-key derivation. Every field is
/// reconstructible from the installed descriptor, envelope, and page frame
/// header; no secret travels in the request itself.
pub struct PageKeyRequest<'a> {
    pub secret_slot: u32,
    pub kind_id: u8,
    pub page_index: i32,
    pub encoded_handle: &'a [u8],
    pub locator_token: &'a [u8],
    pub page_nonce: &'a [u8],
    pub artifact_commitment: &'a [u8],
    /// Secret-pack commitment over the derived key; the authority must verify
    /// it in constant time before returning key material.
    pub expected_key_commitment: &'a [u8],
}

/// Native-side secret authority. The production implementation reconstructs
/// the per-artifact specialization secret pack after the defense probes pass;
/// isolated tests may install a synthetic authority.
pub trait PageKeyAuthority: Send + Sync {
    fn derive_page_key(&self, request: &PageKeyRequest<'_>) -> Result<PageKeyMaterial, RouterError>;
}

struct TransientMaterial([u8; 32]);

impl Drop for TransientMaterial {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

pub struct TypedPageRouter {
    pages: Vec<AttachedPage>,
    route_index: HashMap<RouteIndexKey, usize>,
    vm_route_index: HashMap<i64, Vec<usize>>,
    authority: Option<Box<dyn PageKeyAuthority>>,
}

impl Default for TypedPageRouter {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct OpenedPage {
    kind: PageKind,
    payload: SensitiveBytes,
    entry_token: i64,
    logical_binding_path: String,
}

impl OpenedPage {
    pub const fn kind(&self) -> PageKind {
        self.kind
    }

    pub fn payload(&self) -> &[u8] {
        self.payload.as_slice()
    }

    pub fn with_payload<T, F>(&self, f: F) -> T
    where
        F: FnOnce(&[u8]) -> T,
    {
        f(self.payload.as_slice())
    }

    pub fn entry_token(&self) -> i64 {
        self.entry_token
    }

    pub fn logical_binding_path(&self) -> &str {
        &self.logical_binding_path
    }

    pub fn parse_vm_with_material(
        &self,
        crypto_domain: [u8; 32],
        layout_digest: [u8; 32],
        state_binding: &[u8],
        dialect_corpus: &qp_vm::VmDialectCorpus,
    ) -> Result<qp_vm::VmProgram, RouterError> {
        if self.kind != PageKind::Vm {
            return Err(RouterError::RouteUnavailable { kind: self.kind });
        }
        let material = qp_vm::VmKeyMaterial::new(crypto_domain, layout_digest)
            .with_dialect_corpus(dialect_corpus.clone());
        let parser = qp_vm::VmParser::new(&material, state_binding)
            .map_err(|error| RouterError::Wire(error.to_string()))?;
        parser
            .parse(self.payload.as_slice())
            .map_err(|error| RouterError::Wire(error.to_string()))
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
            Self::TooManyPages => formatter.write_str("Qp page catalog is full"),
            Self::InvalidRequest(reason) => {
                write!(formatter, "Qp page request is invalid: {reason}")
            }
            Self::AuthenticationFailed => formatter.write_str("Qp page authentication failed"),
            Self::RouteUnavailable { kind } => match kind {
                PageKind::Vm => formatter.write_str("Qp VM page route is unavailable"),
                _ => formatter.write_str("Qp typed page route is unavailable"),
            },
            Self::Wire(reason) => write!(formatter, "Qp page wire error: {reason}"),
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
        Self {
            pages: Vec::new(),
            route_index: HashMap::new(),
            vm_route_index: HashMap::new(),
            authority: None,
        }
    }

    /// Installs the native secret authority exactly once, before any page is
    /// attached. A router without an authority refuses every install.
    pub fn bind_page_key_authority(&mut self, authority: Box<dyn PageKeyAuthority>) {
        assert!(self.pages.is_empty(), "page key authority must be bound before installs");
        assert!(self.authority.is_none(), "page key authority is already bound");
        self.authority = Some(authority);
    }

    fn authority(&self) -> Result<&dyn PageKeyAuthority, RouterError> {
        self.authority
            .as_deref()
            .ok_or(RouterError::AuthenticationFailed)
    }

    /// Derives one page key from the native secret authority. The structured
    /// derivation inputs are read from the descriptor and the page frame
    /// header; the authority verifies the key commitment before returning
    /// material.
    fn derive_attached_key_material(
        &self,
        descriptor: &qp_page::PageDescriptor,
        encoded: &[u8],
    ) -> Result<PageKeyMaterial, RouterError> {
        let authority = self.authority()?;
        let layout = qp_page::PageLayout::from_variant(descriptor.route().layout_variant())
            .map_err(|_| RouterError::AuthenticationFailed)?;
        let header_offset = layout
            .header_offset(encoded.len())
            .map_err(|_| RouterError::AuthenticationFailed)?;
        let header_end = header_offset + qp_page::LOGICAL_HEADER_SIZE;
        if header_end > encoded.len() {
            return Err(RouterError::AuthenticationFailed);
        }
        let header = qp_page::PageHeader::decode(&encoded[header_offset..header_end])
            .map_err(|_| RouterError::AuthenticationFailed)?;
        let handle = descriptor.handle().map_err(|_| RouterError::AuthenticationFailed)?;
        let handle_encoded = handle.encoded();
        let handle_locator = handle.locator_token();
        let page_nonce = header.nonce();
        let header_commitment = header.evaluator_fingerprint();
        let artifact_commitment = descriptor.proof().artifact_commitment();
        let request = PageKeyRequest {
            secret_slot: descriptor.secret_slot(),
            kind_id: descriptor.resource_kind().id(),
            page_index: descriptor.page_index(),
            encoded_handle: handle_encoded.as_slice(),
            locator_token: handle_locator.as_slice(),
            page_nonce: page_nonce.as_slice(),
            artifact_commitment: artifact_commitment.as_slice(),
            expected_key_commitment: header_commitment.as_slice(),
        };
        authority.derive_page_key(&request)
    }

    pub fn len(&self) -> usize {
        self.pages.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pages.is_empty()
    }

    /// Install only an artifact-specific descriptor-bound page. Generic
    /// catalog keys/DEKs are intentionally not accepted by the current format.
    /// Install a page whose page-local decryptor is carried by the authenticated
    /// descriptor.  No generic key or sidecar is accepted on this path.
    pub fn install_descriptor_bound(
        &mut self,
        envelope: PageEnvelope,
        encoded: Vec<u8>,
        descriptor: Vec<u8>,
    ) -> Result<(), RouterError> {
        if encoded.is_empty() {
            return Err(RouterError::InvalidRequest(
                "attached page is missing ciphertext",
            ));
        }
        if descriptor.is_empty() {
            return Err(RouterError::InvalidRequest(
                "attached page is missing descriptor",
            ));
        }
        if self.pages.len() >= MAX_ATTACHED_PAGES {
            return Err(RouterError::TooManyPages);
        }
        let encoded_handle = envelope
            .encoded_handle()
            .map_err(|_| RouterError::AuthenticationFailed)?;
        let key = RouteIndexKey {
            kind_id: envelope.kind().id(),
            encoded_handle,
        };
        if self.route_index.contains_key(&key) {
            return Err(RouterError::AuthenticationFailed);
        }
        let parsed_descriptor = qp_page::PageDescriptor::decode(&descriptor)?;
        if !envelope.matches_descriptor(&parsed_descriptor) {
            return Err(RouterError::AuthenticationFailed);
        }
        // Prove the authority can derive a committed page key, then drop it.
        // The material is not retained on the attached page.
        drop(self.derive_attached_key_material(&parsed_descriptor, &encoded)?);
        self.install_descriptor_bound_parsed(envelope, encoded, parsed_descriptor, key)
    }

    fn install_descriptor_bound_parsed(
        &mut self,
        envelope: PageEnvelope,
        encoded: Vec<u8>,
        descriptor: qp_page::PageDescriptor,
        key: RouteIndexKey,
    ) -> Result<(), RouterError> {
        if self.pages.len() >= MAX_ATTACHED_PAGES {
            return Err(RouterError::TooManyPages);
        }
        if self.route_index.contains_key(&key) {
            return Err(RouterError::AuthenticationFailed);
        }
        let page_position = self.pages.len();
        let is_vm = envelope.kind() == qp_page::PageKind::Vm;
        let entry_token = envelope.entry_token();
        let page_index = envelope.page_index();
        self.pages.push(AttachedPage {
            envelope,
            encoded,
            descriptor,
        });
        self.route_index.insert(key, page_position);
        if is_vm {
            let slots = self.vm_route_index.entry(entry_token).or_default();
            if slots
                .iter()
                .any(|&slot| self.pages[slot].envelope.page_index() == page_index)
            {
                self.pages.pop();
                self.route_index.remove(&key);
                return Err(RouterError::InvalidRequest(
                    "duplicate VM page index for entry token",
                ));
            }
            slots.push(page_position);
            slots.sort_by_key(|&slot| self.pages[slot].envelope.page_index());
        }
        Ok(())
    }

    pub fn open(&self, entry_token: i64, request: &PageRequest) -> Result<OpenedPage, RouterError> {
        let page_index = i32::try_from(request.page_index())
            .map_err(|_| RouterError::InvalidRequest("page index does not fit the wire type"))?;
        let encoded_handle = request.handle().as_bytes();
        let proof = request.proof().as_bytes();
        let key = RouteIndexKey {
            kind_id: request.kind().id(),
            encoded_handle: *encoded_handle,
        };
        let Some(&page_position) = self.route_index.get(&key) else {
            return Err(RouterError::RouteUnavailable {
                kind: request.kind(),
            });
        };
        let attached = self
            .pages
            .get(page_position)
            .ok_or(RouterError::AuthenticationFailed)?;
        if !matches_attached_request(attached, entry_token, encoded_handle, page_index, proof) {
            return Err(RouterError::AuthenticationFailed);
        }
        let (payload, logical_binding_path) = self.open_attached_page(attached)?;
        Ok(OpenedPage {
            kind: request.kind(),
            payload,
            entry_token,
            logical_binding_path: logical_binding_path.to_string(),
        })
    }

    /// Open and concatenate every protected VM page belonging to one method route.
    ///
    /// A protected VM program is partitioned across page-local authenticated frames;
    /// the VM parser must receive the reconstructed serialized program rather
    /// than page zero alone.  The caller still authenticates one concrete page
    /// request (normally page zero) before the complete contiguous route is
    /// opened.
    pub fn open_vm_pages(
        &self,
        entry_token: i64,
        request: &PageRequest,
    ) -> Result<OpenedPage, RouterError> {
        if request.kind() != PageKind::Vm {
            return Err(RouterError::RouteUnavailable {
                kind: request.kind(),
            });
        }
        let Some(slots) = self.vm_route_index.get(&entry_token) else {
            return Err(RouterError::RouteUnavailable { kind: PageKind::Vm });
        };
        if slots.is_empty() {
            return Err(RouterError::RouteUnavailable { kind: PageKind::Vm });
        }
        let request_handle = request.handle().as_bytes();
        let request_proof = request.proof().as_bytes();
        let request_index = request.page_index() as i32;
        if !slots.iter().any(|&slot| {
            self.pages.get(slot).is_some_and(|page| {
                page.envelope.matches_typed_bridge_request(
                    entry_token,
                    request_handle,
                    request_index,
                    request_proof,
                )
            })
        }) {
            return Err(RouterError::RouteUnavailable { kind: PageKind::Vm });
        }

        let mut total_encoded = 0usize;
        let mut logical_binding_path: Option<&str> = None;
        for (expected_index, &slot) in slots.iter().enumerate() {
            let page = self
                .pages
                .get(slot)
                .ok_or(RouterError::AuthenticationFailed)?;
            if page.envelope.page_index() != expected_index as i32 {
                return Err(RouterError::AuthenticationFailed);
            }
            let current_path = page.descriptor.route().logical_binding_path();
            if let Some(expected_path) = logical_binding_path {
                if expected_path != current_path {
                    return Err(RouterError::AuthenticationFailed);
                }
            } else {
                logical_binding_path = Some(current_path);
            }
            total_encoded = total_encoded
                .checked_add(page.encoded.len())
                .ok_or(RouterError::AuthenticationFailed)?;
        }
        let logical_binding_path = logical_binding_path
            .ok_or(RouterError::AuthenticationFailed)?
            .to_string();

        if slots.len() == 1 {
            let page = self
                .pages
                .get(slots[0])
                .ok_or(RouterError::AuthenticationFailed)?;
            let (payload, _) = self.open_attached_page(page)?;
            return Ok(OpenedPage {
                kind: PageKind::Vm,
                payload,
                entry_token,
                logical_binding_path,
            });
        }

        let mut payload = SensitiveBytes::new(Vec::with_capacity(total_encoded));
        for &slot in slots {
            let page = self
                .pages
                .get(slot)
                .ok_or(RouterError::AuthenticationFailed)?;
            let mut part = self.open_attached_page(page)?.0;
            payload.append(&mut part);
        }
        Ok(OpenedPage {
            kind: PageKind::Vm,
            payload,
            entry_token,
            logical_binding_path,
        })
    }

    fn open_attached_page<'a>(
        &self,
        attached: &'a AttachedPage,
    ) -> Result<(SensitiveBytes, &'a str), RouterError> {
        let key_material =
            self.derive_attached_key_material(&attached.descriptor, &attached.encoded)?;
        let schedule = key_material.materialize()?;
        drop(key_material);
        // The catalog owns `attached.encoded` for the lifetime of the router.
        // Borrow it for authentication instead of cloning every ciphertext on
        // each hot-path page open; only the transient schedule and plaintext
        // are owned by the lease.
        let mut lease = BorrowedPageLease::open(attached.encoded.as_slice(), schedule);
        if let Err(error) = lease.authenticate_with_descriptor(&attached.descriptor) {
            return Err(RouterError::Wire(error.to_string()));
        }
        let payload = lease
            .consume()
            .map_err(|_| RouterError::AuthenticationFailed)?;
        Ok((
            SensitiveBytes::new(payload),
            attached.descriptor.route().logical_binding_path(),
        ))
    }

    pub fn install_catalog_descriptor_bound(
        &mut self,
        directory: &qp_page::ArtifactDirectory,
        stored_pages: &std::collections::BTreeMap<String, Vec<u8>>,
    ) -> Result<usize, RouterError> {
        let mut installed = 0usize;
        for entry in &directory.entries {
            let Some(blob) = stored_pages.get(&entry.relative_path) else {
                continue;
            };
            if entry.offset < 0 || entry.stored_length <= 0 {
                return Err(RouterError::InvalidRequest(
                    "catalog stored page range is invalid",
                ));
            }
            let start = entry.offset as usize;
            let length = entry.stored_length as usize;
            let end = start.checked_add(length).ok_or(RouterError::InvalidRequest(
                "catalog stored page range overflow",
            ))?;
            if end > blob.len() {
                return Err(RouterError::InvalidRequest(
                    "catalog stored page range is out of bounds",
                ));
            }
            let encoded = blob[start..end].to_vec();
            let envelope = qp_page::PageEnvelope::decode(&entry.envelope)?;
            let descriptor = qp_page::PageDescriptor::decode(&entry.descriptor)?;
            if !envelope.matches_descriptor(&descriptor) {
                return Err(RouterError::AuthenticationFailed);
            }
            let encoded_handle = envelope
                .encoded_handle()
                .map_err(|_| RouterError::AuthenticationFailed)?;
            let key = RouteIndexKey {
                kind_id: envelope.kind().id(),
                encoded_handle,
            };
            drop(self.derive_attached_key_material(&descriptor, &encoded)?);
            self.install_descriptor_bound_parsed(envelope, encoded, descriptor, key)?;
            installed = installed.checked_add(1).ok_or(RouterError::TooManyPages)?;
        }
        self.seal_vm_routes()?;
        Ok(installed)
    }

    fn seal_vm_routes(&self) -> Result<(), RouterError> {
        for slots in self.vm_route_index.values() {
            if slots.is_empty() {
                return Err(RouterError::AuthenticationFailed);
            }
            let mut logical_binding_path: Option<&str> = None;
            for (expected_index, &slot) in slots.iter().enumerate() {
                let page = self
                    .pages
                    .get(slot)
                    .ok_or(RouterError::AuthenticationFailed)?;
                if page.envelope.kind() != qp_page::PageKind::Vm
                    || page.envelope.page_index() != expected_index as i32
                {
                    return Err(RouterError::InvalidRequest(
                        "VM page index is missing, duplicated, or out of order",
                    ));
                }
                let current_path = page.descriptor.route().logical_binding_path();
                if let Some(expected_path) = logical_binding_path {
                    if expected_path != current_path {
                        return Err(RouterError::InvalidRequest(
                            "VM page logical path is inconsistent",
                        ));
                    }
                } else {
                    logical_binding_path = Some(current_path);
                }
            }
        }
        Ok(())
    }

    pub fn clear(&mut self) {
        self.pages.clear();
        self.route_index.clear();
        self.vm_route_index.clear();
        self.authority = None;
    }
}

/// Validate a request against the immutable, catalog-authenticated page
/// record without recomputing the proof digest on every open.
///
/// `PageEnvelope::matches_typed_bridge_request` remains the public generic
/// verifier for callers that only possess an envelope.  The runtime router has
/// the stronger descriptor-bound record available after installation, so it
/// can compare the raw call-site proof directly with the proof authenticated
/// by `matches_descriptor` at install time.  This preserves fail-closed
/// semantics while removing one SHA-256 over every hot StringPage access.
fn matches_attached_request(
    attached: &AttachedPage,
    entry_token: i64,
    encoded_handle: &[u8],
    page_index: i32,
    raw_call_site_proof: &[u8],
) -> bool {
    if attached.envelope.is_wiped()
        || page_index < 0
        || encoded_handle.len() != qp_page::ENCODED_HANDLE_SIZE
        || raw_call_site_proof.is_empty()
        || raw_call_site_proof.len() > qp_page::MAX_CALL_SITE_PROOF_SIZE
    {
        return false;
    }
    let expected_handle = match attached.envelope.encoded_handle() {
        Ok(value) => value,
        Err(_) => return false,
    };
    let token_match = entry_token == 0 || attached.envelope.entry_token() == entry_token;
    let page_match = attached.envelope.page_index() == page_index;
    let handle_match = constant_time_eq(&expected_handle, encoded_handle);
    let proof_match = constant_time_eq(
        attached.descriptor.proof().call_site_proof(),
        raw_call_site_proof,
    );
    token_match && page_match && handle_match && proof_match
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
    use qp_crypto::{hkdf_sha256, hmac_sha256_bytes};
    use qp_page::{
        encode_page, LeafIdentity, PageDescriptor, PageEnvelope, PageHandle, PageKind as WireKind,
        PageLayout, PageProof, PageRoute, CANONICAL_CODEC_VARIANT, DIGEST_SIZE,
        ENCODED_HANDLE_SIZE, FINGERPRINT_SIZE, NONCE_SIZE,
    };

    /// Synthetic authority mirroring the production derivation: structured
    /// binary inputs, HKDF page key, constant-time commitment verification.
    struct TestAuthority {
        seed: [u8; 32],
        commitment_key: [u8; 32],
        native_identity: [u8; 32],
        authorized: bool,
    }

    impl TestAuthority {
        const COMMITMENT_DOMAIN: &[u8] = b"javashroud-test-commitment-v4";
        const PAGE_KEY_DOMAIN: &[u8] = b"javashroud-test-page-key-v4";

        fn new(seed: [u8; 32]) -> Self {
            let commitment_key = hkdf_sha256(&seed, Self::COMMITMENT_DOMAIN, &[], 32)
                .expect("test commitment key");
            let mut key = [0u8; 32];
            key.copy_from_slice(&commitment_key[..32]);
            Self {
                seed,
                commitment_key: key,
                native_identity: [0x5A; 32],
                authorized: true,
            }
        }

        fn material_for(&self, fixture: &AttachedFixture) -> [u8; 32] {
            let request = PageKeyRequest {
                secret_slot: 0,
                kind_id: fixture.kind.id(),
                page_index: fixture.page_index,
                encoded_handle: &fixture.encoded_handle,
                locator_token: &fixture.locator,
                page_nonce: &fixture.page_nonce,
                artifact_commitment: &[0x10; DIGEST_SIZE],
                expected_key_commitment: &fixture.commitment,
            };
            self.derive(&request).expect("test page key")
        }

        /// Same derivation the production authority performs.
        fn derive(&self, request: &PageKeyRequest<'_>) -> Result<[u8; 32], RouterError> {
            if !self.authorized {
                return Err(RouterError::AuthenticationFailed);
            }
            let mut info = Vec::new();
            info.extend_from_slice(request.artifact_commitment);
            info.extend_from_slice(&request.secret_slot.to_be_bytes());
            info.push(request.kind_id);
            info.extend_from_slice(&(request.page_index as u32).to_be_bytes());
            info.extend_from_slice(request.encoded_handle);
            info.extend_from_slice(request.locator_token);
            info.extend_from_slice(request.page_nonce);
            info.extend_from_slice(&self.native_identity);
            let key = hkdf_sha256(&self.seed, Self::PAGE_KEY_DOMAIN, &info, 32)
                .map_err(|_| RouterError::AuthenticationFailed)?;
            let mut material = [0u8; 32];
            material.copy_from_slice(&key[..32]);
            Ok(material)
        }
    }

    impl PageKeyAuthority for TestAuthority {
        fn derive_page_key(
            &self,
            request: &PageKeyRequest<'_>,
        ) -> Result<PageKeyMaterial, RouterError> {
            let key = self.derive(request)?;
            let expected = hmac_sha256_bytes(&self.commitment_key, &[&key]);
            if !constant_time_eq(&expected, request.expected_key_commitment) {
                return Err(RouterError::AuthenticationFailed);
            }
            Ok(PageKeyMaterial::from_material(&key))
        }
    }

    fn clone_authority(authority: &TestAuthority) -> TestAuthority {
        TestAuthority {
            seed: authority.seed,
            commitment_key: authority.commitment_key,
            native_identity: authority.native_identity,
            authorized: authority.authorized,
        }
    }

    struct AttachedFixture {
        envelope: PageEnvelope,
        encoded: Vec<u8>,
        descriptor_bytes: Vec<u8>,
        encoded_handle: [u8; PAGE_HANDLE_SIZE],
        locator: [u8; 16],
        proof_bytes: Vec<u8>,
        authority: TestAuthority,
        page_nonce: [u8; NONCE_SIZE],
        kind: WireKind,
        page_index: i32,
        commitment: [u8; FINGERPRINT_SIZE],
    }

    fn attached_string_page() -> AttachedFixture {
        attached_typed_page(WireKind::StringPage, 3, 0x11, b"hello-native")
    }

    fn attached_typed_page(
        kind: WireKind,
        page_index: i32,
        handle_fill: u8,
        payload: &[u8],
    ) -> AttachedFixture {
        let authority = TestAuthority::new([0x77; 32]);
        let encoded_handle = [handle_fill; ENCODED_HANDLE_SIZE];
        let locator = [0x12u8.wrapping_add(handle_fill); 16];
        let page_nonce = [0x50u8; NONCE_SIZE];
        let page_material = {
            let request = PageKeyRequest {
                secret_slot: 0,
                kind_id: kind.id(),
                page_index,
                encoded_handle: &encoded_handle,
                locator_token: &locator,
                page_nonce: &page_nonce,
                artifact_commitment: &[0x10; DIGEST_SIZE],
                expected_key_commitment: &[0u8; 32],
            };
            authority.derive(&request).expect("test page key")
        };
        let page_commitment = hmac_sha256_bytes(&authority.commitment_key, &[&page_material]);
        let handle = PageHandle::new(kind, page_index, encoded_handle, locator, page_commitment)
            .expect("handle");
        let identity = format!("logical-page-{page_index}");
        let leaf = LeafIdentity::from_handle(&handle, identity.as_bytes()).expect("leaf");
        let layout =
            PageLayout::new("unit", 12, 8, false, &[9, 8, 7, 6, 5, 4, 3, 2]).expect("layout");
        let layout_variant = layout.variant();
        let route = PageRoute::new(
            leaf.clone(),
            "META-INF/qpunit/page",
            7,
            123,
            CANONICAL_CODEC_VARIANT,
            &layout_variant,
            "META-INF/qpunit/page",
        )
        .expect("route");
        let proof_bytes = if page_index == 3 {
            b"call-site-proof".to_vec()
        } else {
            format!("call-site-proof-{page_index}").into_bytes()
        };
        let proof = PageProof::new(
            leaf,
            &[0x10; DIGEST_SIZE],
            &[0x13; DIGEST_SIZE],
            &[0x14; DIGEST_SIZE],
            vec![[0x15; DIGEST_SIZE], [0x16; DIGEST_SIZE]],
            vec![false, true],
            &proof_bytes,
            CANONICAL_CODEC_VARIANT,
            &layout_variant,
        )
        .expect("proof");
        let descriptor = PageDescriptor::new(route, proof, 1024, 0).expect("descriptor");
        let envelope =
            PageEnvelope::create(0, &handle, &descriptor, &proof_bytes).expect("envelope");
        let descriptor_bytes = descriptor.encode();
        let encoded = encode_page(
            payload,
            &page_material,
            &[0x10; DIGEST_SIZE],
            identity.as_bytes(),
            page_index,
            kind,
            &page_commitment,
            CANONICAL_CODEC_VARIANT,
            &layout,
            &locator,
            &page_nonce,
            &[0x61; 12],
            &[0x62; 8],
        )
        .expect("encode");
        AttachedFixture {
            envelope,
            encoded,
            descriptor_bytes,
            encoded_handle,
            locator,
            proof_bytes,
            authority,
            page_nonce,
            kind,
            page_index,
            commitment: page_commitment,
        }
    }

    struct InstalledRouter {
        router: TypedPageRouter,
        encoded_handle: [u8; PAGE_HANDLE_SIZE],
        proof_bytes: Vec<u8>,
    }

    fn installed_router() -> InstalledRouter {
        let fixture = attached_string_page();
        let mut router = TypedPageRouter::new();
        router.bind_page_key_authority(Box::new(clone_authority(&fixture.authority)));
        router
            .install_descriptor_bound(
                fixture.envelope,
                fixture.encoded.clone(),
                fixture.descriptor_bytes.clone(),
            )
            .expect("descriptor-bound install");
        InstalledRouter {
            router,
            encoded_handle: fixture.encoded_handle,
            proof_bytes: fixture.proof_bytes,
        }
    }

    fn string_request(
        installed: &InstalledRouter,
        proof: &[u8],
    ) -> PageRequest {
        PageRequest::new(&installed.encoded_handle, 3, proof, PageKind::String)
            .expect("request")
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
    fn install_fails_closed_without_a_bound_authority() {
        let fixture = attached_string_page();
        let mut router = TypedPageRouter::new();
        assert_eq!(
            router.install_descriptor_bound(
                fixture.envelope,
                fixture.encoded.clone(),
                fixture.descriptor_bytes.clone()
            ),
            Err(RouterError::AuthenticationFailed)
        );
    }

    #[test]
    fn descriptor_bound_install_requires_ciphertext_and_descriptor() {
        let fixture = attached_string_page();
        let mut router = TypedPageRouter::new();
        router.bind_page_key_authority(Box::new(clone_authority(&fixture.authority)));
        let envelope = PageEnvelope::create(
            0,
            &PageHandle::new(
                WireKind::StringPage,
                3,
                fixture.encoded_handle,
                fixture.locator,
                fixture.commitment,
            )
            .expect("handle"),
            &{
                let descriptor =
                    PageDescriptor::decode(&fixture.descriptor_bytes).expect("descriptor");
                descriptor
            },
            &fixture.proof_bytes,
        )
        .expect("envelope");
        assert_eq!(
            router.install_descriptor_bound(envelope, Vec::new(), fixture.descriptor_bytes.clone()),
            Err(RouterError::InvalidRequest(
                "attached page is missing ciphertext"
            ))
        );
        let fixture2 = attached_string_page();
        assert_eq!(
            router.install_descriptor_bound(fixture2.envelope, fixture2.encoded, Vec::new()),
            Err(RouterError::InvalidRequest(
                "attached page is missing descriptor"
            ))
        );
    }

    #[test]
    fn descriptor_bound_install_retains_only_authenticated_descriptor_bytes() {
        let installed = installed_router();
        assert_eq!(installed.router.len(), 1);
        assert!(
            installed.router.pages.iter().all(|page| {
                // Attached pages keep ciphertext and the authenticated descriptor
                // only; page keys are re-derived on open.
                !page.encoded.is_empty()
            })
        );
    }

    #[test]
    fn clear_unbinds_authority_so_later_opens_fail_closed() {
        let mut installed = installed_router();
        let request = string_request(&installed, &installed.proof_bytes);
        installed.router.open(0, &request).expect("open before clear");
        installed.router.clear();
        assert!(installed.router.is_empty());
        let fixture = attached_string_page();
        assert_eq!(
            installed.router.install_descriptor_bound(
                fixture.envelope,
                fixture.encoded,
                fixture.descriptor_bytes
            ),
            Err(RouterError::AuthenticationFailed)
        );
    }

    #[test]
    fn current_schedule_round_trips_an_authenticated_page() {
        let installed = installed_router();
        let request = string_request(&installed, &installed.proof_bytes);
        let opened = installed.router.open(0, &request).expect("open current page");
        opened.with_payload(|bytes| assert_eq!(bytes, b"hello-native"));
    }

    #[test]
    fn descriptor_bound_open_rejects_wrong_raw_call_site_proof() {
        let installed = installed_router();
        let mut wrong = installed.proof_bytes.clone();
        wrong[0] ^= 0x5a;
        let request = string_request(&installed, &wrong);
        assert_eq!(
            installed.router.open(0, &request),
            Err(RouterError::AuthenticationFailed)
        );
    }

    #[test]
    fn unauthorized_authority_fails_closed() {
        let fixture = attached_string_page();
        let mut router = TypedPageRouter::new();
        router.bind_page_key_authority(Box::new(TestAuthority {
            authorized: false,
            ..clone_authority(&fixture.authority)
        }));
        assert_eq!(
            router.install_descriptor_bound(
                fixture.envelope,
                fixture.encoded,
                fixture.descriptor_bytes
            ),
            Err(RouterError::AuthenticationFailed)
        );
    }

    #[test]
    fn wrong_slot_fails_closed() {
        let fixture = attached_string_page();
        // Re-encode the descriptor with a slot the authority does not know.
        let mut reslotted_bytes = fixture.descriptor_bytes.clone();
        let tail = reslotted_bytes.len();
        // The slot is the trailing big-endian u32.
        reslotted_bytes[tail - 1] = reslotted_bytes[tail - 1].wrapping_add(1);
        let mut router = TypedPageRouter::new();
        router.bind_page_key_authority(Box::new(clone_authority(&fixture.authority)));
        assert_eq!(
            router.install_descriptor_bound(
                fixture.envelope,
                fixture.encoded,
                reslotted_bytes
            ),
            Err(RouterError::AuthenticationFailed)
        );
    }
}
