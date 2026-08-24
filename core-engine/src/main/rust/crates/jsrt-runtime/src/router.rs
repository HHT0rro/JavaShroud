use crate::page::{PageKind, PageRequest};
use jsrt_crypto::{constant_time_eq, Sha256};
use jsrt_page::{PageCipherSchedule, PageEnvelope, PageError as WirePageError, PageLease};
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
    descriptor: jsrt_page::PageDescriptor,
    schedule_template: EvaluatorScheduleTemplate,
}

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
struct RouteIndexKey {
    kind_id: u8,
    encoded_handle: [u8; jsrt_page::ENCODED_HANDLE_SIZE],
}

impl Drop for AttachedPage {
    fn drop(&mut self) {
        self.envelope.wipe();
        self.encoded.fill(0);
    }
}

/// Parsed, authenticated evaluator material that contains no reconstructed
/// page key.  Fragment masks are precomputed once when the catalog is sealed;
/// each open still materializes a transient page schedule and wipes it through
/// `PageLease` after authenticated decryption.
struct EvaluatorScheduleTemplate {
    fragments: Vec<EvaluatorScheduleFragment>,
}

struct EvaluatorScheduleFragment {
    offset: usize,
    length: usize,
    family: u8,
    opcode: u8,
    register: u8,
    encoded: Vec<u8>,
    mask: Vec<u8>,
}

impl Drop for EvaluatorScheduleTemplate {
    fn drop(&mut self) {
        self.fragments.clear();
    }
}

impl Drop for EvaluatorScheduleFragment {
    fn drop(&mut self) {
        self.encoded.fill(0);
        self.mask.fill(0);
    }
}

impl EvaluatorScheduleTemplate {
    fn materialize(&self) -> Result<PageCipherSchedule, RouterError> {
        let mut material = TransientMaterial([0u8; 32]);
        for fragment in &self.fragments {
            if fragment.offset + fragment.length > material.0.len()
                || fragment.encoded.len() != fragment.length
                || fragment.mask.len() != fragment.length
            {
                return Err(RouterError::AuthenticationFailed);
            }
            for index in 0..fragment.length {
                let tweak = fragment
                    .family
                    .wrapping_mul(17)
                    .wrapping_add(fragment.opcode)
                    .wrapping_add(fragment.register)
                    .wrapping_add(index as u8);
                material.0[fragment.offset + index] =
                    fragment.encoded[index] ^ fragment.mask[index] ^ tweak;
            }
        }
        PageCipherSchedule::from_material(&material.0)
            .map_err(|_| RouterError::AuthenticationFailed)
    }
}

#[derive(Default)]
pub struct TypedPageRouter {
    pages: Vec<AttachedPage>,
    route_index: HashMap<RouteIndexKey, usize>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct OpenedPage {
    kind: PageKind,
    payload: Vec<u8>,
    entry_token: i64,
    logical_binding_path: String,
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
    ) -> Result<jsrt_vm::VmProgram, RouterError> {
        if self.kind != PageKind::Vm {
            return Err(RouterError::RouteUnavailable { kind: self.kind });
        }
        let material = jsrt_vm::VmKeyMaterial::new(crypto_domain, layout_digest);
        let parser = jsrt_vm::VmParser::new(&material, state_binding)
            .map_err(|_| RouterError::AuthenticationFailed)?;
        parser
            .parse(&self.payload)
            .map_err(|_| RouterError::AuthenticationFailed)
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
        Self {
            pages: Vec::new(),
            route_index: HashMap::new(),
        }
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
        let parsed_descriptor = jsrt_page::PageDescriptor::decode(&descriptor)?;
        if !envelope.matches_descriptor(&parsed_descriptor) {
            return Err(RouterError::AuthenticationFailed);
        }
        let schedule_template = compile_descriptor_schedule(&parsed_descriptor)?;
        self.install_descriptor_bound_parsed(
            envelope,
            encoded,
            parsed_descriptor,
            schedule_template,
            key,
        )
    }

    fn install_descriptor_bound_parsed(
        &mut self,
        envelope: PageEnvelope,
        encoded: Vec<u8>,
        descriptor: jsrt_page::PageDescriptor,
        schedule_template: EvaluatorScheduleTemplate,
        key: RouteIndexKey,
    ) -> Result<(), RouterError> {
        if self.pages.len() >= MAX_ATTACHED_PAGES {
            return Err(RouterError::TooManyPages);
        }
        if self.route_index.contains_key(&key) {
            return Err(RouterError::AuthenticationFailed);
        }
        let page_position = self.pages.len();
        self.pages.push(AttachedPage {
            envelope,
            encoded,
            descriptor,
            schedule_template,
        });
        self.route_index.insert(key, page_position);
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
        let (payload, descriptor) = self.open_attached_page(attached)?;
        Ok(OpenedPage {
            kind: request.kind(),
            payload,
            entry_token,
            logical_binding_path: descriptor.route().logical_binding_path().to_string(),
        })
    }

    /// Open and concatenate every VBC4 page belonging to one method route.
    ///
    /// A VBC4 program is partitioned across page-local authenticated frames;
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
        let mut pages: Vec<&AttachedPage> = self
            .pages
            .iter()
            .filter(|page| {
                page.envelope.kind() == jsrt_page::PageKind::Vm
                    && page.envelope.entry_token() == entry_token
            })
            .collect();
        if pages.is_empty() {
            return Err(RouterError::RouteUnavailable { kind: PageKind::Vm });
        }
        if !pages.iter().any(|page| {
            page.envelope.matches_typed_bridge_request(
                entry_token,
                request.handle().as_bytes(),
                request.page_index() as i32,
                request.proof().as_bytes(),
            )
        }) {
            return Err(RouterError::RouteUnavailable { kind: PageKind::Vm });
        }
        pages.sort_by_key(|page| page.envelope.page_index());

        let mut payload = Vec::new();
        let mut logical_binding_path: Option<String> = None;
        for (expected_index, page) in pages.iter().enumerate() {
            if page.envelope.page_index() != expected_index as i32 {
                return Err(RouterError::AuthenticationFailed);
            }
            let (part, descriptor) = self.open_attached_page(page)?;
            let current_path = descriptor.route().logical_binding_path().to_string();
            if let Some(expected_path) = logical_binding_path.as_deref() {
                if expected_path != current_path {
                    return Err(RouterError::AuthenticationFailed);
                }
            } else {
                logical_binding_path = Some(current_path);
            }
            payload.extend_from_slice(&part);
            let mut part = part;
            part.fill(0);
        }
        Ok(OpenedPage {
            kind: PageKind::Vm,
            payload,
            entry_token,
            logical_binding_path: logical_binding_path.ok_or(RouterError::AuthenticationFailed)?,
        })
    }

    fn open_attached_page(
        &self,
        attached: &AttachedPage,
    ) -> Result<(Vec<u8>, jsrt_page::PageDescriptor), RouterError> {
        let schedule = attached.schedule_template.materialize()?;
        let mut lease = PageLease::open(attached.encoded.clone(), schedule);
        if lease
            .authenticate_with_descriptor(&attached.descriptor)
            .is_err()
        {
            return Err(RouterError::AuthenticationFailed);
        }
        let payload = lease
            .consume()
            .map_err(|_| RouterError::AuthenticationFailed)?;
        Ok((payload, attached.descriptor.clone()))
    }

    pub fn install_catalog_descriptor_bound(
        &mut self,
        directory: &jsrt_page::ArtifactDirectory,
        stored_pages: &std::collections::BTreeMap<String, Vec<u8>>,
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
            let descriptor = jsrt_page::PageDescriptor::decode(&entry.descriptor)?;
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
            let schedule_template = compile_descriptor_schedule(&descriptor)?;
            self.install_descriptor_bound_parsed(
                envelope,
                encoded.clone(),
                descriptor,
                schedule_template,
                key,
            )?;
            installed = installed.checked_add(1).ok_or(RouterError::TooManyPages)?;
        }
        Ok(installed)
    }

    pub fn clear(&mut self) {
        self.pages.clear();
        self.route_index.clear();
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
        || encoded_handle.len() != jsrt_page::ENCODED_HANDLE_SIZE
        || raw_call_site_proof.is_empty()
        || raw_call_site_proof.len() > jsrt_page::MAX_CALL_SITE_PROOF_SIZE
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

/// Evaluate one artifact-specific VBC4 descriptor into a transient page
/// material buffer. The wire grammar is intentionally variable: every page
/// chooses its own dialect byte, fragment count, offsets, opcodes, registers,
/// tokens and fragment lengths. Authentication is completed before any
/// fragment is decoded.
fn compile_descriptor_schedule(
    descriptor: &jsrt_page::PageDescriptor,
) -> Result<EvaluatorScheduleTemplate, RouterError> {
    const MARKER: &[u8; 4] = b"VBC4";
    const MATERIAL_SIZE: usize = 32;
    const NONCE_SIZE: usize = 12;
    const PLAN_NONCE_SIZE: usize = 16;
    const DIGEST_SIZE: usize = 32;
    const DIALECT_SIZE: usize = 32;
    const TAG_SIZE: usize = 16;
    const MIN_FRAGMENTS: usize = 4;
    const MAX_FRAGMENTS: usize = 12;

    let opaque = descriptor.evaluator_plan().opaque();
    let body_end = opaque
        .len()
        .checked_sub(DIGEST_SIZE)
        .ok_or(RouterError::AuthenticationFailed)?;
    if opaque.len() < 4 + 2 + NONCE_SIZE + PLAN_NONCE_SIZE + DIGEST_SIZE * 3 + DIGEST_SIZE {
        return Err(RouterError::AuthenticationFailed);
    }
    let supplied_plan_tag = &opaque[body_end..];
    let expected_plan_tag = sha256_with_domain(b"vbc4-evaluator-seal", &opaque[..body_end]);
    if !constant_time_eq(&expected_plan_tag, supplied_plan_tag) {
        return Err(RouterError::AuthenticationFailed);
    }

    let mut cursor = 0usize;
    let read = |cursor: &mut usize, length: usize| -> Result<&[u8], RouterError> {
        if *cursor > body_end.saturating_sub(length) {
            return Err(RouterError::AuthenticationFailed);
        }
        let start = *cursor;
        *cursor += length;
        Ok(&opaque[start..start + length])
    };
    if read(&mut cursor, MARKER.len())? != MARKER {
        return Err(RouterError::AuthenticationFailed);
    }
    let dialect_byte = read(&mut cursor, 1)?[0];
    let fragment_count = read(&mut cursor, 1)?[0] as usize;
    if !(MIN_FRAGMENTS..=MAX_FRAGMENTS).contains(&fragment_count) {
        return Err(RouterError::AuthenticationFailed);
    }
    let _page_nonce = read(&mut cursor, NONCE_SIZE)?;
    let plan_nonce = read(&mut cursor, PLAN_NONCE_SIZE)?;
    let static_binding = read(&mut cursor, DIGEST_SIZE)?.to_vec();
    let _final_binding = read(&mut cursor, DIGEST_SIZE)?;
    let dialect_commitment = read(&mut cursor, DIALECT_SIZE)?.to_vec();

    let expected_dialect = {
        let mut hasher = Sha256::new();
        hasher.update(b"vbc4-evaluator-dialect");
        hasher.update(&static_binding);
        hasher.update(plan_nonce);
        hasher.update(&[dialect_byte]);
        hasher.finalize().into_bytes()
    };
    if !constant_time_eq(&expected_dialect, &dialect_commitment) {
        return Err(RouterError::AuthenticationFailed);
    }

    let mut covered = [false; MATERIAL_SIZE];
    let mut fragments = Vec::with_capacity(fragment_count);
    for _ in 0..fragment_count {
        let offset = read(&mut cursor, 1)?[0] as usize;
        let length = read(&mut cursor, 1)?[0] as usize;
        let family = read(&mut cursor, 1)?[0];
        let opcode = read(&mut cursor, 1)?[0];
        let register = read(&mut cursor, 1)?[0];
        if length == 0 || offset >= MATERIAL_SIZE || offset + length > MATERIAL_SIZE {
            return Err(RouterError::AuthenticationFailed);
        }
        if (offset..offset + length).any(|index| covered[index]) {
            return Err(RouterError::AuthenticationFailed);
        }
        let token_len = read_u32(opaque, &mut cursor, body_end)? as usize;
        if !(17..=48).contains(&token_len) {
            return Err(RouterError::AuthenticationFailed);
        }
        let token = read(&mut cursor, token_len)?;
        let salt = read(&mut cursor, 16)?;
        let encoded_len = read_u32(opaque, &mut cursor, body_end)? as usize;
        if encoded_len != length {
            return Err(RouterError::AuthenticationFailed);
        }
        let encoded = read(&mut cursor, encoded_len)?;
        let supplied_tag = read(&mut cursor, TAG_SIZE)?;

        let mut tag_hasher = Sha256::new();
        tag_hasher.update(b"vbc4-evaluator-fragment");
        tag_hasher.update(&static_binding);
        tag_hasher.update(&dialect_commitment);
        update_i32(&mut tag_hasher, offset as u32);
        update_i32(&mut tag_hasher, length as u32);
        update_i32(&mut tag_hasher, family as u32);
        update_i32(&mut tag_hasher, opcode as u32);
        update_i32(&mut tag_hasher, register as u32);
        update_frame(&mut tag_hasher, token);
        update_frame(&mut tag_hasher, salt);
        update_frame(&mut tag_hasher, encoded);
        let expected_tag = tag_hasher.finalize();
        if !constant_time_eq(&expected_tag.as_ref()[..TAG_SIZE], supplied_tag) {
            return Err(RouterError::AuthenticationFailed);
        }

        let mut produced = 0usize;
        let mut counter = 0u32;
        let mut mask = vec![0u8; length];
        while produced < length {
            let mut mask_hasher = Sha256::new();
            mask_hasher.update(b"vbc4-evaluator-mask");
            mask_hasher.update(&static_binding);
            mask_hasher.update(&dialect_commitment);
            update_i32(&mut mask_hasher, offset as u32);
            update_i32(&mut mask_hasher, length as u32);
            update_i32(&mut mask_hasher, family as u32);
            update_i32(&mut mask_hasher, opcode as u32);
            update_i32(&mut mask_hasher, register as u32);
            update_frame(&mut mask_hasher, token);
            update_frame(&mut mask_hasher, salt);
            update_i32(&mut mask_hasher, counter);
            let block = mask_hasher.finalize();
            let take = (length - produced).min(block.as_ref().len());
            for index in 0..take {
                mask[produced + index] = block.as_ref()[index];
            }
            produced += take;
            counter = counter.wrapping_add(1);
        }
        for index in offset..offset + length {
            covered[index] = true;
        }
        fragments.push(EvaluatorScheduleFragment {
            offset,
            length,
            family,
            opcode,
            register,
            encoded: encoded.to_vec(),
            mask,
        });
    }
    if cursor != body_end || !covered.iter().all(|value| *value) {
        return Err(RouterError::AuthenticationFailed);
    }
    Ok(EvaluatorScheduleTemplate { fragments })
}

struct TransientMaterial([u8; 32]);

impl Drop for TransientMaterial {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

fn read_u32(bytes: &[u8], cursor: &mut usize, limit: usize) -> Result<u32, RouterError> {
    if *cursor > limit.saturating_sub(4) {
        return Err(RouterError::AuthenticationFailed);
    }
    let value = u32::from_be_bytes([
        bytes[*cursor],
        bytes[*cursor + 1],
        bytes[*cursor + 2],
        bytes[*cursor + 3],
    ]);
    *cursor += 4;
    Ok(value)
}

fn update_i32(hasher: &mut Sha256, value: u32) {
    hasher.update(&value.to_be_bytes());
}

fn update_frame(hasher: &mut Sha256, value: &[u8]) {
    update_i32(hasher, value.len() as u32);
    hasher.update(value);
}

fn sha256_with_domain(domain: &[u8], value: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(value);
    hasher.finalize().into_bytes()
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
        [u8; 32],
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
        [u8; 32],
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
        let page_material = [0x40u8; 32];
        let evaluator_opaque = current_evaluator_opaque(&page_material);
        let evaluator = EvaluatorPlan::new(&evaluator_opaque, &fingerprint).expect("evaluator");
        let mut evaluator_opaque = evaluator_opaque;
        evaluator_opaque.fill(0);
        let descriptor = PageDescriptor::new(route, proof, 1024, evaluator).expect("descriptor");
        let envelope =
            PageEnvelope::create(0, &handle, &descriptor, &proof_bytes).expect("envelope");
        let encoded = encode_page(
            payload,
            &page_material,
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
        (envelope, encoded, [0x40; 32], encoded_handle, proof_bytes)
    }

    fn current_evaluator_opaque(material: &[u8; 32]) -> Vec<u8> {
        let dialect = 0x42u8;
        let plan_nonce = [0x51u8; 16];
        let static_binding = [0x32u8; 32];
        let mut dialect_hasher = Sha256::new();
        dialect_hasher.update(b"vbc4-evaluator-dialect");
        dialect_hasher.update(&static_binding);
        dialect_hasher.update(&plan_nonce);
        dialect_hasher.update(&[dialect]);
        let dialect_commitment = dialect_hasher.finalize().into_bytes();
        let mut body = Vec::new();
        body.extend_from_slice(b"VBC4");
        body.push(dialect);
        body.push(4);
        body.extend_from_slice(&[0x41; 12]);
        body.extend_from_slice(&plan_nonce);
        body.extend_from_slice(&static_binding);
        body.extend_from_slice(&[0x33; 32]);
        body.extend_from_slice(&dialect_commitment);
        for ordinal in 0..4usize {
            let offset = ordinal * 8;
            let length = 8usize;
            let family = (ordinal + 1) as u8;
            let opcode = (0x80 + ordinal) as u8;
            let register = (3 + ordinal) as u8;
            let token = vec![0x61u8.wrapping_add(ordinal as u8); 17];
            let salt = vec![0x71u8.wrapping_add(ordinal as u8); 16];
            let mut mask_hasher = Sha256::new();
            mask_hasher.update(b"vbc4-evaluator-mask");
            mask_hasher.update(&static_binding);
            mask_hasher.update(&dialect_commitment);
            update_i32(&mut mask_hasher, offset as u32);
            update_i32(&mut mask_hasher, length as u32);
            update_i32(&mut mask_hasher, family as u32);
            update_i32(&mut mask_hasher, opcode as u32);
            update_i32(&mut mask_hasher, register as u32);
            update_frame(&mut mask_hasher, &token);
            update_frame(&mut mask_hasher, &salt);
            update_i32(&mut mask_hasher, 0);
            let mask = mask_hasher.finalize();
            let encoded: Vec<u8> = (0..length)
                .map(|index| {
                    let tweak = family
                        .wrapping_mul(17)
                        .wrapping_add(opcode)
                        .wrapping_add(register)
                        .wrapping_add(index as u8);
                    material[offset + index] ^ mask.as_ref()[index] ^ tweak
                })
                .collect();
            let mut tag_hasher = Sha256::new();
            tag_hasher.update(b"vbc4-evaluator-fragment");
            tag_hasher.update(&static_binding);
            tag_hasher.update(&dialect_commitment);
            update_i32(&mut tag_hasher, offset as u32);
            update_i32(&mut tag_hasher, length as u32);
            update_i32(&mut tag_hasher, family as u32);
            update_i32(&mut tag_hasher, opcode as u32);
            update_i32(&mut tag_hasher, register as u32);
            update_frame(&mut tag_hasher, &token);
            update_frame(&mut tag_hasher, &salt);
            update_frame(&mut tag_hasher, &encoded);
            let tag = tag_hasher.finalize();
            body.extend_from_slice(&[offset as u8, length as u8, family, opcode, register]);
            update_u32(&mut body, token.len() as u32);
            body.extend_from_slice(&token);
            body.extend_from_slice(&salt);
            update_u32(&mut body, encoded.len() as u32);
            body.extend_from_slice(&encoded);
            body.extend_from_slice(&tag.as_ref()[..16]);
        }
        let plan_tag = sha256_with_domain(b"vbc4-evaluator-seal", &body);
        body.extend_from_slice(&plan_tag);
        body
    }

    fn update_u32(output: &mut Vec<u8>, value: u32) {
        output.extend_from_slice(&value.to_be_bytes());
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
    fn descriptor_bound_install_requires_ciphertext_and_descriptor() {
        let (envelope, _encoded, _dek, _handle, _proof) = attached_string_page();
        let mut router = TypedPageRouter::new();
        assert_eq!(
            router.install_descriptor_bound(envelope, Vec::new(), b"descriptor".to_vec()),
            Err(RouterError::InvalidRequest(
                "attached page is missing ciphertext"
            ))
        );
        let (envelope, encoded, _dek, _handle, _proof) = attached_string_page();
        assert_eq!(
            router.install_descriptor_bound(envelope, encoded, Vec::new()),
            Err(RouterError::InvalidRequest(
                "attached page is missing descriptor"
            ))
        );
    }

    #[test]
    fn descriptor_bound_install_retains_only_authenticated_descriptor_bytes() {
        let (envelope, encoded, _dek, _handle, _proof) = attached_string_page();
        let descriptor = envelope
            .inline_descriptor()
            .expect("inline descriptor")
            .expect("descriptor bytes");
        let mut router = TypedPageRouter::new();
        router
            .install_descriptor_bound(envelope, encoded, descriptor)
            .expect("descriptor-bound install");
        assert_eq!(router.len(), 1);
    }

    #[test]
    fn current_evaluator_schedule_round_trips_an_authenticated_page() {
        let (envelope, encoded, _material, handle, proof) = attached_string_page();
        let descriptor = envelope
            .inline_descriptor()
            .expect("inline descriptor")
            .expect("descriptor bytes");
        let mut router = TypedPageRouter::new();
        router
            .install_descriptor_bound(envelope, encoded, descriptor)
            .expect("descriptor-bound install");
        let request = PageRequest::new(&handle, 3, &proof, PageKind::String).expect("request");
        let opened = router
            .open(0, &request)
            .expect("open current evaluator page");
        assert_eq!(opened.payload(), b"hello-r1");
    }

    #[test]
    fn descriptor_bound_open_rejects_wrong_raw_call_site_proof() {
        let (envelope, encoded, _material, handle, proof) = attached_string_page();
        let descriptor = envelope
            .inline_descriptor()
            .expect("inline descriptor")
            .expect("descriptor bytes");
        let mut router = TypedPageRouter::new();
        router
            .install_descriptor_bound(envelope, encoded, descriptor)
            .expect("descriptor-bound install");
        let mut wrong = proof.clone();
        wrong[0] ^= 0x5a;
        let request = PageRequest::new(&handle, 3, &wrong, PageKind::String).expect("request");
        assert_eq!(
            router.open(0, &request),
            Err(RouterError::AuthenticationFailed)
        );
    }
}
