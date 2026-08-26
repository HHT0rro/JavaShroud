#![allow(unsafe_code, clippy::not_unsafe_ptr_arg_deref)]

mod relocation;
mod specialization;

pub use specialization::{
    PACKING_LEVEL, PAYLOAD_PROFILE, PROTECTION_LEVEL, SPECIALIZATION_DIGEST, TARGET_TRIPLE,
    VM_CRYPTO_DOMAIN, VM_LAYOUT_DIGEST,
};

use jsrt_crypto::{
    hmac_sha256_bytes, Binding, RuntimeBindingDigest, DIGEST_SIZE, MAX_BINDING_SIZE,
    MAX_PAYLOAD_SIZE,
};
use jsrt_page::{ArtifactDirectory, MAX_FRAME_SIZE};
use jsrt_runtime::{
    OpenedPage, PageKind, PageRequest, RouterError, Runtime, RuntimeError, TypedPageRouter,
};

const MAX_TARGET_LENGTH: usize = 64;

pub const JSRT_R1_OK: i32 = 0;
pub const JSRT_R1_INVALID_INPUT: i32 = -1;
pub const JSRT_R1_AUTHENTICATION_FAILED: i32 = -2;
pub const JSRT_R1_BUFFER_TOO_SMALL: i32 = -3;
pub const JSRT_R1_UNSUPPORTED_TARGET: i32 = -4;
pub const JSRT_R1_INTERNAL_ERROR: i32 = -5;

#[no_mangle]
pub extern "C" fn jsrt_r1_runtime_binding_digest(
    binding: *const u8,
    binding_len: usize,
    digest_out: *mut u8,
) -> i32 {
    if binding_len == 0 || binding_len > MAX_BINDING_SIZE {
        return JSRT_R1_INVALID_INPUT;
    }
    unsafe {
        let Some(binding_bytes) = read_slice(binding, binding_len) else {
            return JSRT_R1_INVALID_INPUT;
        };
        let Some(output) = write_slice(digest_out, DIGEST_SIZE) else {
            return JSRT_R1_INVALID_INPUT;
        };
        let Ok(binding) = Binding::from_slice(binding_bytes) else {
            return JSRT_R1_INVALID_INPUT;
        };
        output.copy_from_slice(RuntimeBindingDigest::compute(&binding).as_bytes());
        JSRT_R1_OK
    }
}

#[no_mangle]
pub extern "C" fn jsrt_r1_open_frame(
    target: *const u8,
    target_len: usize,
    binding: *const u8,
    binding_len: usize,
    frame: *const u8,
    frame_len: usize,
    payload_out: *mut u8,
    payload_capacity: usize,
    payload_len_out: *mut usize,
) -> i32 {
    if target_len == 0
        || target_len > MAX_TARGET_LENGTH
        || binding_len == 0
        || binding_len > MAX_BINDING_SIZE
        || frame_len == 0
        || frame_len > MAX_FRAME_SIZE
        || payload_capacity > MAX_PAYLOAD_SIZE
    {
        return JSRT_R1_INVALID_INPUT;
    }
    unsafe {
        let Some(length_output) =
            write_slice(payload_len_out.cast::<u8>(), core::mem::size_of::<usize>())
        else {
            return JSRT_R1_INVALID_INPUT;
        };
        length_output.fill(0);
        let Some(target_bytes) = read_slice(target, target_len) else {
            return JSRT_R1_INVALID_INPUT;
        };
        let Ok(target_text) = core::str::from_utf8(target_bytes) else {
            return JSRT_R1_INVALID_INPUT;
        };
        let Some(binding_bytes) = read_slice(binding, binding_len) else {
            return JSRT_R1_INVALID_INPUT;
        };
        let Some(frame_bytes) = read_slice(frame, frame_len) else {
            return JSRT_R1_INVALID_INPUT;
        };
        let runtime = match Runtime::for_target_triple(target_text, binding_bytes) {
            Ok(runtime) => runtime,
            Err(RuntimeError::Platform(_)) => return JSRT_R1_UNSUPPORTED_TARGET,
            Err(RuntimeError::Binding(_)) => return JSRT_R1_INVALID_INPUT,
            Err(_) => return JSRT_R1_INTERNAL_ERROR,
        };
        let payload = match runtime.open_payload(frame_bytes) {
            Ok(payload) => payload,
            Err(_) => return JSRT_R1_AUTHENTICATION_FAILED,
        };
        let payload_len = payload.len();
        if payload_len > payload_capacity {
            write_usize(length_output, payload_len);
            return JSRT_R1_BUFFER_TOO_SMALL;
        }
        let Some(output) = write_slice(payload_out, payload_len) else {
            return JSRT_R1_INVALID_INPUT;
        };
        output.copy_from_slice(&payload);
        write_usize(length_output, payload_len);
        JSRT_R1_OK
    }
}

unsafe fn read_slice<'a>(pointer: *const u8, length: usize) -> Option<&'a [u8]> {
    if length == 0 {
        return Some(&[]);
    }
    if pointer.is_null() {
        return None;
    }
    Some(core::slice::from_raw_parts(pointer, length))
}

unsafe fn write_slice<'a>(pointer: *mut u8, length: usize) -> Option<&'a mut [u8]> {
    if length == 0 {
        return Some(&mut []);
    }
    if pointer.is_null() {
        return None;
    }
    Some(core::slice::from_raw_parts_mut(pointer, length))
}

unsafe fn write_usize(bytes: &mut [u8], value: usize) {
    let destination = bytes.as_mut_ptr().cast::<usize>();
    destination.write_unaligned(value);
}

mod jni_bridge {
    use super::*;
    use jsrt_runtime::SupportedTarget;
    use jsrt_vm::{
        InvokeKind, ObjectOperations, VmError, VmExecutor, VmHostError, VmProgram, VmValue,
    };
    use std::os::raw::{c_char, c_void};
    use std::sync::{Mutex, MutexGuard, OnceLock};

    type JInt = i32;
    type JLong = i64;
    type JBoolean = u8;
    type JByte = i8;
    type JChar = u16;
    type JShort = i16;
    type JFloat = f32;
    type JDouble = f64;
    type JSize = i32;
    type JObject = *mut c_void;
    type JClass = JObject;
    type JString = JObject;
    type JByteArray = JObject;
    type JObjectArray = JObject;
    type JNIEnv = *mut *const JniNativeInterface;
    type JavaVM = *mut *const JniInvokeInterface;

    const JNI_OK: JInt = 0;
    const JNI_ERR: JInt = -1;
    const JNI_ABORT: JInt = 2;
    const JNI_VERSION_1_8: JInt = 0x0001_0008;
    const JNI_NATIVE_INTERFACE_SIZE: usize = 303;
    const JNI_INVOKE_INTERFACE_SIZE: usize = 8;
    const MAX_CATALOG_DIRECTORY_SIZE: usize = 64 * 1024 * 1024;
    const MAX_CATALOG_BUNDLE_SIZE: usize = 64 * 1024 * 1024;
    const MAX_CATALOG_PATH_SIZE: usize = 4096;
    const MAX_CATALOG_PAGE_SIZE: usize = 16 * 1024 * 1024 + 1024;

    // The table layout is the stable JNI 1.8 layout from jni.h. Keeping the
    // raw table confined to this module makes the rest of the workspace safe.
    #[repr(C)]
    struct JniNativeInterface {
        entries: [*const c_void; JNI_NATIVE_INTERFACE_SIZE],
    }

    #[repr(C)]
    pub struct JniInvokeInterface {
        entries: [*const c_void; JNI_INVOKE_INTERFACE_SIZE],
    }

    #[repr(C)]
    struct JniNativeMethod {
        name: *const c_char,
        signature: *const c_char,
        fn_ptr: *mut c_void,
    }

    const FIND_CLASS_INDEX: usize = 6;
    const NEW_GLOBAL_REF_INDEX: usize = 21;
    const DELETE_GLOBAL_REF_INDEX: usize = 22;
    // These indices are the JDK 8+ JNINativeInterface_ layout, including
    // the four reserved entries at the head of jni.h.
    const THROW_NEW_INDEX: usize = 14;
    const EXCEPTION_OCCURRED_INDEX: usize = 15;
    const PUSH_LOCAL_FRAME_INDEX: usize = 19;
    const POP_LOCAL_FRAME_INDEX: usize = 20;
    const DELETE_LOCAL_REF_INDEX: usize = 23;
    const EXCEPTION_CLEAR_INDEX: usize = 17;
    const ALLOC_OBJECT_INDEX: usize = 27;
    const IS_SAME_OBJECT_INDEX: usize = 24;
    const NEW_OBJECT_A_INDEX: usize = 30;
    const GET_OBJECT_CLASS_INDEX: usize = 31;
    const IS_INSTANCE_OF_INDEX: usize = 32;
    const GET_METHOD_ID_INDEX: usize = 33;
    const CALL_OBJECT_METHOD_A_INDEX: usize = 36;
    const CALL_BOOLEAN_METHOD_A_INDEX: usize = 39;
    const CALL_BYTE_METHOD_A_INDEX: usize = 42;
    const CALL_CHAR_METHOD_A_INDEX: usize = 45;
    const CALL_SHORT_METHOD_A_INDEX: usize = 48;
    const CALL_INT_METHOD_A_INDEX: usize = 51;
    const CALL_LONG_METHOD_A_INDEX: usize = 54;
    const CALL_FLOAT_METHOD_A_INDEX: usize = 57;
    const CALL_DOUBLE_METHOD_A_INDEX: usize = 60;
    const CALL_VOID_METHOD_A_INDEX: usize = 63;
    const CALL_NONVIRTUAL_OBJECT_METHOD_A_INDEX: usize = 66;
    const CALL_NONVIRTUAL_BOOLEAN_METHOD_A_INDEX: usize = 69;
    const CALL_NONVIRTUAL_BYTE_METHOD_A_INDEX: usize = 72;
    const CALL_NONVIRTUAL_CHAR_METHOD_A_INDEX: usize = 75;
    const CALL_NONVIRTUAL_SHORT_METHOD_A_INDEX: usize = 78;
    const CALL_NONVIRTUAL_INT_METHOD_A_INDEX: usize = 81;
    const CALL_NONVIRTUAL_LONG_METHOD_A_INDEX: usize = 84;
    const CALL_NONVIRTUAL_FLOAT_METHOD_A_INDEX: usize = 87;
    const CALL_NONVIRTUAL_DOUBLE_METHOD_A_INDEX: usize = 90;
    const CALL_NONVIRTUAL_VOID_METHOD_A_INDEX: usize = 93;
    const GET_FIELD_ID_INDEX: usize = 94;
    const GET_OBJECT_FIELD_INDEX: usize = 95;
    const GET_BOOLEAN_FIELD_INDEX: usize = 96;
    const GET_BYTE_FIELD_INDEX: usize = 97;
    const GET_CHAR_FIELD_INDEX: usize = 98;
    const GET_SHORT_FIELD_INDEX: usize = 99;
    const GET_INT_FIELD_INDEX: usize = 100;
    const GET_LONG_FIELD_INDEX: usize = 101;
    const GET_FLOAT_FIELD_INDEX: usize = 102;
    const GET_DOUBLE_FIELD_INDEX: usize = 103;
    const SET_OBJECT_FIELD_INDEX: usize = 104;
    const SET_BOOLEAN_FIELD_INDEX: usize = 105;
    const SET_BYTE_FIELD_INDEX: usize = 106;
    const SET_CHAR_FIELD_INDEX: usize = 107;
    const SET_SHORT_FIELD_INDEX: usize = 108;
    const SET_INT_FIELD_INDEX: usize = 109;
    const SET_LONG_FIELD_INDEX: usize = 110;
    const SET_FLOAT_FIELD_INDEX: usize = 111;
    const SET_DOUBLE_FIELD_INDEX: usize = 112;
    const GET_STATIC_METHOD_ID_INDEX: usize = 113;
    const CALL_STATIC_OBJECT_METHOD_A_INDEX: usize = 116;
    const CALL_STATIC_BOOLEAN_METHOD_A_INDEX: usize = 119;
    const CALL_STATIC_BYTE_METHOD_A_INDEX: usize = 122;
    const CALL_STATIC_CHAR_METHOD_A_INDEX: usize = 125;
    const CALL_STATIC_SHORT_METHOD_A_INDEX: usize = 128;
    const CALL_STATIC_INT_METHOD_A_INDEX: usize = 131;
    const CALL_STATIC_LONG_METHOD_A_INDEX: usize = 134;
    const CALL_STATIC_FLOAT_METHOD_A_INDEX: usize = 137;
    const CALL_STATIC_DOUBLE_METHOD_A_INDEX: usize = 140;
    const CALL_STATIC_VOID_METHOD_A_INDEX: usize = 143;
    const GET_STATIC_FIELD_ID_INDEX: usize = 144;
    const GET_STATIC_OBJECT_FIELD_INDEX: usize = 145;
    const GET_STATIC_BOOLEAN_FIELD_INDEX: usize = 146;
    const GET_STATIC_BYTE_FIELD_INDEX: usize = 147;
    const GET_STATIC_CHAR_FIELD_INDEX: usize = 148;
    const GET_STATIC_SHORT_FIELD_INDEX: usize = 149;
    const GET_STATIC_INT_FIELD_INDEX: usize = 150;
    const GET_STATIC_LONG_FIELD_INDEX: usize = 151;
    const GET_STATIC_FLOAT_FIELD_INDEX: usize = 152;
    const GET_STATIC_DOUBLE_FIELD_INDEX: usize = 153;
    const SET_STATIC_OBJECT_FIELD_INDEX: usize = 154;
    const SET_STATIC_BOOLEAN_FIELD_INDEX: usize = 155;
    const SET_STATIC_BYTE_FIELD_INDEX: usize = 156;
    const SET_STATIC_CHAR_FIELD_INDEX: usize = 157;
    const SET_STATIC_SHORT_FIELD_INDEX: usize = 158;
    const SET_STATIC_INT_FIELD_INDEX: usize = 159;
    const SET_STATIC_LONG_FIELD_INDEX: usize = 160;
    const SET_STATIC_FLOAT_FIELD_INDEX: usize = 161;
    const SET_STATIC_DOUBLE_FIELD_INDEX: usize = 162;
    const NEW_STRING_UTF_INDEX: usize = 167;
    const NEW_BYTE_ARRAY_INDEX: usize = 176;
    const SET_BYTE_ARRAY_REGION_INDEX: usize = 208;
    const SET_BOOLEAN_ARRAY_REGION_INDEX: usize = 207;
    const SET_CHAR_ARRAY_REGION_INDEX: usize = 209;
    const SET_SHORT_ARRAY_REGION_INDEX: usize = 210;
    const SET_INT_ARRAY_REGION_INDEX: usize = 211;
    const SET_LONG_ARRAY_REGION_INDEX: usize = 212;
    const SET_FLOAT_ARRAY_REGION_INDEX: usize = 213;
    const SET_DOUBLE_ARRAY_REGION_INDEX: usize = 214;
    const GET_STRING_UTF_LENGTH_INDEX: usize = 168;
    const GET_STRING_UTF_CHARS_INDEX: usize = 169;
    const RELEASE_STRING_UTF_CHARS_INDEX: usize = 170;
    const GET_ARRAY_LENGTH_INDEX: usize = 171;
    const NEW_OBJECT_ARRAY_INDEX: usize = 172;
    const GET_OBJECT_ARRAY_ELEMENT_INDEX: usize = 173;
    const SET_OBJECT_ARRAY_ELEMENT_INDEX: usize = 174;
    const NEW_BOOLEAN_ARRAY_INDEX: usize = 175;
    const GET_BYTE_ARRAY_ELEMENTS_INDEX: usize = 184;
    const NEW_CHAR_ARRAY_INDEX: usize = 177;
    const NEW_SHORT_ARRAY_INDEX: usize = 178;
    const NEW_INT_ARRAY_INDEX: usize = 179;
    const NEW_LONG_ARRAY_INDEX: usize = 180;
    const NEW_FLOAT_ARRAY_INDEX: usize = 181;
    const NEW_DOUBLE_ARRAY_INDEX: usize = 182;
    const GET_BOOLEAN_ARRAY_ELEMENTS_INDEX: usize = 183;
    const GET_CHAR_ARRAY_ELEMENTS_INDEX: usize = 185;
    const GET_SHORT_ARRAY_ELEMENTS_INDEX: usize = 186;
    const GET_INT_ARRAY_ELEMENTS_INDEX: usize = 187;
    const GET_LONG_ARRAY_ELEMENTS_INDEX: usize = 188;
    const GET_FLOAT_ARRAY_ELEMENTS_INDEX: usize = 189;
    const GET_DOUBLE_ARRAY_ELEMENTS_INDEX: usize = 190;
    const RELEASE_BOOLEAN_ARRAY_ELEMENTS_INDEX: usize = 191;
    const RELEASE_BYTE_ARRAY_ELEMENTS_INDEX: usize = 192;
    const RELEASE_CHAR_ARRAY_ELEMENTS_INDEX: usize = 193;
    const RELEASE_SHORT_ARRAY_ELEMENTS_INDEX: usize = 194;
    const RELEASE_INT_ARRAY_ELEMENTS_INDEX: usize = 195;
    const RELEASE_LONG_ARRAY_ELEMENTS_INDEX: usize = 196;
    const RELEASE_FLOAT_ARRAY_ELEMENTS_INDEX: usize = 197;
    const RELEASE_DOUBLE_ARRAY_ELEMENTS_INDEX: usize = 198;
    const REGISTER_NATIVES_INDEX: usize = 215;
    const UNREGISTER_NATIVES_INDEX: usize = 216;
    const MONITOR_ENTER_INDEX: usize = 217;
    const MONITOR_EXIT_INDEX: usize = 218;
    const EXCEPTION_CHECK_INDEX: usize = 228;
    const GET_ENV_INDEX: usize = 6;

    const TARGET_CLASS: &[u8] =
        b"io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper\0";
    const SECURITY_EXCEPTION_CLASS: &[u8] = b"java/lang/SecurityException\0";
    const DEFENSE_DEBUG_SURFACE: u8 = 1;
    const DEFENSE_VM_SURFACE: u8 = 1 << 1;
    const DEFENSE_ABI_PROBE_SURFACE: u8 = 1 << 2;
    const DEFENSE_SHARE_DOMAIN: &[u8] = b"JavaShroud/AKEN-R2/UnifiedDefense/v2";

    #[derive(Default)]
    struct BridgeState {
        target: Option<SupportedTarget>,
        initialized: bool,
        session_nonce: Option<Vec<u8>>,
        defense_surface_mask: u8,
        defense_profile: Option<DefenseProfile>,
        registered: bool,
        registered_class: Option<usize>,
        router: TypedPageRouter,
    }

    impl BridgeState {
        fn initialize(&mut self, target: SupportedTarget) -> Result<(), BridgeFailure> {
            if let Some(existing) = self.target {
                if existing != target {
                    return Err(BridgeFailure("AKEN-R1 target changed after initialization"));
                }
            }
            self.target = Some(target);
            self.initialized = true;
            Ok(())
        }

        fn install_nonce(&mut self, nonce: Vec<u8>) -> Result<(), BridgeFailure> {
            if !self.initialized {
                return Err(BridgeFailure(
                    "AKEN-R1 session nonce arrived before initialization",
                ));
            }
            if nonce.len() != 32 {
                return Err(BridgeFailure("AKEN-R1 session nonce length is invalid"));
            }
            if let Some(mut previous) = self.session_nonce.replace(nonce) {
                wipe(&mut previous);
            }
            Ok(())
        }

        fn reset_runtime(&mut self) {
            self.target = None;
            self.initialized = false;
            if let Some(mut nonce) = self.session_nonce.take() {
                wipe(&mut nonce);
            }
            self.defense_surface_mask = 0;
            self.defense_profile = None;
            self.router.clear();
        }

        fn clear(&mut self) {
            self.reset_runtime();
            self.registered = false;
            self.registered_class = None;
        }
    }

    impl Drop for BridgeState {
        fn drop(&mut self) {
            self.clear();
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct BridgeFailure(&'static str);

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum DefenseProfile {
        Balanced,
        Hardened,
    }

    impl DefenseProfile {
        fn parse(value: &[u8]) -> Result<Self, BridgeFailure> {
            match value {
                b"balanced" => Ok(Self::Balanced),
                b"hardened" => Ok(Self::Hardened),
                _ => Err(BridgeFailure("AKEN unified defense profile is invalid")),
            }
        }

        fn label(self) -> &'static [u8] {
            match self {
                Self::Balanced => b"balanced",
                Self::Hardened => b"hardened",
            }
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum DefenseSurface {
        OsAntiDebug,
        OsAntiVm,
        AbiProbe,
    }

    impl DefenseSurface {
        fn parse(value: &[u8]) -> Result<Self, BridgeFailure> {
            match value {
                b"os-anti-debug" => Ok(Self::OsAntiDebug),
                b"os-anti-vm" => Ok(Self::OsAntiVm),
                b"abi-probe" => Ok(Self::AbiProbe),
                _ => Err(BridgeFailure("AKEN unified defense surface is invalid")),
            }
        }

        fn mask(self) -> u8 {
            match self {
                Self::OsAntiDebug => DEFENSE_DEBUG_SURFACE,
                Self::OsAntiVm => DEFENSE_VM_SURFACE,
                Self::AbiProbe => DEFENSE_ABI_PROBE_SURFACE,
            }
        }

        fn needs_platform_probe(self) -> bool {
            !matches!(self, Self::AbiProbe)
        }
    }

    fn bridge_state() -> &'static Mutex<BridgeState> {
        static STATE: OnceLock<Mutex<BridgeState>> = OnceLock::new();
        STATE.get_or_init(|| Mutex::new(BridgeState::default()))
    }

    fn lock_state() -> Result<MutexGuard<'static, BridgeState>, BridgeFailure> {
        bridge_state()
            .lock()
            .map_err(|_| BridgeFailure("AKEN-R1 bridge state is poisoned"))
    }

    fn wipe(bytes: &mut [u8]) {
        for byte in bytes {
            // volatile writes prevent the compiler from removing secret
            // clearing when the buffer is otherwise dead.
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
    }

    struct WipedBytes(Vec<u8>);

    impl WipedBytes {
        fn as_bytes(&self) -> &[u8] {
            &self.0
        }

        fn into_inner(mut self) -> Vec<u8> {
            core::mem::take(&mut self.0)
        }
    }

    impl Drop for WipedBytes {
        fn drop(&mut self) {
            wipe(&mut self.0);
        }
    }

    struct JniObjectOperations {
        env: JNIEnv,
        // Global reference to the sealed/relocated Java helper owner registered
        // during JNI_OnLoad.  Never rediscover this class by its source owner:
        // current-format artifacts may relocate the helper package.
        helper_class: Option<JClass>,
        owned: Vec<JObject>,
        pending_exception: Option<(String, JObject)>,
    }

    impl JniObjectOperations {
        fn new(env: JNIEnv, helper_class: Option<JClass>) -> Self {
            Self {
                env,
                helper_class,
                owned: Vec::new(),
                pending_exception: None,
            }
        }

        fn own(&mut self, object: JObject) -> JObject {
            if !object.is_null() {
                self.owned.push(object);
            }
            object
        }

        fn release(&mut self, object: JObject) {
            if object.is_null() {
                return;
            }
            if let Some(index) = self.owned.iter().position(|candidate| *candidate == object) {
                self.owned.swap_remove(index);
            }
        }

        fn class_name(&self, owner: &str) -> Result<std::ffi::CString, VmHostError> {
            std::ffi::CString::new(owner).map_err(|_| VmHostError::Failure)
        }

        unsafe fn find_class_checked(&self, owner: &str) -> Result<JClass, VmHostError> {
            let owner = self.class_name(owner)?;
            let class = find_class(self.env, owner.as_bytes_with_nul())
                .ok_or_else(|| VmHostError::Failure)?;
            Ok(class)
        }

        unsafe fn method_id(
            &self,
            class: JClass,
            name: &str,
            descriptor: &str,
            static_method: bool,
        ) -> Result<*const c_void, VmHostError> {
            let name = std::ffi::CString::new(name).map_err(|_| VmHostError::Failure)?;
            let descriptor =
                std::ffi::CString::new(descriptor).map_err(|_| VmHostError::Failure)?;
            let entry = native_entry(
                self.env,
                if static_method {
                    GET_STATIC_METHOD_ID_INDEX
                } else {
                    GET_METHOD_ID_INDEX
                },
            )
            .ok_or(VmHostError::Failure)?;
            let function: unsafe extern "system" fn(
                JNIEnv,
                JClass,
                *const c_char,
                *const c_char,
            ) -> *const c_void = core::mem::transmute(entry);
            let method = function(self.env, class, name.as_ptr(), descriptor.as_ptr());
            if method.is_null() {
                clear_exception(self.env);
                return Err(VmHostError::Failure);
            }
            Ok(method)
        }

        unsafe fn call_method(
            &mut self,
            kind: InvokeKind,
            class: JClass,
            receiver: Option<JObject>,
            method: *const c_void,
            return_tag: u8,
            args: *const JValue,
        ) -> Result<VmValue<JObject>, VmHostError> {
            let is_static = matches!(kind, InvokeKind::Static | InvokeKind::Dynamic);
            let is_nonvirtual = matches!(kind, InvokeKind::Special);
            let target = if is_static {
                class
            } else {
                receiver.ok_or(VmHostError::Failure)?
            };
            let index = match (is_static, is_nonvirtual, return_tag) {
                (true, _, b'V') => CALL_STATIC_VOID_METHOD_A_INDEX,
                (true, _, b'Z') => CALL_STATIC_BOOLEAN_METHOD_A_INDEX,
                (true, _, b'B') => CALL_STATIC_BYTE_METHOD_A_INDEX,
                (true, _, b'C') => CALL_STATIC_CHAR_METHOD_A_INDEX,
                (true, _, b'S') => CALL_STATIC_SHORT_METHOD_A_INDEX,
                (true, _, b'I') => CALL_STATIC_INT_METHOD_A_INDEX,
                (true, _, b'J') => CALL_STATIC_LONG_METHOD_A_INDEX,
                (true, _, b'F') => CALL_STATIC_FLOAT_METHOD_A_INDEX,
                (true, _, b'D') => CALL_STATIC_DOUBLE_METHOD_A_INDEX,
                (true, _, b'L' | b'[') => CALL_STATIC_OBJECT_METHOD_A_INDEX,
                (false, true, b'V') => CALL_NONVIRTUAL_VOID_METHOD_A_INDEX,
                (false, true, b'Z') => CALL_NONVIRTUAL_BOOLEAN_METHOD_A_INDEX,
                (false, true, b'B') => CALL_NONVIRTUAL_BYTE_METHOD_A_INDEX,
                (false, true, b'C') => CALL_NONVIRTUAL_CHAR_METHOD_A_INDEX,
                (false, true, b'S') => CALL_NONVIRTUAL_SHORT_METHOD_A_INDEX,
                (false, true, b'I') => CALL_NONVIRTUAL_INT_METHOD_A_INDEX,
                (false, true, b'J') => CALL_NONVIRTUAL_LONG_METHOD_A_INDEX,
                (false, true, b'F') => CALL_NONVIRTUAL_FLOAT_METHOD_A_INDEX,
                (false, true, b'D') => CALL_NONVIRTUAL_DOUBLE_METHOD_A_INDEX,
                (false, true, b'L' | b'[') => CALL_NONVIRTUAL_OBJECT_METHOD_A_INDEX,
                (false, false, b'V') => CALL_VOID_METHOD_A_INDEX,
                (false, false, b'Z') => CALL_BOOLEAN_METHOD_A_INDEX,
                (false, false, b'B') => CALL_BYTE_METHOD_A_INDEX,
                (false, false, b'C') => CALL_CHAR_METHOD_A_INDEX,
                (false, false, b'S') => CALL_SHORT_METHOD_A_INDEX,
                (false, false, b'I') => CALL_INT_METHOD_A_INDEX,
                (false, false, b'J') => CALL_LONG_METHOD_A_INDEX,
                (false, false, b'F') => CALL_FLOAT_METHOD_A_INDEX,
                (false, false, b'D') => CALL_DOUBLE_METHOD_A_INDEX,
                (false, false, b'L' | b'[') => CALL_OBJECT_METHOD_A_INDEX,
                _ => return Err(VmHostError::Failure),
            };
            let entry = native_entry(self.env, index).ok_or(VmHostError::Failure)?;
            let value = match return_tag {
                b'V' => {
                    let f: unsafe extern "system" fn(
                        JNIEnv,
                        JObject,
                        *const c_void,
                        *const JValue,
                    ) = core::mem::transmute(entry);
                    if is_static {
                        f(self.env, target, method, args)
                    } else if is_nonvirtual {
                        let f: unsafe extern "system" fn(
                            JNIEnv,
                            JObject,
                            JClass,
                            *const c_void,
                            *const JValue,
                        ) = core::mem::transmute(entry);
                        f(self.env, target, class, method, args);
                    } else {
                        f(self.env, target, method, args);
                    }
                    VmValue::Null
                }
                b'Z' => {
                    if is_nonvirtual {
                        let f: unsafe extern "system" fn(
                            JNIEnv,
                            JObject,
                            JClass,
                            *const c_void,
                            *const JValue,
                        ) -> JBoolean = core::mem::transmute(entry);
                        VmValue::Int(i32::from(f(self.env, target, class, method, args) != 0))
                    } else {
                        let f: unsafe extern "system" fn(
                            JNIEnv,
                            JObject,
                            *const c_void,
                            *const JValue,
                        ) -> JBoolean = core::mem::transmute(entry);
                        VmValue::Int(i32::from(f(self.env, target, method, args) != 0))
                    }
                }
                b'B' | b'C' | b'S' | b'I' => {
                    let value = if is_nonvirtual {
                        let f: unsafe extern "system" fn(
                            JNIEnv,
                            JObject,
                            JClass,
                            *const c_void,
                            *const JValue,
                        ) -> JInt = core::mem::transmute(entry);
                        f(self.env, target, class, method, args)
                    } else {
                        let f: unsafe extern "system" fn(
                            JNIEnv,
                            JObject,
                            *const c_void,
                            *const JValue,
                        ) -> JInt = core::mem::transmute(entry);
                        f(self.env, target, method, args)
                    };
                    VmValue::Int(value)
                }
                b'J' => {
                    let value = if is_nonvirtual {
                        let f: unsafe extern "system" fn(
                            JNIEnv,
                            JObject,
                            JClass,
                            *const c_void,
                            *const JValue,
                        ) -> JLong = core::mem::transmute(entry);
                        f(self.env, target, class, method, args)
                    } else {
                        let f: unsafe extern "system" fn(
                            JNIEnv,
                            JObject,
                            *const c_void,
                            *const JValue,
                        ) -> JLong = core::mem::transmute(entry);
                        f(self.env, target, method, args)
                    };
                    VmValue::Long(value)
                }
                b'F' => {
                    let value = if is_nonvirtual {
                        let f: unsafe extern "system" fn(
                            JNIEnv,
                            JObject,
                            JClass,
                            *const c_void,
                            *const JValue,
                        ) -> JFloat = core::mem::transmute(entry);
                        f(self.env, target, class, method, args)
                    } else {
                        let f: unsafe extern "system" fn(
                            JNIEnv,
                            JObject,
                            *const c_void,
                            *const JValue,
                        ) -> JFloat = core::mem::transmute(entry);
                        f(self.env, target, method, args)
                    };
                    VmValue::Float(value)
                }
                b'D' => {
                    let value = if is_nonvirtual {
                        let f: unsafe extern "system" fn(
                            JNIEnv,
                            JObject,
                            JClass,
                            *const c_void,
                            *const JValue,
                        ) -> JDouble = core::mem::transmute(entry);
                        f(self.env, target, class, method, args)
                    } else {
                        let f: unsafe extern "system" fn(
                            JNIEnv,
                            JObject,
                            *const c_void,
                            *const JValue,
                        ) -> JDouble = core::mem::transmute(entry);
                        f(self.env, target, method, args)
                    };
                    VmValue::Double(value)
                }
                b'L' | b'[' => {
                    let object = if is_static {
                        let f: unsafe extern "system" fn(
                            JNIEnv,
                            JClass,
                            *const c_void,
                            *const JValue,
                        ) -> JObject = core::mem::transmute(entry);
                        f(self.env, target, method, args)
                    } else if is_nonvirtual {
                        let f: unsafe extern "system" fn(
                            JNIEnv,
                            JObject,
                            JClass,
                            *const c_void,
                            *const JValue,
                        ) -> JObject = core::mem::transmute(entry);
                        f(self.env, target, class, method, args)
                    } else {
                        let f: unsafe extern "system" fn(
                            JNIEnv,
                            JObject,
                            *const c_void,
                            *const JValue,
                        ) -> JObject = core::mem::transmute(entry);
                        f(self.env, target, method, args)
                    };
                    if object.is_null() {
                        VmValue::Null
                    } else {
                        VmValue::Object(self.own(object))
                    }
                }
                _ => return Err(VmHostError::Failure),
            };
            Ok(value)
        }

        /// Preserve the throwable raised by the immediately preceding JNI host
        /// operation so the VM can dispatch it through its exception table.
        ///
        /// JNI permits only a small set of operations while an exception is
        /// pending.  Capture and clear the exception first, then query the
        /// throwable class with a normal JNI call sequence.
        unsafe fn capture_pending_exception(&mut self) -> Result<(), VmHostError> {
            if self.pending_exception.is_some() || !exception_pending(self.env) {
                return Err(VmHostError::Failure);
            }
            let throwable = exception_occurred(self.env).ok_or(VmHostError::Failure)?;
            let throwable = self.own(throwable);
            clear_exception(self.env);
            let class_name = match self.throwable_class(&throwable) {
                Ok(Some(class_name)) => class_name,
                _ => {
                    clear_exception(self.env);
                    self.release(throwable);
                    delete_local_ref(self.env, throwable);
                    return Err(VmHostError::Failure);
                }
            };
            self.pending_exception = Some((class_name, throwable));
            Ok(())
        }

        unsafe fn field_id(
            &self,
            class: JClass,
            name: &str,
            descriptor: &str,
            static_field: bool,
        ) -> Result<*const c_void, VmHostError> {
            let name = std::ffi::CString::new(name).map_err(|_| VmHostError::Failure)?;
            let descriptor =
                std::ffi::CString::new(descriptor).map_err(|_| VmHostError::Failure)?;
            let entry = native_entry(
                self.env,
                if static_field {
                    GET_STATIC_FIELD_ID_INDEX
                } else {
                    GET_FIELD_ID_INDEX
                },
            )
            .ok_or(VmHostError::Failure)?;
            let function: unsafe extern "system" fn(
                JNIEnv,
                JClass,
                *const c_char,
                *const c_char,
            ) -> *const c_void = core::mem::transmute(entry);
            let field = function(self.env, class, name.as_ptr(), descriptor.as_ptr());
            if field.is_null() {
                clear_exception(self.env);
                return Err(VmHostError::Failure);
            }
            Ok(field)
        }

        unsafe fn get_field_value(
            &self,
            opcode: u16,
            target: JObject,
            field: *const c_void,
            tag: u8,
        ) -> Result<VmValue<JObject>, VmHostError> {
            let is_static = opcode == jsrt_vm::opcode::GETSTATIC;
            let index = match (is_static, tag) {
                (true, b'Z') => GET_STATIC_BOOLEAN_FIELD_INDEX,
                (true, b'B') => GET_STATIC_BYTE_FIELD_INDEX,
                (true, b'C') => GET_STATIC_CHAR_FIELD_INDEX,
                (true, b'S') => GET_STATIC_SHORT_FIELD_INDEX,
                (true, b'I') => GET_STATIC_INT_FIELD_INDEX,
                (true, b'J') => GET_STATIC_LONG_FIELD_INDEX,
                (true, b'F') => GET_STATIC_FLOAT_FIELD_INDEX,
                (true, b'D') => GET_STATIC_DOUBLE_FIELD_INDEX,
                (true, b'L' | b'[') => GET_STATIC_OBJECT_FIELD_INDEX,
                (false, b'Z') => GET_BOOLEAN_FIELD_INDEX,
                (false, b'B') => GET_BYTE_FIELD_INDEX,
                (false, b'C') => GET_CHAR_FIELD_INDEX,
                (false, b'S') => GET_SHORT_FIELD_INDEX,
                (false, b'I') => GET_INT_FIELD_INDEX,
                (false, b'J') => GET_LONG_FIELD_INDEX,
                (false, b'F') => GET_FLOAT_FIELD_INDEX,
                (false, b'D') => GET_DOUBLE_FIELD_INDEX,
                (false, b'L' | b'[') => GET_OBJECT_FIELD_INDEX,
                _ => return Err(VmHostError::Failure),
            };
            let entry = native_entry(self.env, index).ok_or(VmHostError::Failure)?;
            let value = match (is_static, tag) {
                (true, b'Z') => {
                    let f: unsafe extern "system" fn(JNIEnv, JClass, *const c_void) -> JBoolean =
                        core::mem::transmute(entry);
                    VmValue::Int(i32::from(f(self.env, target, field) != 0))
                }
                (false, b'Z') => {
                    let f: unsafe extern "system" fn(JNIEnv, JObject, *const c_void) -> JBoolean =
                        core::mem::transmute(entry);
                    VmValue::Int(i32::from(f(self.env, target, field) != 0))
                }
                (true, b'B') => {
                    let f: unsafe extern "system" fn(JNIEnv, JClass, *const c_void) -> JByte =
                        core::mem::transmute(entry);
                    VmValue::Int(i32::from(f(self.env, target, field)))
                }
                (false, b'B') => {
                    let f: unsafe extern "system" fn(JNIEnv, JObject, *const c_void) -> JByte =
                        core::mem::transmute(entry);
                    VmValue::Int(i32::from(f(self.env, target, field)))
                }
                (true, b'C') => {
                    let f: unsafe extern "system" fn(JNIEnv, JClass, *const c_void) -> JChar =
                        core::mem::transmute(entry);
                    VmValue::Int(i32::from(f(self.env, target, field)))
                }
                (false, b'C') => {
                    let f: unsafe extern "system" fn(JNIEnv, JObject, *const c_void) -> JChar =
                        core::mem::transmute(entry);
                    VmValue::Int(i32::from(f(self.env, target, field)))
                }
                (true, b'S') => {
                    let f: unsafe extern "system" fn(JNIEnv, JClass, *const c_void) -> JShort =
                        core::mem::transmute(entry);
                    VmValue::Int(i32::from(f(self.env, target, field)))
                }
                (false, b'S') => {
                    let f: unsafe extern "system" fn(JNIEnv, JObject, *const c_void) -> JShort =
                        core::mem::transmute(entry);
                    VmValue::Int(i32::from(f(self.env, target, field)))
                }
                (true, b'I') => {
                    let f: unsafe extern "system" fn(JNIEnv, JClass, *const c_void) -> JInt =
                        core::mem::transmute(entry);
                    VmValue::Int(f(self.env, target, field))
                }
                (false, b'I') => {
                    let f: unsafe extern "system" fn(JNIEnv, JObject, *const c_void) -> JInt =
                        core::mem::transmute(entry);
                    VmValue::Int(f(self.env, target, field))
                }
                (true, b'J') => {
                    let f: unsafe extern "system" fn(JNIEnv, JClass, *const c_void) -> JLong =
                        core::mem::transmute(entry);
                    VmValue::Long(f(self.env, target, field))
                }
                (false, b'J') => {
                    let f: unsafe extern "system" fn(JNIEnv, JObject, *const c_void) -> JLong =
                        core::mem::transmute(entry);
                    VmValue::Long(f(self.env, target, field))
                }
                (true, b'F') => {
                    let f: unsafe extern "system" fn(JNIEnv, JClass, *const c_void) -> JFloat =
                        core::mem::transmute(entry);
                    VmValue::Float(f(self.env, target, field))
                }
                (false, b'F') => {
                    let f: unsafe extern "system" fn(JNIEnv, JObject, *const c_void) -> JFloat =
                        core::mem::transmute(entry);
                    VmValue::Float(f(self.env, target, field))
                }
                (true, b'D') => {
                    let f: unsafe extern "system" fn(JNIEnv, JClass, *const c_void) -> JDouble =
                        core::mem::transmute(entry);
                    VmValue::Double(f(self.env, target, field))
                }
                (false, b'D') => {
                    let f: unsafe extern "system" fn(JNIEnv, JObject, *const c_void) -> JDouble =
                        core::mem::transmute(entry);
                    VmValue::Double(f(self.env, target, field))
                }
                (true, b'L' | b'[') => {
                    let f: unsafe extern "system" fn(JNIEnv, JClass, *const c_void) -> JObject =
                        core::mem::transmute(entry);
                    let object = f(self.env, target, field);
                    if object.is_null() {
                        VmValue::Null
                    } else {
                        VmValue::Object(object)
                    }
                }
                (false, b'L' | b'[') => {
                    let f: unsafe extern "system" fn(JNIEnv, JObject, *const c_void) -> JObject =
                        core::mem::transmute(entry);
                    let object = f(self.env, target, field);
                    if object.is_null() {
                        VmValue::Null
                    } else {
                        VmValue::Object(object)
                    }
                }
                _ => return Err(VmHostError::Failure),
            };
            if exception_pending(self.env) {
                clear_exception(self.env);
                return Err(VmHostError::Failure);
            }
            Ok(value)
        }

        unsafe fn set_field_value(
            &self,
            opcode: u16,
            target: JObject,
            field: *const c_void,
            tag: u8,
            value: VmValue<JObject>,
        ) -> Result<(), VmHostError> {
            let is_static = opcode == jsrt_vm::opcode::PUTSTATIC;

            macro_rules! set_scalar {
                ($index:expr, $ty:ty, $scalar:expr) => {{
                    let entry = native_entry(self.env, $index).ok_or(VmHostError::Failure)?;
                    let scalar: $ty = $scalar;
                    if is_static {
                        let f: unsafe extern "system" fn(JNIEnv, JClass, *const c_void, $ty) =
                            core::mem::transmute(entry);
                        f(self.env, target, field, scalar);
                    } else {
                        let f: unsafe extern "system" fn(JNIEnv, JObject, *const c_void, $ty) =
                            core::mem::transmute(entry);
                        f(self.env, target, field, scalar);
                    }
                }};
            }

            macro_rules! set_object {
                ($index:expr, $object:expr) => {{
                    let entry = native_entry(self.env, $index).ok_or(VmHostError::Failure)?;
                    let object: JObject = $object;
                    if is_static {
                        let f: unsafe extern "system" fn(JNIEnv, JClass, *const c_void, JObject) =
                            core::mem::transmute(entry);
                        f(self.env, target, field, object);
                    } else {
                        let f: unsafe extern "system" fn(JNIEnv, JObject, *const c_void, JObject) =
                            core::mem::transmute(entry);
                        f(self.env, target, field, object);
                    }
                }};
            }

            match (is_static, tag) {
                (true, b'Z') | (false, b'Z') => set_scalar!(
                    if is_static {
                        SET_STATIC_BOOLEAN_FIELD_INDEX
                    } else {
                        SET_BOOLEAN_FIELD_INDEX
                    },
                    JBoolean,
                    match value {
                        VmValue::Int(v) => u8::from(v != 0),
                        _ => return Err(VmHostError::Failure),
                    }
                ),
                (true, b'B') | (false, b'B') => set_scalar!(
                    if is_static {
                        SET_STATIC_BYTE_FIELD_INDEX
                    } else {
                        SET_BYTE_FIELD_INDEX
                    },
                    JByte,
                    match value {
                        VmValue::Int(v) => v as JByte,
                        _ => return Err(VmHostError::Failure),
                    }
                ),
                (true, b'C') | (false, b'C') => set_scalar!(
                    if is_static {
                        SET_STATIC_CHAR_FIELD_INDEX
                    } else {
                        SET_CHAR_FIELD_INDEX
                    },
                    JChar,
                    match value {
                        VmValue::Int(v) => v as JChar,
                        _ => return Err(VmHostError::Failure),
                    }
                ),
                (true, b'S') | (false, b'S') => set_scalar!(
                    if is_static {
                        SET_STATIC_SHORT_FIELD_INDEX
                    } else {
                        SET_SHORT_FIELD_INDEX
                    },
                    JShort,
                    match value {
                        VmValue::Int(v) => v as JShort,
                        _ => return Err(VmHostError::Failure),
                    }
                ),
                (true, b'I') | (false, b'I') => set_scalar!(
                    if is_static {
                        SET_STATIC_INT_FIELD_INDEX
                    } else {
                        SET_INT_FIELD_INDEX
                    },
                    JInt,
                    match value {
                        VmValue::Int(v) => v,
                        _ => return Err(VmHostError::Failure),
                    }
                ),
                (true, b'J') | (false, b'J') => set_scalar!(
                    if is_static {
                        SET_STATIC_LONG_FIELD_INDEX
                    } else {
                        SET_LONG_FIELD_INDEX
                    },
                    JLong,
                    match value {
                        VmValue::Long(v) => v,
                        VmValue::Int(v) => i64::from(v),
                        _ => return Err(VmHostError::Failure),
                    }
                ),
                (true, b'F') | (false, b'F') => set_scalar!(
                    if is_static {
                        SET_STATIC_FLOAT_FIELD_INDEX
                    } else {
                        SET_FLOAT_FIELD_INDEX
                    },
                    JFloat,
                    match value {
                        VmValue::Float(v) => v,
                        VmValue::Int(v) => v as JFloat,
                        _ => return Err(VmHostError::Failure),
                    }
                ),
                (true, b'D') | (false, b'D') => set_scalar!(
                    if is_static {
                        SET_STATIC_DOUBLE_FIELD_INDEX
                    } else {
                        SET_DOUBLE_FIELD_INDEX
                    },
                    JDouble,
                    match value {
                        VmValue::Double(v) => v,
                        VmValue::Float(v) => f64::from(v),
                        VmValue::Int(v) => f64::from(v),
                        _ => return Err(VmHostError::Failure),
                    }
                ),
                (true, b'L' | b'[') | (false, b'L' | b'[') => set_object!(
                    if is_static {
                        SET_STATIC_OBJECT_FIELD_INDEX
                    } else {
                        SET_OBJECT_FIELD_INDEX
                    },
                    match value {
                        VmValue::Object(v) => v,
                        VmValue::Null => core::ptr::null_mut(),
                        _ => return Err(VmHostError::Failure),
                    }
                ),
                _ => return Err(VmHostError::Failure),
            }
            if exception_pending(self.env) {
                clear_exception(self.env);
                return Err(VmHostError::Failure);
            }
            Ok(())
        }

        unsafe fn new_string(&mut self, value: &str) -> Result<JObject, VmHostError> {
            let bytes = std::ffi::CString::new(value).map_err(|_| VmHostError::Failure)?;
            let object =
                new_string_utf(self.env, bytes.as_bytes_with_nul()).ok_or(VmHostError::Failure)?;
            Ok(self.own(object))
        }

        unsafe fn object_array_values(&self, array: JObject) -> Result<Vec<JObject>, VmHostError> {
            if array.is_null() {
                return Ok(Vec::new());
            }
            let length_entry =
                native_entry(self.env, GET_ARRAY_LENGTH_INDEX).ok_or(VmHostError::Failure)?;
            let length: unsafe extern "system" fn(JNIEnv, JObject) -> JSize =
                core::mem::transmute(length_entry);
            let count = length(self.env, array);
            if count < 0 || count > 4096 {
                return Err(VmHostError::Failure);
            }
            let entry = native_entry(self.env, GET_OBJECT_ARRAY_ELEMENT_INDEX)
                .ok_or(VmHostError::Failure)?;
            let get: unsafe extern "system" fn(JNIEnv, JObject, JSize) -> JObject =
                core::mem::transmute(entry);
            let mut values = Vec::with_capacity(count as usize);
            for index in 0..count {
                let value = get(self.env, array, index);
                if value.is_null() {
                    clear_exception(self.env);
                }
                values.push(value);
            }
            Ok(values)
        }

        unsafe fn unbox(
            &mut self,
            object: JObject,
            tag: u8,
        ) -> Result<VmValue<JObject>, VmHostError> {
            if object.is_null() {
                return Err(VmHostError::Failure);
            }
            let (class_name, method_name, descriptor) = match tag {
                b'Z' => ("java/lang/Boolean", "booleanValue", "()Z"),
                b'B' => ("java/lang/Byte", "byteValue", "()B"),
                b'C' => ("java/lang/Character", "charValue", "()C"),
                b'S' => ("java/lang/Short", "shortValue", "()S"),
                b'I' => ("java/lang/Integer", "intValue", "()I"),
                b'J' => ("java/lang/Long", "longValue", "()J"),
                b'F' => ("java/lang/Float", "floatValue", "()F"),
                b'D' => ("java/lang/Double", "doubleValue", "()D"),
                _ => return Ok(VmValue::Object(object)),
            };
            let class = self.find_class_checked(class_name)?;
            let method = self.method_id(class, method_name, descriptor, false)?;
            let args: [JValue; 0] = [];
            let value = match tag {
                b'Z' => {
                    let entry = native_entry(self.env, CALL_BOOLEAN_METHOD_A_INDEX)
                        .ok_or(VmHostError::Failure)?;
                    let f: unsafe extern "system" fn(
                        JNIEnv,
                        JObject,
                        *const c_void,
                        *const JValue,
                    ) -> JBoolean = core::mem::transmute(entry);
                    VmValue::Int(i32::from(
                        f(self.env, object, method, jvalue_ptr(&args)) != 0,
                    ))
                }
                b'B' => {
                    let entry = native_entry(self.env, CALL_BYTE_METHOD_A_INDEX)
                        .ok_or(VmHostError::Failure)?;
                    let f: unsafe extern "system" fn(
                        JNIEnv,
                        JObject,
                        *const c_void,
                        *const JValue,
                    ) -> JByte = core::mem::transmute(entry);
                    VmValue::Int(i32::from(f(self.env, object, method, jvalue_ptr(&args))))
                }
                b'C' => {
                    let entry = native_entry(self.env, CALL_CHAR_METHOD_A_INDEX)
                        .ok_or(VmHostError::Failure)?;
                    let f: unsafe extern "system" fn(
                        JNIEnv,
                        JObject,
                        *const c_void,
                        *const JValue,
                    ) -> JChar = core::mem::transmute(entry);
                    VmValue::Int(i32::from(f(self.env, object, method, jvalue_ptr(&args))))
                }
                b'S' => {
                    let entry = native_entry(self.env, CALL_SHORT_METHOD_A_INDEX)
                        .ok_or(VmHostError::Failure)?;
                    let f: unsafe extern "system" fn(
                        JNIEnv,
                        JObject,
                        *const c_void,
                        *const JValue,
                    ) -> JShort = core::mem::transmute(entry);
                    VmValue::Int(i32::from(f(self.env, object, method, jvalue_ptr(&args))))
                }
                b'I' => {
                    let entry = native_entry(self.env, CALL_INT_METHOD_A_INDEX)
                        .ok_or(VmHostError::Failure)?;
                    let f: unsafe extern "system" fn(
                        JNIEnv,
                        JObject,
                        *const c_void,
                        *const JValue,
                    ) -> JInt = core::mem::transmute(entry);
                    VmValue::Int(f(self.env, object, method, jvalue_ptr(&args)))
                }
                b'J' => {
                    let entry = native_entry(self.env, CALL_LONG_METHOD_A_INDEX)
                        .ok_or(VmHostError::Failure)?;
                    let f: unsafe extern "system" fn(
                        JNIEnv,
                        JObject,
                        *const c_void,
                        *const JValue,
                    ) -> JLong = core::mem::transmute(entry);
                    VmValue::Long(f(self.env, object, method, jvalue_ptr(&args)))
                }
                b'F' => {
                    let entry = native_entry(self.env, CALL_FLOAT_METHOD_A_INDEX)
                        .ok_or(VmHostError::Failure)?;
                    let f: unsafe extern "system" fn(
                        JNIEnv,
                        JObject,
                        *const c_void,
                        *const JValue,
                    ) -> JFloat = core::mem::transmute(entry);
                    VmValue::Float(f(self.env, object, method, jvalue_ptr(&args)))
                }
                b'D' => {
                    let entry = native_entry(self.env, CALL_DOUBLE_METHOD_A_INDEX)
                        .ok_or(VmHostError::Failure)?;
                    let f: unsafe extern "system" fn(
                        JNIEnv,
                        JObject,
                        *const c_void,
                        *const JValue,
                    ) -> JDouble = core::mem::transmute(entry);
                    VmValue::Double(f(self.env, object, method, jvalue_ptr(&args)))
                }
                _ => return Err(VmHostError::Failure),
            };
            if unsafe { exception_pending(self.env) } {
                unsafe { clear_exception(self.env) };
                return Err(VmHostError::Failure);
            }
            Ok(value)
        }
    }

    impl Drop for JniObjectOperations {
        fn drop(&mut self) {
            for object in self.owned.drain(..) {
                unsafe { delete_local_ref(self.env, object) };
            }
        }
    }

    fn parse_type_tag(bytes: &[u8], cursor: &mut usize, allow_void: bool) -> Option<u8> {
        let tag = *bytes.get(*cursor)?;
        match tag {
            b'[' => {
                while bytes.get(*cursor) == Some(&b'[') {
                    *cursor += 1;
                }
                match bytes.get(*cursor).copied()? {
                    b'L' => {
                        let end = bytes[*cursor + 1..].iter().position(|byte| *byte == b';')?;
                        *cursor += end + 2;
                    }
                    b'Z' | b'B' | b'C' | b'S' | b'I' | b'J' | b'F' | b'D' => *cursor += 1,
                    _ => return None,
                }
                Some(b'[')
            }
            b'L' => {
                let end = bytes[*cursor + 1..].iter().position(|byte| *byte == b';')?;
                *cursor += end + 2;
                Some(b'L')
            }
            b'V' if allow_void => {
                *cursor += 1;
                Some(b'V')
            }
            b'Z' | b'B' | b'C' | b'S' | b'I' | b'J' | b'F' | b'D' => {
                *cursor += 1;
                Some(tag)
            }
            _ => None,
        }
    }

    fn parse_method_descriptor(descriptor: &str) -> Result<(Vec<u8>, u8), VmHostError> {
        let bytes = descriptor.as_bytes();
        if bytes.first() != Some(&b'(') {
            return Err(VmHostError::Failure);
        }
        let mut cursor = 1usize;
        let mut arguments = Vec::new();
        while bytes.get(cursor) != Some(&b')') {
            arguments.push(parse_type_tag(bytes, &mut cursor, false).ok_or(VmHostError::Failure)?);
            if arguments.len() > 1024 {
                return Err(VmHostError::Failure);
            }
        }
        cursor += 1;
        let return_tag = parse_type_tag(bytes, &mut cursor, true).ok_or(VmHostError::Failure)?;
        if cursor != bytes.len() {
            return Err(VmHostError::Failure);
        }
        Ok((arguments, return_tag))
    }

    fn parse_member_reference(reference: &str) -> Result<(&str, &str, &str), VmHostError> {
        let (member, descriptor) = reference.rsplit_once(':').ok_or(VmHostError::Failure)?;
        let (owner, name) = member.rsplit_once('.').ok_or(VmHostError::Failure)?;
        if owner.is_empty() || name.is_empty() || descriptor.is_empty() {
            return Err(VmHostError::Failure);
        }
        Ok((owner, name, descriptor))
    }

    // JNI Call*MethodA permits a null jvalue pointer when the method has no
    // arguments.  Vec::as_ptr() on an empty vector is a dangling, non-null
    // pointer (typically 0x1), which is not a valid JNI argument array and
    // can corrupt HotSpot while dispatching zero-argument methods.
    fn jvalue_ptr(values: &[JValue]) -> *const JValue {
        if values.is_empty() {
            core::ptr::null()
        } else {
            values.as_ptr()
        }
    }

    fn primitive_value(value: &VmValue<JObject>, tag: u8) -> Result<JValue, VmHostError> {
        let result = match tag {
            b'Z' => JValue {
                z: match value {
                    VmValue::Int(value) => u8::from(*value != 0),
                    _ => return Err(VmHostError::Failure),
                },
            },
            b'B' => JValue {
                b: match value {
                    VmValue::Int(value) => *value as JByte,
                    _ => return Err(VmHostError::Failure),
                },
            },
            b'C' => JValue {
                c: match value {
                    VmValue::Int(value) => *value as JChar,
                    _ => return Err(VmHostError::Failure),
                },
            },
            b'S' => JValue {
                s: match value {
                    VmValue::Int(value) => *value as JShort,
                    _ => return Err(VmHostError::Failure),
                },
            },
            b'I' => JValue {
                i: match value {
                    VmValue::Int(value) => *value,
                    _ => return Err(VmHostError::Failure),
                },
            },
            b'J' => JValue {
                j: match value {
                    VmValue::Long(value) => *value,
                    VmValue::Int(value) => i64::from(*value),
                    _ => return Err(VmHostError::Failure),
                },
            },
            b'F' => JValue {
                f: match value {
                    VmValue::Float(value) => *value,
                    VmValue::Int(value) => *value as f32,
                    _ => return Err(VmHostError::Failure),
                },
            },
            b'D' => JValue {
                d: match value {
                    VmValue::Double(value) => *value,
                    VmValue::Float(value) => f64::from(*value),
                    VmValue::Int(value) => f64::from(*value),
                    _ => return Err(VmHostError::Failure),
                },
            },
            b'L' | b'[' => JValue {
                l: match value {
                    VmValue::Object(value) => *value,
                    VmValue::Null => core::ptr::null_mut(),
                    _ => return Err(VmHostError::Failure),
                },
            },
            _ => return Err(VmHostError::Failure),
        };
        Ok(result)
    }

    impl ObjectOperations for JniObjectOperations {
        type Object = JObject;

        fn invoke(
            &mut self,
            kind: InvokeKind,
            reference: &str,
            receiver: Option<&Self::Object>,
            arguments: &[VmValue<Self::Object>],
        ) -> Result<VmValue<Self::Object>, VmHostError> {
            // Current-format SAM lambdas are encoded by the serializer as a
            // compact recipe rather than as a JVM constant-pool handle.  The
            // Java helper already owns the class-loader/private-lookup logic
            // needed to link the implementation method, so route the recipe
            // through its typed factory instead of attempting to parse it as a
            // normal owner.name:descriptor reference.  The latter used to
            // turn every lambda into a synthetic LinkageError, which broke
            // ThreadPoolExecutor.submit in the acceptance fixture.
            if matches!(kind, InvokeKind::Dynamic) && reference.starts_with("lambda|") {
                let mut fields = reference.split('|');
                let _ = fields.next();
                let sam_name = fields.next().ok_or(VmHostError::Failure)?;
                let factory_descriptor = fields.next().ok_or(VmHostError::Failure)?;
                let impl_tag = fields
                    .next()
                    .ok_or(VmHostError::Failure)?
                    .parse::<i32>()
                    .map_err(|_| VmHostError::Failure)?;
                let owner = fields.next().ok_or(VmHostError::Failure)?;
                let name = fields.next().ok_or(VmHostError::Failure)?;
                let descriptor = fields.next().ok_or(VmHostError::Failure)?;
                let sam_descriptor = fields.next().ok_or(VmHostError::Failure)?;
                let instantiated_descriptor = fields.next().ok_or(VmHostError::Failure)?;
                let encoded_options = fields.next().ok_or(VmHostError::Failure)?;
                if fields.next().is_some() {
                    return Err(VmHostError::Failure);
                }
                let (argument_tags, return_tag) = parse_method_descriptor(factory_descriptor)?;
                if argument_tags.len() != arguments.len() || return_tag != b'L' {
                    return Err(VmHostError::Failure);
                }

                // Materialize the captured values into Object[].  Primitive
                // captures are boxed exactly once for the Java helper call;
                // object/null captures are passed through unchanged.
                let object_class = unsafe { self.find_class_checked("java/lang/Object")? };
                let new_array_entry = unsafe { native_entry(self.env, NEW_OBJECT_ARRAY_INDEX) }
                    .ok_or(VmHostError::Failure)?;
                let new_array: unsafe extern "system" fn(
                    JNIEnv,
                    JSize,
                    JClass,
                    JObject,
                ) -> JObject = unsafe { core::mem::transmute(new_array_entry) };
                let captured_array = unsafe {
                    new_array(
                        self.env,
                        arguments.len() as JSize,
                        object_class,
                        core::ptr::null_mut(),
                    )
                };
                if captured_array.is_null() || unsafe { exception_pending(self.env) } {
                    unsafe { clear_exception(self.env) };
                    return Err(VmHostError::Failure);
                }
                let captured_array = self.own(captured_array);
                let set_entry = unsafe { native_entry(self.env, SET_OBJECT_ARRAY_ELEMENT_INDEX) }
                    .ok_or(VmHostError::Failure)?;
                let set_element: unsafe extern "system" fn(JNIEnv, JObject, JSize, JObject) =
                    unsafe { core::mem::transmute(set_entry) };
                let mut boxed = Vec::new();
                for (index, (tag, value)) in argument_tags.iter().zip(arguments.iter()).enumerate()
                {
                    let object = match tag {
                        b'L' | b'[' => match value {
                            VmValue::Object(object) => *object,
                            VmValue::Null => core::ptr::null_mut(),
                            _ => return Err(VmHostError::Failure),
                        },
                        b'Z' | b'B' | b'C' | b'S' | b'I' | b'J' | b'F' | b'D' => {
                            let object = unsafe {
                                box_vm_value_with_tag(self.env, value.clone(), Some(*tag))
                            }
                            .ok_or(VmHostError::Failure)?;
                            boxed.push(object);
                            object
                        }
                        _ => return Err(VmHostError::Failure),
                    };
                    unsafe { set_element(self.env, captured_array, index as JSize, object) };
                    if unsafe { exception_pending(self.env) } {
                        unsafe { clear_exception(self.env) };
                        for object in boxed.drain(..) {
                            unsafe { delete_local_ref(self.env, object) };
                        }
                        return Err(VmHostError::Failure);
                    }
                }

                let helper_class = self.helper_class.ok_or(VmHostError::Failure)?;
                let helper_method = unsafe {
                    self.method_id(
                        helper_class,
                        "createSamLambda",
                        "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;",
                        true,
                    )?
                };
                let sam_name_object = unsafe { self.new_string(sam_name)? };
                let factory_descriptor_object = unsafe { self.new_string(factory_descriptor)? };
                let owner_object = unsafe { self.new_string(owner)? };
                let name_object = unsafe { self.new_string(name)? };
                let descriptor_object = unsafe { self.new_string(descriptor)? };
                let sam_descriptor_object = unsafe { self.new_string(sam_descriptor)? };
                let instantiated_descriptor_object =
                    unsafe { self.new_string(instantiated_descriptor)? };
                let options_object = unsafe { self.new_string(encoded_options)? };
                let values = [
                    JValue { l: sam_name_object },
                    JValue {
                        l: factory_descriptor_object,
                    },
                    JValue { l: owner_object },
                    JValue { l: name_object },
                    JValue {
                        l: descriptor_object,
                    },
                    JValue { i: impl_tag },
                    JValue {
                        l: sam_descriptor_object,
                    },
                    JValue {
                        l: instantiated_descriptor_object,
                    },
                    JValue { l: options_object },
                    JValue { l: captured_array },
                ];
                let result = unsafe {
                    self.call_method(
                        InvokeKind::Static,
                        helper_class,
                        None,
                        helper_method,
                        b'L',
                        jvalue_ptr(&values),
                    )
                };
                for object in boxed {
                    unsafe { delete_local_ref(self.env, object) };
                }
                if unsafe { exception_pending(self.env) } {
                    unsafe {
                        let _ = self.capture_pending_exception();
                    }
                    return Err(VmHostError::Failure);
                }
                return result;
            }
            if matches!(kind, InvokeKind::Dynamic) && reference.starts_with("mhstatic|") {
                let mut fields = reference.split('|');
                let _ = fields.next();
                let _call_name = fields.next().ok_or(VmHostError::Failure)?;
                let _call_descriptor = fields.next().ok_or(VmHostError::Failure)?;
                let owner = fields.next().ok_or(VmHostError::Failure)?;
                let name = fields.next().ok_or(VmHostError::Failure)?;
                let descriptor = fields.next().ok_or(VmHostError::Failure)?;
                if fields.next().is_some() {
                    return Err(VmHostError::Failure);
                }
                let (argument_tags, return_tag) = parse_method_descriptor(descriptor)?;
                if argument_tags.len() != arguments.len() {
                    return Err(VmHostError::Failure);
                }
                let values = argument_tags
                    .iter()
                    .zip(arguments.iter())
                    .map(|(tag, value)| primitive_value(value, *tag))
                    .collect::<Result<Vec<_>, _>>()?;
                let class = unsafe { self.find_class_checked(owner)? };
                let method = unsafe { self.method_id(class, name, descriptor, true)? };
                let result = unsafe {
                    self.call_method(
                        InvokeKind::Static,
                        class,
                        None,
                        method,
                        return_tag,
                        jvalue_ptr(&values),
                    )?
                };
                if unsafe { exception_pending(self.env) } {
                    unsafe {
                        let _ = self.capture_pending_exception();
                    }
                    return Err(VmHostError::Failure);
                }
                return Ok(result);
            }
            let (owner, name, descriptor) =
                parse_member_reference(reference).map_err(|error| error)?;
            let (argument_tags, return_tag) = parse_method_descriptor(descriptor)?;
            if argument_tags.len() != arguments.len() {
                return Err(VmHostError::Failure);
            }
            let values = argument_tags
                .iter()
                .zip(arguments.iter())
                .map(|(tag, value)| primitive_value(value, *tag))
                .collect::<Result<Vec<_>, _>>()?;
            let class = unsafe { self.find_class_checked(owner)? };
            let is_static = matches!(kind, InvokeKind::Static | InvokeKind::Dynamic);
            let method = unsafe { self.method_id(class, name, descriptor, is_static)? };
            let result = unsafe {
                self.call_method(
                    kind,
                    class,
                    receiver.copied(),
                    method,
                    return_tag,
                    jvalue_ptr(&values),
                )?
            };
            if unsafe { exception_pending(self.env) } {
                unsafe {
                    let _ = self.capture_pending_exception();
                }
                return Err(VmHostError::Failure);
            }
            Ok(result)
        }

        fn take_pending_exception(&mut self) -> Option<(String, Self::Object)> {
            // Keep the captured throwable in `owned` for the whole VM execution
            // lifetime.  Exception tables may retain it across handler probes,
            // nested calls, and frame unwinding; removing it here lets the
            // enclosing host drop delete a reference that the VM still holds.
            self.pending_exception.take()
        }

        fn new_object(&mut self, class_name: &str) -> Result<Self::Object, VmHostError> {
            let class = unsafe { self.find_class_checked(class_name)? };
            let entry = unsafe { native_entry(self.env, ALLOC_OBJECT_INDEX) }
                .ok_or(VmHostError::Failure)?;
            let alloc: unsafe extern "system" fn(JNIEnv, JClass) -> JObject =
                unsafe { core::mem::transmute(entry) };
            let object = unsafe { alloc(self.env, class) };
            if object.is_null() || unsafe { exception_pending(self.env) } {
                unsafe { clear_exception(self.env) };
                return Err(VmHostError::Failure);
            }
            Ok(self.own(object))
        }

        fn new_primitive_array(
            &mut self,
            kind: i32,
            length: i32,
        ) -> Result<Self::Object, VmHostError> {
            if length < 0 {
                return Err(VmHostError::Failure);
            }
            let index = match kind {
                4 => NEW_BOOLEAN_ARRAY_INDEX,
                5 => NEW_CHAR_ARRAY_INDEX,
                6 => NEW_FLOAT_ARRAY_INDEX,
                7 => NEW_DOUBLE_ARRAY_INDEX,
                8 => NEW_BYTE_ARRAY_INDEX,
                9 => NEW_SHORT_ARRAY_INDEX,
                10 => NEW_INT_ARRAY_INDEX,
                11 => NEW_LONG_ARRAY_INDEX,
                _ => return Err(VmHostError::Unsupported),
            };
            let entry = unsafe { native_entry(self.env, index) }.ok_or(VmHostError::Failure)?;
            let function: unsafe extern "system" fn(JNIEnv, JSize) -> JObject =
                unsafe { core::mem::transmute(entry) };
            let object = unsafe { function(self.env, length) };
            if object.is_null() || unsafe { exception_pending(self.env) } {
                unsafe { clear_exception(self.env) };
                return Err(VmHostError::Failure);
            }
            Ok(self.own(object))
        }

        fn new_reference_array(
            &mut self,
            class_name: &str,
            length: i32,
        ) -> Result<Self::Object, VmHostError> {
            if length < 0 {
                return Err(VmHostError::Failure);
            }
            let element = unsafe { self.find_class_checked(class_name)? };
            let object = unsafe {
                let entry =
                    native_entry(self.env, NEW_OBJECT_ARRAY_INDEX).ok_or(VmHostError::Failure)?;
                let function: unsafe extern "system" fn(JNIEnv, JSize, JClass, JObject) -> JObject =
                    core::mem::transmute(entry);
                function(self.env, length, element, core::ptr::null_mut())
            };
            if object.is_null() || unsafe { exception_pending(self.env) } {
                unsafe { clear_exception(self.env) };
                return Err(VmHostError::Failure);
            }
            Ok(self.own(object))
        }

        fn new_multi_array(
            &mut self,
            descriptor: &str,
            dimensions: &[i32],
        ) -> Result<Self::Object, VmHostError> {
            if dimensions.is_empty() || dimensions.iter().any(|value| *value < 0) {
                return Err(VmHostError::Failure);
            }
            let class = unsafe { self.find_class_checked("java/lang/reflect/Array")? };
            let method = unsafe {
                self.method_id(
                    class,
                    "newInstance",
                    "(Ljava/lang/Class;[I)Ljava/lang/Object;",
                    true,
                )?
            };
            let component = descriptor.trim_start_matches('[');
            let component = if component.starts_with('L') {
                component.trim_start_matches('L').trim_end_matches(';')
            } else {
                "java/lang/Object"
            };
            let component_class = unsafe { self.find_class_checked(component)? };
            let array = self.new_primitive_array(10, dimensions.len() as i32)?;
            let entry = unsafe { native_entry(self.env, SET_INT_ARRAY_REGION_INDEX) }
                .ok_or(VmHostError::Failure)?;
            let set: unsafe extern "system" fn(JNIEnv, JObject, JSize, JSize, *const JInt) =
                unsafe { core::mem::transmute(entry) };
            unsafe {
                set(
                    self.env,
                    array,
                    0,
                    dimensions.len() as JSize,
                    dimensions.as_ptr(),
                )
            };
            let values = [JValue { l: component_class }, JValue { l: array }];
            let entry = unsafe { native_entry(self.env, CALL_STATIC_OBJECT_METHOD_A_INDEX) }
                .ok_or(VmHostError::Failure)?;
            let call: unsafe extern "system" fn(
                JNIEnv,
                JClass,
                *const c_void,
                *const JValue,
            ) -> JObject = unsafe { core::mem::transmute(entry) };
            let object = unsafe { call(self.env, class, method, values.as_ptr()) };
            if object.is_null() || unsafe { exception_pending(self.env) } {
                unsafe { clear_exception(self.env) };
                return Err(VmHostError::Failure);
            }
            Ok(self.own(object))
        }

        fn array_length(&mut self, array: &Self::Object) -> Result<i32, VmHostError> {
            let entry = unsafe { native_entry(self.env, GET_ARRAY_LENGTH_INDEX) }
                .ok_or(VmHostError::Failure)?;
            let function: unsafe extern "system" fn(JNIEnv, JObject) -> JSize =
                unsafe { core::mem::transmute(entry) };
            let length = unsafe { function(self.env, *array) };
            if length < 0 || unsafe { exception_pending(self.env) } {
                unsafe { clear_exception(self.env) };
                return Err(VmHostError::Failure);
            }
            Ok(length)
        }

        fn array_load(
            &mut self,
            opcode: u16,
            array: &Self::Object,
            index: i32,
        ) -> Result<VmValue<Self::Object>, VmHostError> {
            if index < 0 {
                return Err(VmHostError::Failure);
            }
            let len = self.array_length(array)?;
            if index >= len {
                return Err(VmHostError::Failure);
            }
            if opcode == jsrt_vm::opcode::AALOAD {
                let entry = unsafe { native_entry(self.env, GET_OBJECT_ARRAY_ELEMENT_INDEX) }
                    .ok_or(VmHostError::Failure)?;
                let get: unsafe extern "system" fn(JNIEnv, JObject, JSize) -> JObject =
                    unsafe { core::mem::transmute(entry) };
                return Ok(match unsafe { get(self.env, *array, index) } {
                    value if value.is_null() => VmValue::Null,
                    value => VmValue::Object(value),
                });
            }
            let (index, kind) = match opcode {
                jsrt_vm::opcode::IALOAD => (GET_INT_ARRAY_ELEMENTS_INDEX, b'I'),
                jsrt_vm::opcode::LALOAD => (GET_LONG_ARRAY_ELEMENTS_INDEX, b'J'),
                jsrt_vm::opcode::FALOAD => (GET_FLOAT_ARRAY_ELEMENTS_INDEX, b'F'),
                jsrt_vm::opcode::DALOAD => (GET_DOUBLE_ARRAY_ELEMENTS_INDEX, b'D'),
                jsrt_vm::opcode::BALOAD => (GET_BYTE_ARRAY_ELEMENTS_INDEX, b'B'),
                jsrt_vm::opcode::CALOAD => (GET_CHAR_ARRAY_ELEMENTS_INDEX, b'C'),
                jsrt_vm::opcode::SALOAD => (GET_SHORT_ARRAY_ELEMENTS_INDEX, b'S'),
                _ => return Err(VmHostError::Unsupported),
            };
            let entry = unsafe { native_entry(self.env, index) }.ok_or(VmHostError::Failure)?;
            let get: unsafe extern "system" fn(JNIEnv, JObject, *mut JBoolean) -> *mut c_void =
                unsafe { core::mem::transmute(entry) };
            let values = unsafe { get(self.env, *array, core::ptr::null_mut()) };
            if values.is_null() {
                unsafe { clear_exception(self.env) };
                return Err(VmHostError::Failure);
            }
            let value = unsafe {
                match kind {
                    b'I' => VmValue::Int((values.cast::<JInt>().add(index as usize)).read()),
                    b'J' => VmValue::Long((values.cast::<JLong>().add(index as usize)).read()),
                    b'F' => VmValue::Float((values.cast::<JFloat>().add(index as usize)).read()),
                    b'D' => VmValue::Double((values.cast::<JDouble>().add(index as usize)).read()),
                    b'B' => VmValue::Int(i32::from(
                        (values.cast::<JByte>().add(index as usize)).read(),
                    )),
                    b'C' => VmValue::Int(i32::from(
                        (values.cast::<JChar>().add(index as usize)).read(),
                    )),
                    b'S' => VmValue::Int(i32::from(
                        (values.cast::<JShort>().add(index as usize)).read(),
                    )),
                    _ => return Err(VmHostError::Failure),
                }
            };
            let release_index = match kind {
                b'I' => RELEASE_INT_ARRAY_ELEMENTS_INDEX,
                b'J' => RELEASE_LONG_ARRAY_ELEMENTS_INDEX,
                b'F' => RELEASE_FLOAT_ARRAY_ELEMENTS_INDEX,
                b'D' => RELEASE_DOUBLE_ARRAY_ELEMENTS_INDEX,
                b'B' => RELEASE_BYTE_ARRAY_ELEMENTS_INDEX,
                b'C' => RELEASE_CHAR_ARRAY_ELEMENTS_INDEX,
                b'S' => RELEASE_SHORT_ARRAY_ELEMENTS_INDEX,
                _ => return Err(VmHostError::Failure),
            };
            let release_entry =
                unsafe { native_entry(self.env, release_index) }.ok_or(VmHostError::Failure)?;
            let release: unsafe extern "system" fn(JNIEnv, JObject, *mut c_void, JInt) =
                unsafe { core::mem::transmute(release_entry) };
            unsafe { release(self.env, *array, values, JNI_ABORT) };
            Ok(value)
        }

        fn array_store(
            &mut self,
            opcode: u16,
            array: &Self::Object,
            index: i32,
            value: VmValue<Self::Object>,
        ) -> Result<(), VmHostError> {
            let length = self.array_length(array)?;
            if index < 0 || index >= length {
                return Err(VmHostError::Failure);
            }
            if opcode == jsrt_vm::opcode::AASTORE {
                let value = match value {
                    VmValue::Object(value) => value,
                    VmValue::Null => core::ptr::null_mut(),
                    _ => return Err(VmHostError::Failure),
                };
                let entry = unsafe { native_entry(self.env, SET_OBJECT_ARRAY_ELEMENT_INDEX) }
                    .ok_or(VmHostError::Failure)?;
                let set: unsafe extern "system" fn(JNIEnv, JObject, JSize, JObject) =
                    unsafe { core::mem::transmute(entry) };
                unsafe { set(self.env, *array, index, value) };
            } else {
                let (tag, set_index, ptr): (u8, usize, *const c_void) = match opcode {
                    jsrt_vm::opcode::IASTORE => {
                        (b'I', SET_INT_ARRAY_REGION_INDEX, core::ptr::null())
                    }
                    jsrt_vm::opcode::LASTORE => {
                        (b'J', SET_LONG_ARRAY_REGION_INDEX, core::ptr::null())
                    }
                    jsrt_vm::opcode::FASTORE => {
                        (b'F', SET_FLOAT_ARRAY_REGION_INDEX, core::ptr::null())
                    }
                    jsrt_vm::opcode::DASTORE => {
                        (b'D', SET_DOUBLE_ARRAY_REGION_INDEX, core::ptr::null())
                    }
                    jsrt_vm::opcode::BASTORE => {
                        (b'B', SET_BYTE_ARRAY_REGION_INDEX, core::ptr::null())
                    }
                    jsrt_vm::opcode::CASTORE => {
                        (b'C', SET_CHAR_ARRAY_REGION_INDEX, core::ptr::null())
                    }
                    jsrt_vm::opcode::SASTORE => {
                        (b'S', SET_SHORT_ARRAY_REGION_INDEX, core::ptr::null())
                    }
                    _ => return Err(VmHostError::Unsupported),
                };
                let entry =
                    unsafe { native_entry(self.env, set_index) }.ok_or(VmHostError::Failure)?;
                macro_rules! set_array {
                    ($ty:ty, $variant:ident, $cast:expr) => {{
                        let set: unsafe extern "system" fn(
                            JNIEnv,
                            JObject,
                            JSize,
                            JSize,
                            *const $ty,
                        ) = unsafe { core::mem::transmute(entry) };
                        let scalar: $ty = match value {
                            VmValue::$variant(v) => $cast(v),
                            VmValue::Int(v) if tag != b'J' && tag != b'F' && tag != b'D' => {
                                $cast(v)
                            }
                            _ => return Err(VmHostError::Failure),
                        };
                        unsafe { set(self.env, *array, index, 1, &scalar) };
                    }};
                }
                macro_rules! set_wide_array {
                    ($ty:ty, $variant:ident, $from_int:expr) => {{
                        let set: unsafe extern "system" fn(
                            JNIEnv,
                            JObject,
                            JSize,
                            JSize,
                            *const $ty,
                        ) = unsafe { core::mem::transmute(entry) };
                        let scalar: $ty = match value {
                            VmValue::$variant(v) => v,
                            VmValue::Int(v) => $from_int(v),
                            _ => return Err(VmHostError::Failure),
                        };
                        unsafe { set(self.env, *array, index, 1, &scalar) };
                    }};
                }
                match tag {
                    b'I' => set_array!(JInt, Int, |v| v),
                    b'J' => set_wide_array!(JLong, Long, |v: JInt| i64::from(v)),
                    b'F' => set_wide_array!(JFloat, Float, |v: JInt| v as JFloat),
                    b'D' => set_wide_array!(JDouble, Double, |v: JInt| v as JDouble),
                    b'B' => set_array!(JByte, Int, |v| v as JByte),
                    b'C' => set_array!(JChar, Int, |v| v as JChar),
                    b'S' => set_array!(JShort, Int, |v| v as JShort),
                    _ => return Err(VmHostError::Failure),
                };
            }
            if unsafe { exception_pending(self.env) } {
                unsafe { clear_exception(self.env) };
                return Err(VmHostError::Failure);
            }
            Ok(())
        }

        fn field_get(
            &mut self,
            opcode: u16,
            reference: &str,
            receiver: Option<&Self::Object>,
        ) -> Result<VmValue<Self::Object>, VmHostError> {
            let (owner, name, descriptor) = parse_member_reference(reference)?;
            let tag = parse_type_tag(descriptor.as_bytes(), &mut 0usize, true)
                .ok_or(VmHostError::Failure)?;
            let class = unsafe { self.find_class_checked(owner)? };
            let is_static = opcode == jsrt_vm::opcode::GETSTATIC;
            let field = unsafe { self.field_id(class, name, descriptor, is_static)? };
            let target = receiver.copied().unwrap_or(class);
            let result = unsafe { self.get_field_value(opcode, target, field, tag) }?;
            Ok(result)
        }

        fn field_put(
            &mut self,
            opcode: u16,
            reference: &str,
            receiver: Option<&Self::Object>,
            value: VmValue<Self::Object>,
        ) -> Result<(), VmHostError> {
            let (owner, name, descriptor) = parse_member_reference(reference)?;
            let tag = parse_type_tag(descriptor.as_bytes(), &mut 0usize, true)
                .ok_or(VmHostError::Failure)?;
            let class = unsafe { self.find_class_checked(owner)? };
            let is_static = opcode == jsrt_vm::opcode::PUTSTATIC;
            let field = unsafe { self.field_id(class, name, descriptor, is_static)? };
            let target = receiver.copied().unwrap_or(class);
            let result = unsafe { self.set_field_value(opcode, target, field, tag, value) };
            result
        }

        fn instance_of(
            &mut self,
            object: &Self::Object,
            class_name: &str,
        ) -> Result<bool, VmHostError> {
            let class = unsafe { self.find_class_checked(class_name)? };
            let entry = unsafe { native_entry(self.env, IS_INSTANCE_OF_INDEX) }
                .ok_or(VmHostError::Failure)?;
            let function: unsafe extern "system" fn(JNIEnv, JObject, JClass) -> JBoolean =
                unsafe { core::mem::transmute(entry) };
            Ok(unsafe { function(self.env, *object, class) != 0 })
        }

        fn same_object(
            &mut self,
            left: &Self::Object,
            right: &Self::Object,
        ) -> Result<bool, VmHostError> {
            let entry = unsafe { native_entry(self.env, IS_SAME_OBJECT_INDEX) }
                .ok_or(VmHostError::Failure)?;
            let function: unsafe extern "system" fn(JNIEnv, JObject, JObject) -> JBoolean =
                unsafe { core::mem::transmute(entry) };
            Ok(unsafe { function(self.env, *left, *right) != 0 })
        }

        fn cast(
            &mut self,
            object: Self::Object,
            class_name: &str,
        ) -> Result<Self::Object, VmHostError> {
            if object.is_null() || self.instance_of(&object, class_name)? {
                Ok(object)
            } else {
                Err(VmHostError::Failure)
            }
        }

        fn throwable_class(
            &mut self,
            object: &Self::Object,
        ) -> Result<Option<String>, VmHostError> {
            if object.is_null() {
                return Ok(None);
            }
            let class = unsafe { native_entry(self.env, GET_OBJECT_CLASS_INDEX) }
                .ok_or(VmHostError::Failure)?;
            let get_class: unsafe extern "system" fn(JNIEnv, JObject) -> JClass =
                unsafe { core::mem::transmute(class) };
            let object_class = unsafe { get_class(self.env, *object) };
            let class_class = unsafe { self.find_class_checked("java/lang/Class")? };
            let method =
                unsafe { self.method_id(class_class, "getName", "()Ljava/lang/String;", false)? };
            let entry = unsafe { native_entry(self.env, CALL_OBJECT_METHOD_A_INDEX) }
                .ok_or(VmHostError::Failure)?;
            let call: unsafe extern "system" fn(
                JNIEnv,
                JObject,
                *const c_void,
                *const JValue,
            ) -> JObject = unsafe { core::mem::transmute(entry) };
            let name = unsafe { call(self.env, object_class, method, core::ptr::null()) };
            if name.is_null() {
                return Ok(None);
            }
            let value =
                unsafe { copy_jstring(self.env, name) }.map_err(|_| VmHostError::Failure)?;
            unsafe { delete_local_ref(self.env, name) };
            Ok(value.map(|class_name| class_name.replace('.', "/")))
        }

        fn monitor_enter(&mut self, object: &Self::Object) -> Result<(), VmHostError> {
            let entry = unsafe { native_entry(self.env, MONITOR_ENTER_INDEX) }
                .ok_or(VmHostError::Failure)?;
            let function: unsafe extern "system" fn(JNIEnv, JObject) -> JInt =
                unsafe { core::mem::transmute(entry) };
            if unsafe { function(self.env, *object) } != 0 {
                return Err(VmHostError::Failure);
            }
            Ok(())
        }

        fn monitor_exit(&mut self, object: &Self::Object) -> Result<(), VmHostError> {
            let entry = unsafe { native_entry(self.env, MONITOR_EXIT_INDEX) }
                .ok_or(VmHostError::Failure)?;
            let function: unsafe extern "system" fn(JNIEnv, JObject) -> JInt =
                unsafe { core::mem::transmute(entry) };
            if unsafe { function(self.env, *object) } != 0 {
                return Err(VmHostError::Failure);
            }
            Ok(())
        }

        fn string_constant(&mut self, value: &str) -> Result<Self::Object, VmHostError> {
            unsafe { self.new_string(value) }
        }

        fn type_constant(&mut self, descriptor: &str) -> Result<Self::Object, VmHostError> {
            if descriptor.is_empty() {
                return Err(VmHostError::Failure);
            }

            // ASM emits object class literals as `Lowner;`, array literals as
            // JVM array descriptors, and primitive literals as one-byte
            // descriptors.  JNI FindClass accepts the internal/array forms;
            // primitive Class objects are exposed through wrapper TYPE fields.
            let owner = if descriptor.starts_with('L') && descriptor.ends_with(';') {
                &descriptor[1..descriptor.len() - 1]
            } else {
                descriptor
            };
            let primitive_wrapper = match descriptor {
                "Z" => Some("java/lang/Boolean"),
                "B" => Some("java/lang/Byte"),
                "C" => Some("java/lang/Character"),
                "S" => Some("java/lang/Short"),
                "I" => Some("java/lang/Integer"),
                "J" => Some("java/lang/Long"),
                "F" => Some("java/lang/Float"),
                "D" => Some("java/lang/Double"),
                "V" => Some("java/lang/Void"),
                _ => None,
            };

            if let Some(wrapper_name) = primitive_wrapper {
                let wrapper = unsafe { self.find_class_checked(wrapper_name)? };
                let field = unsafe { self.field_id(wrapper, "TYPE", "Ljava/lang/Class;", true)? };
                let value = unsafe {
                    self.get_field_value(jsrt_vm::opcode::GETSTATIC, wrapper, field, b'L')?
                };
                unsafe { delete_local_ref(self.env, wrapper) };
                return match value {
                    VmValue::Object(object) if !object.is_null() => Ok(self.own(object)),
                    _ => Err(VmHostError::Failure),
                };
            }

            let class = unsafe { self.find_class_checked(owner)? };
            Ok(self.own(class))
        }
    }

    fn target_from_platform(bytes: &[u8]) -> Result<SupportedTarget, BridgeFailure> {
        match core::str::from_utf8(bytes)
            .map_err(|_| BridgeFailure("AKEN-R1 platform is not UTF-8"))?
        {
            "windows-x64" | "x86_64-pc-windows-gnu" => Ok(SupportedTarget::WindowsX64Gnu),
            "linux-x64" | "x86_64-unknown-linux-gnu.2.17" => Ok(SupportedTarget::LinuxX64Gnu217),
            _ => Err(BridgeFailure("AKEN-R1 platform is unsupported")),
        }
    }

    unsafe fn native_entry(env: JNIEnv, index: usize) -> Option<*const c_void> {
        if env.is_null() || (*env).is_null() || index >= JNI_NATIVE_INTERFACE_SIZE {
            return None;
        }
        Some((**env).entries[index])
    }

    unsafe fn invoke_get_env(vm: JavaVM, env_out: &mut *mut c_void) -> Option<JInt> {
        if vm.is_null() || (*vm).is_null() {
            return None;
        }
        let entry = (**vm).entries[GET_ENV_INDEX];
        if entry.is_null() {
            return None;
        }
        let function: unsafe extern "system" fn(JavaVM, *mut *mut c_void, JInt) -> JInt =
            core::mem::transmute(entry);
        Some(function(vm, env_out, JNI_VERSION_1_8))
    }

    unsafe fn find_class(env: JNIEnv, name: &[u8]) -> Option<JClass> {
        let entry = native_entry(env, FIND_CLASS_INDEX)?;
        let function: unsafe extern "system" fn(JNIEnv, *const c_char) -> JClass =
            core::mem::transmute(entry);
        let class = function(env, name.as_ptr().cast());
        (!class.is_null()).then_some(class)
    }

    fn vm_state_binding(entry_token: i64, resource_path: &str) -> String {
        let mut layout_hex = String::with_capacity(64);
        for byte in specialization::VM_LAYOUT_DIGEST {
            layout_hex.push_str(&format!("{:02x}", byte));
        }
        format!(
            "{:x}\u{0000}{}\u{0000}10429f6c\u{0000}{}",
            entry_token as u64, resource_path, layout_hex,
        )
    }

    unsafe fn throw_new(env: JNIEnv, message: &'static [u8]) {
        if env.is_null() {
            return;
        }
        clear_exception(env);
        let Some(entry) = native_entry(env, THROW_NEW_INDEX) else {
            return;
        };
        let Some(class) = find_class(env, SECURITY_EXCEPTION_CLASS) else {
            return;
        };
        let length = message
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(message.len());
        let Ok(message) = std::ffi::CString::new(&message[..length]) else {
            delete_local_ref(env, class);
            return;
        };
        let function: unsafe extern "system" fn(JNIEnv, JClass, *const c_char) -> JInt =
            core::mem::transmute(entry);
        let _ = function(env, class, message.as_ptr());
        delete_local_ref(env, class);
    }

    unsafe fn throw_named_exception(env: JNIEnv, class_name: &str) {
        if env.is_null() {
            return;
        }
        clear_exception(env);
        let Some(entry) = native_entry(env, THROW_NEW_INDEX) else {
            return;
        };
        let normalized = class_name.replace('.', "/");
        let Ok(class_name) = std::ffi::CString::new(normalized) else {
            return;
        };
        let Some(class) = find_class(env, class_name.as_bytes_with_nul()) else {
            clear_exception(env);
            return;
        };
        let empty = b"\0";
        let function: unsafe extern "system" fn(JNIEnv, JClass, *const c_char) -> JInt =
            core::mem::transmute(entry);
        let _ = function(env, class, empty.as_ptr().cast());
        delete_local_ref(env, class);
    }

    unsafe fn clear_exception(env: JNIEnv) {
        let Some(check_entry) = native_entry(env, EXCEPTION_CHECK_INDEX) else {
            return;
        };
        let check: unsafe extern "system" fn(JNIEnv) -> JBoolean =
            core::mem::transmute(check_entry);
        if check(env) == 0 {
            return;
        }
        if let Some(clear_entry) = native_entry(env, EXCEPTION_CLEAR_INDEX) {
            let clear: unsafe extern "system" fn(JNIEnv) = core::mem::transmute(clear_entry);
            clear(env);
        }
    }

    unsafe fn exception_pending(env: JNIEnv) -> bool {
        let Some(entry) = native_entry(env, EXCEPTION_CHECK_INDEX) else {
            return false;
        };
        let check: unsafe extern "system" fn(JNIEnv) -> JBoolean = core::mem::transmute(entry);
        check(env) != 0
    }

    unsafe fn exception_occurred(env: JNIEnv) -> Option<JObject> {
        let entry = native_entry(env, EXCEPTION_OCCURRED_INDEX)?;
        let occurred: unsafe extern "system" fn(JNIEnv) -> JObject = core::mem::transmute(entry);
        let throwable = occurred(env);
        (!throwable.is_null()).then_some(throwable)
    }

    unsafe fn push_local_frame(env: JNIEnv, capacity: JInt) -> bool {
        let Some(entry) = native_entry(env, PUSH_LOCAL_FRAME_INDEX) else {
            return false;
        };
        let push: unsafe extern "system" fn(JNIEnv, JInt) -> JInt = core::mem::transmute(entry);
        push(env, capacity) == JNI_OK
    }

    unsafe fn pop_local_frame(env: JNIEnv, result: JObject) -> JObject {
        let Some(entry) = native_entry(env, POP_LOCAL_FRAME_INDEX) else {
            return core::ptr::null_mut();
        };
        let pop: unsafe extern "system" fn(JNIEnv, JObject) -> JObject =
            core::mem::transmute(entry);
        pop(env, result)
    }

    unsafe fn delete_local_ref(env: JNIEnv, reference: JObject) {
        if reference.is_null() {
            return;
        }
        let Some(entry) = native_entry(env, DELETE_LOCAL_REF_INDEX) else {
            return;
        };
        let function: unsafe extern "system" fn(JNIEnv, JObject) = core::mem::transmute(entry);
        function(env, reference);
    }

    unsafe fn new_global_ref(env: JNIEnv, reference: JObject) -> Option<JObject> {
        if reference.is_null() {
            return None;
        }
        let entry = native_entry(env, NEW_GLOBAL_REF_INDEX)?;
        let function: unsafe extern "system" fn(JNIEnv, JObject) -> JObject =
            core::mem::transmute(entry);
        let global = function(env, reference);
        (!global.is_null()).then_some(global)
    }

    unsafe fn delete_global_ref(env: JNIEnv, reference: JObject) {
        if reference.is_null() {
            return;
        }
        let Some(entry) = native_entry(env, DELETE_GLOBAL_REF_INDEX) else {
            return;
        };
        let function: unsafe extern "system" fn(JNIEnv, JObject) = core::mem::transmute(entry);
        function(env, reference);
    }

    unsafe fn copy_string(env: JNIEnv, value: JString) -> Result<Vec<u8>, BridgeFailure> {
        if value.is_null() {
            return Err(BridgeFailure("AKEN-R1 platform string is null"));
        }
        let Some(length_entry) = native_entry(env, GET_STRING_UTF_LENGTH_INDEX) else {
            return Err(BridgeFailure("JNI GetStringUTFLength is unavailable"));
        };
        let Some(chars_entry) = native_entry(env, GET_STRING_UTF_CHARS_INDEX) else {
            return Err(BridgeFailure("JNI GetStringUTFChars is unavailable"));
        };
        let Some(release_entry) = native_entry(env, RELEASE_STRING_UTF_CHARS_INDEX) else {
            return Err(BridgeFailure("JNI ReleaseStringUTFChars is unavailable"));
        };
        let length: unsafe extern "system" fn(JNIEnv, JString) -> JSize =
            core::mem::transmute(length_entry);
        let get_chars: unsafe extern "system" fn(JNIEnv, JString, *mut JBoolean) -> *const c_char =
            core::mem::transmute(chars_entry);
        let release_chars: unsafe extern "system" fn(JNIEnv, JString, *const c_char) =
            core::mem::transmute(release_entry);
        let size = length(env, value);
        if !(0..=64).contains(&size) {
            return Err(BridgeFailure("AKEN-R1 platform string length is invalid"));
        }
        let chars = get_chars(env, value, core::ptr::null_mut());
        if chars.is_null() {
            return Err(BridgeFailure("JNI GetStringUTFChars failed"));
        }
        let output = core::slice::from_raw_parts(chars.cast::<u8>(), size as usize).to_vec();
        release_chars(env, value, chars);
        Ok(output)
    }

    unsafe fn copy_byte_array(
        env: JNIEnv,
        value: JByteArray,
        max_length: usize,
    ) -> Result<WipedBytes, BridgeFailure> {
        if value.is_null() {
            return Err(BridgeFailure("AKEN-R1 byte array is null"));
        }
        let Some(length_entry) = native_entry(env, GET_ARRAY_LENGTH_INDEX) else {
            return Err(BridgeFailure("JNI GetArrayLength is unavailable"));
        };
        let Some(elements_entry) = native_entry(env, GET_BYTE_ARRAY_ELEMENTS_INDEX) else {
            return Err(BridgeFailure("JNI GetByteArrayElements is unavailable"));
        };
        let Some(release_entry) = native_entry(env, RELEASE_BYTE_ARRAY_ELEMENTS_INDEX) else {
            return Err(BridgeFailure("JNI ReleaseByteArrayElements is unavailable"));
        };
        let length: unsafe extern "system" fn(JNIEnv, JObject) -> JSize =
            core::mem::transmute(length_entry);
        let get_elements: unsafe extern "system" fn(JNIEnv, JByteArray, *mut JBoolean) -> *mut i8 =
            core::mem::transmute(elements_entry);
        let release_elements: unsafe extern "system" fn(JNIEnv, JByteArray, *mut i8, JInt) =
            core::mem::transmute(release_entry);
        let size = length(env, value);
        if size < 0 || size as usize > max_length {
            return Err(BridgeFailure("AKEN-R1 byte array length exceeds its bound"));
        }
        let elements = get_elements(env, value, core::ptr::null_mut());
        if elements.is_null() && size != 0 {
            return Err(BridgeFailure("JNI GetByteArrayElements failed"));
        }
        let output = if size == 0 {
            Vec::new()
        } else {
            core::slice::from_raw_parts(elements.cast::<u8>(), size as usize).to_vec()
        };
        if !elements.is_null() {
            release_elements(env, value, elements, JNI_ABORT);
        }
        Ok(WipedBytes(output))
    }

    unsafe fn copy_vm_arguments(
        env: JNIEnv,
        args: JObjectArray,
        program: &VmProgram,
    ) -> Result<Vec<VmValue<JObject>>, BridgeFailure> {
        let metadata = program.metadata();
        let user_count = metadata.argument_tags.len();
        let expected = user_count + usize::from(!metadata.is_static);
        if args.is_null() {
            if expected == 0 {
                return Ok(Vec::new());
            }
            return Err(BridgeFailure("AKEN-R1 VM arguments are null"));
        }
        let Some(length_entry) = native_entry(env, GET_ARRAY_LENGTH_INDEX) else {
            return Err(BridgeFailure("JNI GetArrayLength is unavailable"));
        };
        let Some(element_entry) = native_entry(env, GET_OBJECT_ARRAY_ELEMENT_INDEX) else {
            return Err(BridgeFailure("JNI GetObjectArrayElement is unavailable"));
        };
        let length: unsafe extern "system" fn(JNIEnv, JObject) -> JSize =
            core::mem::transmute(length_entry);
        let get_element: unsafe extern "system" fn(JNIEnv, JObjectArray, JSize) -> JObject =
            core::mem::transmute(element_entry);
        let actual = length(env, args);
        if actual < 0 || actual as usize != expected || exception_pending(env) {
            clear_exception(env);
            return Err(BridgeFailure(
                "AKEN-R1 VM argument count does not match method descriptor",
            ));
        }

        let mut host = JniObjectOperations::new(env, None);
        let mut values = Vec::with_capacity(expected);
        for index in 0..actual as usize {
            let object = get_element(env, args, index as JSize);
            if exception_pending(env) {
                clear_exception(env);
                return Err(BridgeFailure("AKEN-R1 VM argument extraction failed"));
            }
            if !metadata.is_static && index == 0 {
                if object.is_null() {
                    return Err(BridgeFailure("AKEN-R1 VM receiver is null"));
                }
                values.push(VmValue::Object(object));
                continue;
            }
            let tag_index = index - usize::from(!metadata.is_static);
            let tag = *metadata
                .argument_tags
                .get(tag_index)
                .ok_or(BridgeFailure("AKEN-R1 VM argument metadata is malformed"))?;
            match tag {
                b'L' | b'[' => {
                    values.push(if object.is_null() {
                        VmValue::Null
                    } else {
                        VmValue::Object(object)
                    });
                }
                b'Z' | b'B' | b'C' | b'S' | b'I' | b'J' | b'F' | b'D' => {
                    if object.is_null() {
                        return Err(BridgeFailure(
                            "AKEN-R1 primitive VM argument must not be null",
                        ));
                    }
                    let value = host.unbox(object, tag).map_err(|_| {
                        BridgeFailure("AKEN-R1 boxed primitive argument type mismatch")
                    })?;
                    values.push(value);
                }
                _ => {
                    return Err(BridgeFailure("AKEN-R1 VM argument descriptor is invalid"));
                }
            }
        }
        Ok(values)
    }

    fn validate_defense_label(value: &[u8], failure: &'static str) -> Result<(), BridgeFailure> {
        if value.is_empty()
            || value.len() > 64
            || value
                .iter()
                .any(|byte| *byte == 0 || *byte <= 0x20 || *byte == 0x7f)
        {
            return Err(BridgeFailure(failure));
        }
        Ok(())
    }

    fn detect_debugger() -> Result<bool, BridgeFailure> {
        #[cfg(target_os = "linux")]
        {
            let status = std::fs::read_to_string("/proc/self/status")
                .map_err(|_| BridgeFailure("AKEN unified defense cannot read TracerPid"))?;
            let tracer_pid = status
                .lines()
                .find_map(|line| line.strip_prefix("TracerPid:"))
                .ok_or(BridgeFailure(
                    "AKEN unified defense TracerPid is unavailable",
                ))?
                .trim()
                .parse::<u32>()
                .map_err(|_| BridgeFailure("AKEN unified defense TracerPid is malformed"))?;
            if tracer_pid != 0 {
                return Ok(true);
            }

            let command_line = std::fs::read("/proc/self/cmdline")
                .map_err(|_| BridgeFailure("AKEN unified defense cannot read command line"))?;
            let agent_argument_present = command_line.split(|byte| *byte == 0).any(|argument| {
                argument.starts_with(b"-javaagent:")
                    || argument.starts_with(b"-agentlib:")
                    || argument.starts_with(b"-agentpath:")
            });
            let injected_option_present =
                ["JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS"]
                    .iter()
                    .filter_map(|name| std::env::var_os(name))
                    .filter_map(|value| value.into_string().ok())
                    .any(|value| {
                        value.contains("-javaagent:")
                            || value.contains("-agentlib:")
                            || value.contains("-agentpath:")
                    });
            Ok(agent_argument_present || injected_option_present)
        }

        #[cfg(target_os = "windows")]
        {
            #[link(name = "kernel32")]
            extern "system" {
                fn IsDebuggerPresent() -> i32;
            }
            // IsDebuggerPresent is a high-confidence Windows x64 debugger signal.
            Ok(unsafe { IsDebuggerPresent() != 0 })
        }

        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            Err(BridgeFailure("AKEN unified defense target is unsupported"))
        }
    }

    #[cfg(target_os = "linux")]
    fn contains_vm_vendor(bytes: &[u8]) -> bool {
        let normalized = String::from_utf8_lossy(bytes).to_ascii_lowercase();
        [
            "hyper-v",
            "hyperv",
            "microsoft corporation",
            "vmware",
            "virtualbox",
            "innotek",
            "qemu",
            "kvm",
            "xen",
            "parallels",
            "bhyve",
        ]
        .iter()
        .any(|vendor| normalized.contains(vendor))
    }

    #[cfg(target_arch = "x86_64")]
    fn cpuid_hypervisor_present() -> bool {
        let leaf = unsafe { core::arch::x86_64::__cpuid(1) };
        (leaf.ecx & (1 << 31)) != 0
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn cpuid_hypervisor_present() -> bool {
        false
    }

    fn detect_virtual_machine() -> Result<bool, BridgeFailure> {
        // The CPUID hypervisor bit is a high-confidence signal.  Firmware/DMI
        // strings are intentionally only weak evidence and require a second,
        // independent source below so a normal machine with one BIOS string is
        // not rejected.
        if cpuid_hypervisor_present() {
            return Ok(true);
        }

        #[cfg(target_os = "linux")]
        {
            let dmi_paths = [
                "/sys/class/dmi/id/product_name",
                "/sys/class/dmi/id/sys_vendor",
                "/sys/class/dmi/id/board_vendor",
            ];
            let mut dmi_signal = false;
            for path in dmi_paths {
                match std::fs::read(path) {
                    Ok(bytes) => dmi_signal |= contains_vm_vendor(&bytes),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(_) => {
                        return Err(BridgeFailure(
                            "AKEN unified defense cannot read Linux DMI evidence",
                        ));
                    }
                }
            }
            let cpuinfo_signal = match std::fs::read("/proc/cpuinfo") {
                Ok(bytes) => contains_vm_vendor(&bytes),
                Err(_) => {
                    return Err(BridgeFailure(
                        "AKEN unified defense cannot read Linux CPU evidence",
                    ));
                }
            };
            // DMI and /proc/cpuinfo are separate weak evidence sources.
            return Ok(dmi_signal && cpuinfo_signal);
        }

        #[cfg(target_os = "windows")]
        {
            // Without a CPUID hypervisor indication, a lone firmware/vendor
            // string is weak evidence.  The current Windows runtime therefore
            // does not reject on it alone.
            Ok(false)
        }

        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        {
            Err(BridgeFailure("AKEN unified defense target is unsupported"))
        }
    }

    fn probe_defense_surface(
        surface: DefenseSurface,
        point: &[u8],
        profile: Option<DefenseProfile>,
    ) -> Result<(), BridgeFailure> {
        validate_defense_label(point, "AKEN unified defense probe point is invalid")?;
        if surface == DefenseSurface::AbiProbe {
            if point != b"abi" && point != b"startup" {
                return Err(BridgeFailure(
                    "AKEN unified defense ABI probe point is invalid",
                ));
            }
            return Ok(());
        }
        let detected = match surface {
            DefenseSurface::OsAntiDebug => detect_debugger()?,
            DefenseSurface::OsAntiVm => detect_virtual_machine()?,
            DefenseSurface::AbiProbe => false,
        };
        // Balanced fixtures retain authentication and telemetry while allowing
        // a host-level hypervisor indication. RELEASE_HARDENED passes use the
        // default hardened profile and still fail closed on this high-
        // confidence signal.
        if detected
            && !(surface == DefenseSurface::OsAntiVm && profile == Some(DefenseProfile::Balanced))
        {
            return Err(BridgeFailure(
                "AKEN unified defense detected a protected-host violation",
            ));
        }
        Ok(())
    }

    fn defense_share(
        state: &BridgeState,
        material: &[u8],
        binding: &[u8],
    ) -> Result<[u8; DIGEST_SIZE], BridgeFailure> {
        if state.defense_surface_mask == 0 {
            return Err(BridgeFailure("AKEN unified defense is not armed"));
        }
        let target = state
            .target
            .ok_or(BridgeFailure("AKEN unified defense target is missing"))?;
        let nonce = state.session_nonce.as_ref().ok_or(BridgeFailure(
            "AKEN unified defense session binding is missing",
        ))?;
        let profile = state.defense_profile.unwrap_or(DefenseProfile::Balanced);
        let surface_mask = [state.defense_surface_mask];
        let mut scoped_key = hmac_sha256_bytes(
            nonce,
            &[
                DEFENSE_SHARE_DOMAIN,
                target.triple().as_bytes(),
                profile.label(),
                &surface_mask,
                specialization::SPECIALIZATION_DIGEST.as_ref(),
                specialization::VM_LAYOUT_DIGEST.as_ref(),
            ],
        );
        let output = hmac_sha256_bytes(
            &scoped_key,
            &[
                DEFENSE_SHARE_DOMAIN,
                target.triple().as_bytes(),
                profile.label(),
                &surface_mask,
                binding,
                material,
            ],
        );
        wipe(&mut scoped_key);
        Ok(output)
    }

    fn target_from_state() -> Result<SupportedTarget, BridgeFailure> {
        let state = lock_state()?;
        if !state.initialized {
            return Err(BridgeFailure("AKEN-R1 native bridge is not initialized"));
        }
        state
            .target
            .ok_or(BridgeFailure("AKEN-R1 native bridge target is missing"))
    }

    unsafe fn open_page_route(
        env: JNIEnv,
        entry_token: JLong,
        handle: JByteArray,
        page_index: JInt,
        proof: JByteArray,
        kind: PageKind,
    ) -> Result<OpenedPage, BridgeFailure> {
        if page_index < 0 {
            return Err(BridgeFailure("AKEN-R1 page index is negative"));
        }
        let _ = target_from_state()?;
        {
            let state = lock_state()?;
            if state.session_nonce.is_none() {
                return Err(BridgeFailure("AKEN-R1 session leaf is missing"));
            }
        }
        let handle = copy_byte_array(env, handle, 24)?;
        let proof = copy_byte_array(env, proof, 4096)?;
        let request =
            PageRequest::new(handle.as_bytes(), page_index as u32, proof.as_bytes(), kind)
                .map_err(|_| BridgeFailure("AKEN-R1 page request is malformed"))?;
        let state = lock_state()?;
        state
            .router
            .open(entry_token, &request)
            .map_err(router_failure)
    }

    unsafe fn open_page_route_vm(
        env: JNIEnv,
        entry_token: JLong,
        handle: JByteArray,
        page_index: JInt,
        proof: JByteArray,
    ) -> Result<OpenedPage, BridgeFailure> {
        if page_index < 0 {
            return Err(BridgeFailure("AKEN-R1 page index is negative"));
        }
        let _ = target_from_state()?;
        {
            let state = lock_state()?;
            if state.session_nonce.is_none() {
                return Err(BridgeFailure("AKEN-R1 session leaf is missing"));
            }
        }
        let handle = copy_byte_array(env, handle, 24)?;
        let proof = copy_byte_array(env, proof, 4096)?;
        let request = PageRequest::new(
            handle.as_bytes(),
            page_index as u32,
            proof.as_bytes(),
            PageKind::Vm,
        )
        .map_err(|_| BridgeFailure("AKEN-R1 page request is malformed"))?;
        let state = lock_state()?;
        state
            .router
            .open_vm_pages(entry_token, &request)
            .map_err(router_failure)
    }

    fn router_failure(error: RouterError) -> BridgeFailure {
        match error {
            RouterError::RouteUnavailable { kind: PageKind::Vm } => {
                BridgeFailure("AKEN VM page route is unavailable")
            }
            RouterError::RouteUnavailable { .. } => {
                BridgeFailure("AKEN typed page route is unavailable")
            }
            RouterError::AuthenticationFailed => {
                BridgeFailure("AKEN-R1 page authentication failed")
            }
            _ => BridgeFailure("AKEN-R1 page request is malformed"),
        }
    }

    fn parse_catalog_bundle(
        bundle: &[u8],
        directory: &ArtifactDirectory,
    ) -> Result<std::collections::BTreeMap<String, Vec<u8>>, BridgeFailure> {
        if bundle.len() > MAX_CATALOG_BUNDLE_SIZE {
            return Err(BridgeFailure(
                "AKEN current catalog bundle exceeds its bound",
            ));
        }
        let mut cursor = 0usize;
        let count = read_catalog_u32(bundle, &mut cursor)? as usize;
        if count != directory.entries.len() {
            return Err(BridgeFailure(
                "AKEN current catalog page count does not match the directory",
            ));
        }
        let mut stored = std::collections::BTreeMap::new();
        for _ in 0..count {
            let path_len = read_catalog_u32(bundle, &mut cursor)? as usize;
            if path_len == 0 || path_len > MAX_CATALOG_PATH_SIZE {
                return Err(BridgeFailure("AKEN current catalog path length is invalid"));
            }
            let path_bytes = read_catalog_bytes(bundle, &mut cursor, path_len)?;
            let path = std::str::from_utf8(path_bytes)
                .map_err(|_| BridgeFailure("AKEN current catalog path is not UTF-8"))?;
            if path.starts_with('/')
                || path.contains('\\')
                || path.contains('\0')
                || path.contains("..")
            {
                return Err(BridgeFailure("AKEN current catalog path is invalid"));
            }
            let page_len = read_catalog_u32(bundle, &mut cursor)? as usize;
            if page_len == 0 || page_len > MAX_CATALOG_PAGE_SIZE {
                return Err(BridgeFailure("AKEN current catalog page length is invalid"));
            }
            let page = read_catalog_bytes(bundle, &mut cursor, page_len)?.to_vec();
            if stored.insert(path.to_owned(), page).is_some() {
                return Err(BridgeFailure(
                    "AKEN current catalog contains duplicate pages",
                ));
            }
        }
        if cursor != bundle.len() {
            return Err(BridgeFailure(
                "AKEN current catalog bundle has trailing bytes",
            ));
        }
        for entry in &directory.entries {
            let Some(page) = stored.get(&entry.relative_path) else {
                return Err(BridgeFailure(
                    "AKEN current catalog is missing a directory page",
                ));
            };
            if page.len() != entry.stored_length as usize {
                return Err(BridgeFailure(
                    "AKEN current catalog page length does not match the directory",
                ));
            }
        }
        Ok(stored)
    }

    fn read_catalog_u32(bundle: &[u8], cursor: &mut usize) -> Result<u32, BridgeFailure> {
        let bytes = read_catalog_bytes(bundle, cursor, 4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_catalog_bytes<'a>(
        bundle: &'a [u8],
        cursor: &mut usize,
        length: usize,
    ) -> Result<&'a [u8], BridgeFailure> {
        let end = cursor
            .checked_add(length)
            .ok_or(BridgeFailure("AKEN current catalog bundle length overflow"))?;
        if end > bundle.len() {
            return Err(BridgeFailure("AKEN current catalog bundle is truncated"));
        }
        let range = &bundle[*cursor..end];
        *cursor = end;
        Ok(range)
    }

    fn native_install_catalog_inner(
        env: JNIEnv,
        directory_bytes: JByteArray,
        bundle_bytes: JByteArray,
    ) -> Result<JInt, BridgeFailure> {
        let directory_bytes =
            unsafe { copy_byte_array(env, directory_bytes, MAX_CATALOG_DIRECTORY_SIZE) }?;
        let bundle_bytes = unsafe { copy_byte_array(env, bundle_bytes, MAX_CATALOG_BUNDLE_SIZE) }?;
        let directory = ArtifactDirectory::decode(directory_bytes.as_bytes())
            .map_err(|_| BridgeFailure("AKEN current catalog directory authentication failed"))?;
        let stored = parse_catalog_bundle(bundle_bytes.as_bytes(), &directory)?;
        let mut state = lock_state()?;
        if !state.initialized || state.session_nonce.is_none() {
            return Err(BridgeFailure(
                "AKEN current catalog session binding is missing",
            ));
        }
        let target = state
            .target
            .ok_or(BridgeFailure("AKEN current catalog target is missing"))?;
        if directory.runtime.target_triple != target.triple() {
            return Err(BridgeFailure(
                "AKEN current catalog target binding mismatch",
            ));
        }
        if !state.router.is_empty() {
            return Err(BridgeFailure("AKEN current catalog was already installed"));
        }
        let installed = state
            .router
            .install_catalog_descriptor_bound(&directory, &stored)
            .map_err(|_| BridgeFailure("AKEN current catalog page installation failed"))?;
        if installed != directory.entries.len() {
            return Err(BridgeFailure(
                "AKEN current catalog installed an incomplete page set",
            ));
        }
        i32::try_from(installed)
            .map_err(|_| BridgeFailure("AKEN current catalog page count overflow"))
    }

    fn native_init_inner(env: JNIEnv, platform: JString) -> Result<JInt, BridgeFailure> {
        let platform = unsafe { copy_string(env, platform) }?;
        let target = target_from_platform(&platform)?;
        let mut state = lock_state()?;
        state.initialize(target)?;
        Ok(JSRT_R1_OK)
    }

    fn native_heartbeat_inner() -> Result<JInt, BridgeFailure> {
        let _ = target_from_state()?;
        Ok(JSRT_R1_OK)
    }

    fn native_nonce_inner(env: JNIEnv, nonce: JByteArray) -> Result<JBoolean, BridgeFailure> {
        let nonce = unsafe { copy_byte_array(env, nonce, 32) }?;
        if nonce.as_bytes().len() != 32 {
            return Err(BridgeFailure("AKEN-R1 session nonce must be 32 bytes"));
        }
        let mut state = lock_state()?;
        state.install_nonce(nonce.into_inner())?;
        Ok(1)
    }

    fn native_initialize_defense_inner(
        env: JNIEnv,
        surface: JString,
        profile: JString,
    ) -> Result<JInt, BridgeFailure> {
        let surface = unsafe { copy_string(env, surface) }?;
        let profile = unsafe { copy_string(env, profile) }?;
        let surface = DefenseSurface::parse(&surface)?;
        let profile = DefenseProfile::parse(&profile)?;
        {
            let state = lock_state()?;
            if !state.initialized {
                return Err(BridgeFailure(
                    "AKEN unified defense initialized before native bridge",
                ));
            }
            if state.session_nonce.is_none() {
                return Err(BridgeFailure(
                    "AKEN unified defense session binding is missing",
                ));
            }
            if surface.needs_platform_probe()
                && state
                    .defense_profile
                    .is_some_and(|existing| existing != profile)
            {
                return Err(BridgeFailure(
                    "AKEN unified defense profile changed after initialization",
                ));
            }
        }
        probe_defense_surface(surface, b"startup", Some(profile))?;
        let mut state = lock_state()?;
        if surface.needs_platform_probe() {
            state.defense_profile = Some(profile);
        }
        state.defense_surface_mask |= surface.mask();
        Ok(JSRT_R1_OK)
    }

    fn native_probe_defense_inner(
        env: JNIEnv,
        surface: JString,
        point: JString,
    ) -> Result<JInt, BridgeFailure> {
        let surface = unsafe { copy_string(env, surface) }?;
        let point = unsafe { copy_string(env, point) }?;
        let surface = DefenseSurface::parse(&surface)?;
        validate_defense_label(&point, "AKEN unified defense probe point is invalid")?;
        {
            let state = lock_state()?;
            if !state.initialized || state.session_nonce.is_none() {
                return Err(BridgeFailure(
                    "AKEN unified defense bridge state is incomplete",
                ));
            }
            if state.defense_surface_mask & surface.mask() == 0 {
                return Err(BridgeFailure("AKEN unified defense surface is not armed"));
            }
        }
        let profile = {
            let state = lock_state()?;
            state.defense_profile
        };
        probe_defense_surface(surface, &point, profile)?;
        Ok(JSRT_R1_OK)
    }

    fn native_transform_defense_inner(
        env: JNIEnv,
        material: JByteArray,
        binding: JString,
    ) -> Result<JByteArray, BridgeFailure> {
        let material = unsafe { copy_byte_array(env, material, 4096) }?;
        if material.as_bytes().is_empty() {
            return Err(BridgeFailure("AKEN unified defense material is invalid"));
        }
        let binding = unsafe { copy_string(env, binding) }?;
        validate_defense_label(&binding, "AKEN unified defense binding is invalid")?;
        let mut share = {
            let state = lock_state()?;
            defense_share(&state, material.as_bytes(), &binding)?
        };
        let result = unsafe { new_byte_array(env, &share) }.ok_or(BridgeFailure(
            "AKEN unified defense output allocation failed",
        ));
        wipe(&mut share);
        result
    }

    unsafe extern "system" fn native_init(env: JNIEnv, _class: JClass, platform: JString) -> JInt {
        match native_init_inner(env, platform) {
            Ok(result) => result,
            Err(failure) => {
                throw_new(env, failure.0.as_bytes());
                JNI_ERR
            }
        }
    }

    unsafe extern "system" fn native_heartbeat(env: JNIEnv, _class: JClass) -> JInt {
        match native_heartbeat_inner() {
            Ok(result) => result,
            Err(failure) => {
                throw_new(env, failure.0.as_bytes());
                JNI_ERR
            }
        }
    }

    unsafe extern "system" fn native_install_session_nonce(
        env: JNIEnv,
        _class: JClass,
        nonce: JByteArray,
    ) -> JBoolean {
        match native_nonce_inner(env, nonce) {
            Ok(result) => result,
            Err(failure) => {
                throw_new(env, failure.0.as_bytes());
                0
            }
        }
    }

    unsafe extern "system" fn native_install_catalog(
        env: JNIEnv,
        _class: JClass,
        directory: JByteArray,
        bundle: JByteArray,
    ) -> JInt {
        match native_install_catalog_inner(env, directory, bundle) {
            Ok(result) => result,
            Err(failure) => {
                throw_new(env, failure.0.as_bytes());
                JNI_ERR
            }
        }
    }

    unsafe extern "system" fn native_initialize_defense(
        env: JNIEnv,
        _class: JClass,
        surface: JString,
        profile: JString,
    ) -> JInt {
        match native_initialize_defense_inner(env, surface, profile) {
            Ok(result) => result,
            Err(failure) => {
                throw_new(env, failure.0.as_bytes());
                JNI_ERR
            }
        }
    }

    unsafe extern "system" fn native_probe_defense(
        env: JNIEnv,
        _class: JClass,
        surface: JString,
        point: JString,
    ) -> JInt {
        match native_probe_defense_inner(env, surface, point) {
            Ok(result) => result,
            Err(failure) => {
                throw_new(env, failure.0.as_bytes());
                JNI_ERR
            }
        }
    }

    unsafe extern "system" fn native_transform_defense(
        env: JNIEnv,
        _class: JClass,
        material: JByteArray,
        binding: JString,
    ) -> JByteArray {
        match native_transform_defense_inner(env, material, binding) {
            Ok(result) => result,
            Err(failure) => {
                throw_new(env, failure.0.as_bytes());
                core::ptr::null_mut()
            }
        }
    }

    unsafe extern "system" fn native_execute_aken_vm_page(
        env: JNIEnv,
        _class: JClass,
        _entry_token: JLong,
        handle: JByteArray,
        page_index: JInt,
        proof: JByteArray,
        args: JObjectArray,
    ) -> JObject {
        // A protected page can execute thousands of JNI operations.  Keep all
        // transient FindClass/GetObjectArrayElement/boxing references in a
        // bounded local frame, and promote only the final return object.  This
        // prevents local-reference growth from corrupting subsequent JVM
        // reflection calls while retaining a captured pending throwable until
        // the VM host is dropped below.
        if !push_local_frame(env, 4096) {
            throw_new(env, b"AKEN-R1 JNI local frame unavailable\0");
            return core::ptr::null_mut();
        }
        let result = match open_page_route_vm(env, _entry_token, handle, page_index, proof) {
            Ok(opened) => match opened.parse_vm_with_material(
                specialization::VM_CRYPTO_DOMAIN,
                specialization::VM_LAYOUT_DIGEST,
                vm_state_binding(opened.entry_token(), opened.logical_binding_path()).as_bytes(),
            ) {
                Ok(program) => match copy_vm_arguments(env, args, &program) {
                    Ok(arguments) => {
                        let helper_class = lock_state()
                            .ok()
                            .and_then(|state| state.registered_class.map(|class| class as JObject));
                        let mut executor =
                            VmExecutor::new(JniObjectOperations::new(env, helper_class));
                        let execution = executor.execute(&program, &arguments);
                        let mut host = executor.into_host();
                        match execution {
                            Ok(value) => {
                                // JNI local references created by the VM host
                                // are owned by JniObjectOperations. Transfer
                                // the returned object out of that ownership
                                // set before the host drops, otherwise a
                                // freshly-created CallSite/File/etc. is
                                // deleted before Java receives it.
                                if let VmValue::Object(object) = &value {
                                    host.release(*object);
                                }
                                box_vm_value_with_tag(
                                    env,
                                    value,
                                    Some(program.metadata().return_tag),
                                )
                                .unwrap_or(core::ptr::null_mut())
                            }
                            Err(VmError::UncaughtException(class_name)) => {
                                unsafe { throw_named_exception(env, &class_name) };
                                core::ptr::null_mut()
                            }
                            Err(_) => {
                                throw_new(env, b"AKEN-R1 VM execution failed\0");
                                core::ptr::null_mut()
                            }
                        }
                    }
                    Err(error) => {
                        throw_new(env, error.0.as_bytes());
                        core::ptr::null_mut()
                    }
                },
                Err(error) => {
                    throw_new(env, router_failure(error).0.as_bytes());
                    core::ptr::null_mut()
                }
            },
            Err(failure) => {
                throw_new(env, failure.0.as_bytes());
                core::ptr::null_mut()
            }
        };
        // PopLocalFrame promotes a non-null result into the caller's frame;
        // null leaves any pending Java exception intact and releases all
        // temporaries created while executing the page.
        pop_local_frame(env, result)
    }

    unsafe extern "system" fn native_open_aken_string(
        env: JNIEnv,
        _class: JClass,
        handle: JByteArray,
        page_index: JInt,
        proof: JByteArray,
    ) -> JString {
        match open_page_route(env, 0, handle, page_index, proof, PageKind::String) {
            Ok(opened) => match std::ffi::CString::new(opened.payload()) {
                Ok(text) => {
                    new_string_utf(env, text.as_bytes_with_nul()).unwrap_or(core::ptr::null_mut())
                }
                Err(_) => {
                    throw_new(env, b"AKEN-R1 string page is not UTF-8\0");
                    core::ptr::null_mut()
                }
            },
            Err(failure) => {
                throw_new(env, failure.0.as_bytes());
                core::ptr::null_mut()
            }
        }
    }

    unsafe extern "system" fn native_read_aken_class_page(
        env: JNIEnv,
        _class: JClass,
        handle: JByteArray,
        page_index: JInt,
        proof: JByteArray,
    ) -> JByteArray {
        match open_page_route(env, 0, handle, page_index, proof, PageKind::Class) {
            Ok(opened) => new_byte_array(env, opened.payload()).unwrap_or(core::ptr::null_mut()),
            Err(failure) => {
                throw_new(env, failure.0.as_bytes());
                core::ptr::null_mut()
            }
        }
    }

    unsafe extern "system" fn native_consume_aken_native_chunk(
        env: JNIEnv,
        _class: JClass,
        handle: JByteArray,
        page_index: JInt,
        proof: JByteArray,
    ) {
        match open_page_route(env, 0, handle, page_index, proof, PageKind::Native) {
            Ok(_opened) => {}
            Err(failure) => throw_new(env, failure.0.as_bytes()),
        }
    }

    fn registered_methods() -> [JniNativeMethod; 11] {
        [
            JniNativeMethod {
                name: b"nativeInit\0".as_ptr().cast(),
                signature: b"(Ljava/lang/String;)I\0".as_ptr().cast(),
                fn_ptr: native_init as *mut c_void,
            },
            JniNativeMethod {
                name: b"nativeHeartbeat\0".as_ptr().cast(),
                signature: b"()I\0".as_ptr().cast(),
                fn_ptr: native_heartbeat as *mut c_void,
            },
            JniNativeMethod {
                name: b"nativeInstallAkenSessionNonce\0".as_ptr().cast(),
                signature: b"([B)Z\0".as_ptr().cast(),
                fn_ptr: native_install_session_nonce as *mut c_void,
            },
            JniNativeMethod {
                name: b"nativeInstallAkenCatalog\0".as_ptr().cast(),
                signature: b"([B[B)I\0".as_ptr().cast(),
                fn_ptr: native_install_catalog as *mut c_void,
            },
            JniNativeMethod {
                name: b"nativeExecuteAkenVmPage\0".as_ptr().cast(),
                signature: b"(J[BI[B[Ljava/lang/Object;)Ljava/lang/Object;\0"
                    .as_ptr()
                    .cast(),
                fn_ptr: native_execute_aken_vm_page as *mut c_void,
            },
            JniNativeMethod {
                name: b"nativeOpenAkenString\0".as_ptr().cast(),
                signature: b"([BI[B)Ljava/lang/String;\0".as_ptr().cast(),
                fn_ptr: native_open_aken_string as *mut c_void,
            },
            JniNativeMethod {
                name: b"nativeReadAkenClassPage\0".as_ptr().cast(),
                signature: b"([BI[B)[B\0".as_ptr().cast(),
                fn_ptr: native_read_aken_class_page as *mut c_void,
            },
            JniNativeMethod {
                name: b"nativeConsumeAkenNativeChunk\0".as_ptr().cast(),
                signature: b"([BI[B)V\0".as_ptr().cast(),
                fn_ptr: native_consume_aken_native_chunk as *mut c_void,
            },
            JniNativeMethod {
                name: b"nativeInitializeDefense\0".as_ptr().cast(),
                signature: b"(Ljava/lang/String;Ljava/lang/String;)I\0".as_ptr().cast(),
                fn_ptr: native_initialize_defense as *mut c_void,
            },
            JniNativeMethod {
                name: b"nativeProbeDefense\0".as_ptr().cast(),
                signature: b"(Ljava/lang/String;Ljava/lang/String;)I\0".as_ptr().cast(),
                fn_ptr: native_probe_defense as *mut c_void,
            },
            JniNativeMethod {
                name: b"nativeTransformDefense\0".as_ptr().cast(),
                signature: b"([BLjava/lang/String;)[B\0".as_ptr().cast(),
                fn_ptr: native_transform_defense as *mut c_void,
            },
        ]
    }

    unsafe fn register_natives(
        env: JNIEnv,
        class: JClass,
        methods: &[JniNativeMethod],
    ) -> Result<(), BridgeFailure> {
        let Some(entry) = native_entry(env, REGISTER_NATIVES_INDEX) else {
            return Err(BridgeFailure("JNI RegisterNatives is unavailable"));
        };
        let function: unsafe extern "system" fn(
            JNIEnv,
            JClass,
            *const JniNativeMethod,
            JInt,
        ) -> JInt = core::mem::transmute(entry);
        if function(env, class, methods.as_ptr(), methods.len() as JInt) != JNI_OK {
            clear_exception(env);
            return Err(BridgeFailure("AKEN-R1 JNI native registration failed"));
        }
        Ok(())
    }

    #[repr(C)]
    union JValue {
        l: JObject,
        i: JInt,
        z: JBoolean,
        b: JByte,
        c: JChar,
        s: JShort,
        j: JLong,
        f: JFloat,
        d: JDouble,
    }

    unsafe fn read_system_property(
        env: JNIEnv,
        name: &[u8],
    ) -> Result<Option<String>, BridgeFailure> {
        let Some(system) = find_class(env, b"java/lang/System\0") else {
            clear_exception(env);
            return Err(BridgeFailure("java.lang.System is unavailable"));
        };
        let method = get_static_method_id(
            env,
            system,
            b"getProperty\0",
            b"(Ljava/lang/String;)Ljava/lang/String;\0",
        );
        if method.is_none() {
            delete_local_ref(env, system);
            clear_exception(env);
            return Err(BridgeFailure("System.getProperty is unavailable"));
        }
        let Some(key) = new_string_utf(env, name) else {
            delete_local_ref(env, system);
            return Err(BridgeFailure("AKEN-R1 property name is invalid"));
        };
        let args = [JValue { l: key }];
        let value = call_static_object_method_a(env, system, method.unwrap(), jvalue_ptr(&args));
        delete_local_ref(env, key);
        delete_local_ref(env, system);
        let Some(value) = value else {
            return Ok(None);
        };
        let copied = copy_jstring(env, value)?;
        delete_local_ref(env, value);
        Ok(copied)
    }

    unsafe fn get_static_method_id(
        env: JNIEnv,
        class: JClass,
        name: &[u8],
        signature: &[u8],
    ) -> Option<*const c_void> {
        let entry = native_entry(env, GET_STATIC_METHOD_ID_INDEX)?;
        let function: unsafe extern "system" fn(
            JNIEnv,
            JClass,
            *const c_char,
            *const c_char,
        ) -> *const c_void = core::mem::transmute(entry);
        let method = function(env, class, name.as_ptr().cast(), signature.as_ptr().cast());
        (!method.is_null()).then_some(method)
    }

    unsafe fn call_static_object_method_a(
        env: JNIEnv,
        class: JClass,
        method: *const c_void,
        args: *const JValue,
    ) -> Option<JObject> {
        let entry = native_entry(env, CALL_STATIC_OBJECT_METHOD_A_INDEX)?;
        let function: unsafe extern "system" fn(
            JNIEnv,
            JClass,
            *const c_void,
            *const JValue,
        ) -> JObject = core::mem::transmute(entry);
        let value = function(env, class, method, args);
        (!value.is_null()).then_some(value)
    }

    unsafe fn box_vm_value_with_tag(
        env: JNIEnv,
        value: VmValue<JObject>,
        type_tag: Option<u8>,
    ) -> Option<JObject> {
        let (class_name, method_name, descriptor, argument) = match value {
            VmValue::Int(value) if type_tag == Some(b'Z') => (
                b"java/lang/Boolean\0" as &[u8],
                b"valueOf\0" as &[u8],
                b"(Z)Ljava/lang/Boolean;\0" as &[u8],
                JValue {
                    z: u8::from(value != 0),
                },
            ),
            VmValue::Int(value) => (
                b"java/lang/Integer\0" as &[u8],
                b"valueOf\0" as &[u8] as &[u8],
                b"(I)Ljava/lang/Integer;\0" as &[u8],
                JValue { i: value },
            ),
            VmValue::Long(value) => (
                b"java/lang/Long\0" as &[u8],
                b"valueOf\0" as &[u8],
                b"(J)Ljava/lang/Long;\0" as &[u8],
                JValue { j: value },
            ),
            VmValue::Float(value) => (
                b"java/lang/Float\0" as &[u8],
                b"valueOf\0" as &[u8],
                b"(F)Ljava/lang/Float;\0" as &[u8],
                JValue { f: value },
            ),
            VmValue::Double(value) => (
                b"java/lang/Double\0" as &[u8],
                b"valueOf\0" as &[u8],
                b"(D)Ljava/lang/Double;\0" as &[u8],
                JValue { d: value },
            ),
            VmValue::Object(value) => return (!value.is_null()).then_some(value),
            VmValue::Null => return Some(core::ptr::null_mut()),
            _ => return None,
        };
        let class = find_class(env, class_name)?;
        let method = get_static_method_id(env, class, method_name, descriptor)?;
        let boxed = call_static_object_method_a(env, class, method, &argument);
        delete_local_ref(env, class);
        boxed
    }

    unsafe fn box_vm_value(env: JNIEnv, value: VmValue<JObject>) -> Option<JObject> {
        box_vm_value_with_tag(env, value, None)
    }

    unsafe fn box_int(env: JNIEnv, value: i32) -> Option<JObject> {
        box_vm_value(env, VmValue::Int(value))
    }

    unsafe fn new_byte_array(env: JNIEnv, bytes: &[u8]) -> Option<JByteArray> {
        let entry = native_entry(env, NEW_BYTE_ARRAY_INDEX)?;
        let create: unsafe extern "system" fn(JNIEnv, JSize) -> JByteArray =
            core::mem::transmute(entry);
        let array = create(env, bytes.len() as JSize);
        if array.is_null() {
            return None;
        }
        if !bytes.is_empty() {
            let set_entry = native_entry(env, SET_BYTE_ARRAY_REGION_INDEX)?;
            let set: unsafe extern "system" fn(JNIEnv, JByteArray, JSize, JSize, *const i8) =
                core::mem::transmute(set_entry);
            set(env, array, 0, bytes.len() as JSize, bytes.as_ptr().cast());
        }
        Some(array)
    }

    unsafe fn new_string_utf(env: JNIEnv, bytes: &[u8]) -> Option<JString> {
        let entry = native_entry(env, NEW_STRING_UTF_INDEX)?;
        let function: unsafe extern "system" fn(JNIEnv, *const c_char) -> JString =
            core::mem::transmute(entry);
        let value = function(env, bytes.as_ptr().cast());
        (!value.is_null()).then_some(value)
    }

    unsafe fn copy_jstring(env: JNIEnv, value: JString) -> Result<Option<String>, BridgeFailure> {
        let Some(entry) = native_entry(env, GET_STRING_UTF_CHARS_INDEX) else {
            return Err(BridgeFailure("GetStringUTFChars is unavailable"));
        };
        let function: unsafe extern "system" fn(JNIEnv, JString, *mut JBoolean) -> *const c_char =
            core::mem::transmute(entry);
        let chars = function(env, value, core::ptr::null_mut());
        if chars.is_null() {
            clear_exception(env);
            return Ok(None);
        }
        let copied = std::ffi::CStr::from_ptr(chars)
            .to_str()
            .map(str::to_owned)
            .map_err(|_| BridgeFailure("AKEN-R1 system property is not UTF-8"));
        if let Some(release) = native_entry(env, RELEASE_STRING_UTF_CHARS_INDEX) {
            let release_fn: unsafe extern "system" fn(JNIEnv, JString, *const c_char) =
                core::mem::transmute(release);
            release_fn(env, value, chars);
        }
        copied.map(Some)
    }

    unsafe fn resolve_registration_plan(
        env: JNIEnv,
    ) -> Result<crate::relocation::RegistrationPlan, BridgeFailure> {
        let loader_owner = read_system_property(env, b"j.l\0")?;
        let method_text = read_system_property(env, b"j.m\0")?;
        let method_map = match method_text.as_deref() {
            None => Default::default(),
            Some(text) => {
                crate::relocation::parse_binding_map(text).map_err(|error| BridgeFailure(error))?
            }
        };
        crate::relocation::resolve_registration(loader_owner.as_deref(), &method_map)
            .map_err(|error| BridgeFailure(error))
    }

    unsafe fn unregister_natives(env: JNIEnv, class: JClass) {
        let Some(entry) = native_entry(env, UNREGISTER_NATIVES_INDEX) else {
            return;
        };
        let function: unsafe extern "system" fn(JNIEnv, JClass) -> JInt =
            core::mem::transmute(entry);
        let _ = function(env, class);
    }

    #[no_mangle]
    pub unsafe extern "system" fn JNI_OnLoad(vm: JavaVM, _reserved: *mut c_void) -> JInt {
        let mut raw_env = core::ptr::null_mut();
        if invoke_get_env(vm, &mut raw_env) != Some(JNI_OK) || raw_env.is_null() {
            return JNI_ERR;
        }
        let env = raw_env.cast::<*const JniNativeInterface>();
        let plan = match resolve_registration_plan(env) {
            Ok(plan) => plan,
            Err(_) => {
                clear_exception(env);
                return JNI_ERR;
            }
        };
        let Ok(owner) = std::ffi::CString::new(plan.owner.as_str()) else {
            return JNI_ERR;
        };
        let mut remapped_names = Vec::with_capacity(plan.methods.len());
        for (name, _) in &plan.methods {
            let Ok(owned) = std::ffi::CString::new(name.as_str()) else {
                return JNI_ERR;
            };
            remapped_names.push(owned);
        }
        let base = registered_methods();
        let methods: [JniNativeMethod; 11] = core::array::from_fn(|index| JniNativeMethod {
            name: remapped_names[index].as_ptr(),
            signature: base[index].signature,
            fn_ptr: base[index].fn_ptr,
        });
        let owner_bytes = if plan.owner == crate::relocation::ORIGINAL_HELPER_OWNER {
            TARGET_CLASS
        } else {
            owner.as_bytes_with_nul()
        };
        let Some(class) = find_class(env, owner_bytes) else {
            clear_exception(env);
            return JNI_ERR;
        };
        let result = register_natives(env, class, &methods);
        if result.is_err() {
            clear_exception(env);
            delete_local_ref(env, class);
            return JNI_ERR;
        }
        let Some(global_class) = new_global_ref(env, class) else {
            clear_exception(env);
            unregister_natives(env, class);
            delete_local_ref(env, class);
            return JNI_ERR;
        };
        if let Ok(mut state) = lock_state() {
            state.registered = true;
            state.registered_class = Some(global_class as usize);
        } else {
            unregister_natives(env, class);
            delete_global_ref(env, global_class);
            delete_local_ref(env, class);
            return JNI_ERR;
        }
        delete_local_ref(env, class);
        JNI_VERSION_1_8
    }

    #[no_mangle]
    pub unsafe extern "system" fn JNI_OnUnload(vm: JavaVM, _reserved: *mut c_void) {
        let mut raw_env = core::ptr::null_mut();
        if invoke_get_env(vm, &mut raw_env) == Some(JNI_OK) && !raw_env.is_null() {
            let env = raw_env.cast::<*const JniNativeInterface>();
            let registered_class = lock_state()
                .ok()
                .and_then(|mut state| state.registered_class.take());
            if let Some(class) = registered_class {
                let class = class as JObject;
                unregister_natives(env, class);
                delete_global_ref(env, class);
            }
            clear_exception(env);
        }
        if let Ok(mut state) = lock_state() {
            state.clear();
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::collections::BTreeSet;
        use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};

        const EXPECTED_ROUTES: [(&str, &str); 11] = [
            ("nativeInit", "(Ljava/lang/String;)I"),
            ("nativeHeartbeat", "()I"),
            ("nativeInstallAkenSessionNonce", "([B)Z"),
            ("nativeInstallAkenCatalog", "([B[B)I"),
            (
                "nativeExecuteAkenVmPage",
                "(J[BI[B[Ljava/lang/Object;)Ljava/lang/Object;",
            ),
            ("nativeOpenAkenString", "([BI[B)Ljava/lang/String;"),
            ("nativeReadAkenClassPage", "([BI[B)[B"),
            ("nativeConsumeAkenNativeChunk", "([BI[B)V"),
            (
                "nativeInitializeDefense",
                "(Ljava/lang/String;Ljava/lang/String;)I",
            ),
            (
                "nativeProbeDefense",
                "(Ljava/lang/String;Ljava/lang/String;)I",
            ),
            ("nativeTransformDefense", "([BLjava/lang/String;)[B"),
        ];

        static REGISTER_CALLS: AtomicUsize = AtomicUsize::new(0);
        static REGISTERED_COUNT: AtomicI32 = AtomicI32::new(-1);
        static REGISTERED_ROUTE_MASK: AtomicUsize = AtomicUsize::new(0);

        unsafe extern "system" fn capture_register_natives(
            _env: JNIEnv,
            _class: JClass,
            methods: *const JniNativeMethod,
            count: JInt,
        ) -> JInt {
            REGISTER_CALLS.fetch_add(1, Ordering::SeqCst);
            REGISTERED_COUNT.store(count, Ordering::SeqCst);
            if methods.is_null() || count < 0 {
                return JNI_ERR;
            }
            let mut mask = 0usize;
            for method in core::slice::from_raw_parts(methods, count as usize) {
                if method.name.is_null() || method.signature.is_null() || method.fn_ptr.is_null() {
                    continue;
                }
                let name = std::ffi::CStr::from_ptr(method.name).to_bytes();
                let signature = std::ffi::CStr::from_ptr(method.signature).to_bytes();
                if let Some(index) =
                    EXPECTED_ROUTES
                        .iter()
                        .position(|(expected_name, expected_sig)| {
                            name == expected_name.as_bytes() && signature == expected_sig.as_bytes()
                        })
                {
                    mask |= 1usize << index;
                }
            }
            REGISTERED_ROUTE_MASK.store(mask, Ordering::SeqCst);
            JNI_OK
        }

        fn route(method: &JniNativeMethod) -> (&str, &str) {
            (
                unsafe { std::ffi::CStr::from_ptr(method.name) }
                    .to_str()
                    .expect("JNI method name"),
                unsafe { std::ffi::CStr::from_ptr(method.signature) }
                    .to_str()
                    .expect("JNI method signature"),
            )
        }

        #[test]
        fn source_helper_owner_matches_the_relocation_fallback() {
            assert_eq!(
                core::str::from_utf8(&TARGET_CLASS[..TARGET_CLASS.len() - 1]).expect("owner"),
                crate::relocation::ORIGINAL_HELPER_OWNER,
            );
        }

        #[test]
        fn registration_table_is_exactly_the_eleven_typed_r1_methods() {
            let methods = registered_methods();
            assert_eq!(methods.len(), EXPECTED_ROUTES.len());
            assert_eq!(
                methods.iter().map(route).collect::<Vec<_>>(),
                EXPECTED_ROUTES
            );
            assert!(methods.iter().all(|method| !method.fn_ptr.is_null()));
            assert_eq!(
                methods
                    .iter()
                    .map(|method| method.fn_ptr as usize)
                    .collect::<BTreeSet<_>>()
                    .len(),
                EXPECTED_ROUTES.len(),
                "each typed JNI registration must have a distinct implementation",
            );
        }

        #[test]
        fn register_natives_receives_all_eleven_typed_methods_in_one_call() {
            REGISTER_CALLS.store(0, Ordering::SeqCst);
            REGISTERED_COUNT.store(-1, Ordering::SeqCst);
            REGISTERED_ROUTE_MASK.store(0, Ordering::SeqCst);

            let mut table = JniNativeInterface {
                entries: [core::ptr::null(); JNI_NATIVE_INTERFACE_SIZE],
            };
            table.entries[REGISTER_NATIVES_INDEX] = capture_register_natives as *const c_void;
            let mut table_pointer: *const JniNativeInterface = &table;
            let env: JNIEnv = &mut table_pointer;
            let class = 1usize as JClass;

            unsafe { register_natives(env, class, &registered_methods()) }
                .expect("typed RegisterNatives call");
            assert_eq!(REGISTER_CALLS.load(Ordering::SeqCst), 1);
            assert_eq!(
                REGISTERED_COUNT.load(Ordering::SeqCst),
                EXPECTED_ROUTES.len() as JInt
            );
            assert_eq!(
                REGISTERED_ROUTE_MASK.load(Ordering::SeqCst),
                (1usize << EXPECTED_ROUTES.len()) - 1,
            );
        }

        #[test]
        fn jni_table_indices_match_the_jdk_8_layout() {
            assert_eq!(FIND_CLASS_INDEX, 6);
            assert_eq!(GET_ENV_INDEX, 6);
            assert_eq!(GET_STATIC_METHOD_ID_INDEX, 113);
            assert_eq!(CALL_STATIC_OBJECT_METHOD_A_INDEX, 116);
            assert_eq!(NEW_STRING_UTF_INDEX, 167);
            assert_eq!(NEW_BYTE_ARRAY_INDEX, 176);
            assert_eq!(SET_BYTE_ARRAY_REGION_INDEX, 208);
            assert_eq!(THROW_NEW_INDEX, 14);
            assert_eq!(EXCEPTION_OCCURRED_INDEX, 15);
            assert_eq!(EXCEPTION_CLEAR_INDEX, 17);
            assert_eq!(PUSH_LOCAL_FRAME_INDEX, 19);
            assert_eq!(POP_LOCAL_FRAME_INDEX, 20);
            assert_eq!(NEW_GLOBAL_REF_INDEX, 21);
            assert_eq!(DELETE_GLOBAL_REF_INDEX, 22);
            assert_eq!(DELETE_LOCAL_REF_INDEX, 23);
            assert_eq!(GET_STRING_UTF_LENGTH_INDEX, 168);
            assert_eq!(GET_STRING_UTF_CHARS_INDEX, 169);
            assert_eq!(RELEASE_STRING_UTF_CHARS_INDEX, 170);
            assert_eq!(GET_ARRAY_LENGTH_INDEX, 171);
            assert_eq!(GET_BYTE_ARRAY_ELEMENTS_INDEX, 184);
            assert_eq!(RELEASE_BYTE_ARRAY_ELEMENTS_INDEX, 192);
            assert_eq!(REGISTER_NATIVES_INDEX, 215);
            assert_eq!(UNREGISTER_NATIVES_INDEX, 216);
            assert_eq!(EXCEPTION_CHECK_INDEX, 228);
        }

        #[test]
        fn bridge_state_wipes_and_rejects_target_changes() {
            let mut state = BridgeState::default();
            state
                .initialize(SupportedTarget::WindowsX64Gnu)
                .expect("init");
            assert!(state.initialize(SupportedTarget::LinuxX64Gnu217).is_err());
            state.install_nonce(vec![7; 32]).expect("nonce");
            state.clear();
            assert!(!state.initialized);
            assert!(state.session_nonce.is_none());
        }

        #[test]
        fn target_aliases_are_restricted_to_the_two_r1_routes() {
            for (value, expected) in [
                (b"windows-x64".as_slice(), SupportedTarget::WindowsX64Gnu),
                (
                    b"x86_64-pc-windows-gnu".as_slice(),
                    SupportedTarget::WindowsX64Gnu,
                ),
                (b"linux-x64".as_slice(), SupportedTarget::LinuxX64Gnu217),
                (
                    b"x86_64-unknown-linux-gnu.2.17".as_slice(),
                    SupportedTarget::LinuxX64Gnu217,
                ),
            ] {
                assert_eq!(target_from_platform(value), Ok(expected));
            }
            for rejected in [
                b"x86_64-pc-windows-msvc".as_slice(),
                b"x86_64-unknown-linux-gnu".as_slice(),
                b"x86_64-unknown-linux-musl".as_slice(),
                b"x86_64-apple-darwin".as_slice(),
                b"aarch64-apple-darwin".as_slice(),
            ] {
                assert!(target_from_platform(rejected).is_err());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsrt_page::RuntimeEnvelope;
    use jsrt_shell::WINDOWS_X64_GNU;

    #[test]
    fn ffi_digest_and_open_round_trip() {
        let binding = b"ffi-binding";
        let frame =
            RuntimeEnvelope::encode(&Binding::from_slice(binding).expect("binding"), b"payload")
                .expect("frame");
        let mut digest = [0; DIGEST_SIZE];
        assert_eq!(
            jsrt_r1_runtime_binding_digest(binding.as_ptr(), binding.len(), digest.as_mut_ptr()),
            JSRT_R1_OK
        );
        let mut output = [0; 32];
        let mut output_len = 0usize;
        assert_eq!(
            jsrt_r1_open_frame(
                WINDOWS_X64_GNU.as_ptr(),
                WINDOWS_X64_GNU.len(),
                binding.as_ptr(),
                binding.len(),
                frame.as_ptr(),
                frame.len(),
                output.as_mut_ptr(),
                output.len(),
                &mut output_len,
            ),
            JSRT_R1_OK
        );
        assert_eq!(&output[..output_len], b"payload");
    }

    #[test]
    fn ffi_rejects_unsupported_target_and_bad_pointers() {
        let binding = b"binding";
        let mut digest = [0; DIGEST_SIZE];
        assert_eq!(
            jsrt_r1_runtime_binding_digest(core::ptr::null(), binding.len(), digest.as_mut_ptr()),
            JSRT_R1_INVALID_INPUT
        );
        assert_eq!(
            jsrt_r1_runtime_binding_digest(binding.as_ptr(), binding.len(), core::ptr::null_mut()),
            JSRT_R1_INVALID_INPUT
        );
        let mut output_len = 0usize;
        assert_eq!(
            jsrt_r1_open_frame(
                b"x86_64-apple-darwin".as_ptr(),
                "x86_64-apple-darwin".len(),
                binding.as_ptr(),
                binding.len(),
                b"frame".as_ptr(),
                5,
                core::ptr::null_mut(),
                0,
                &mut output_len,
            ),
            JSRT_R1_UNSUPPORTED_TARGET
        );
    }

    #[test]
    fn ffi_reports_required_capacity_and_authentication_failure() {
        let binding = b"binding";
        let frame =
            RuntimeEnvelope::encode(&Binding::from_slice(binding).expect("binding"), b"payload")
                .expect("frame");
        let mut short_output = [0; 3];
        let mut output_len = usize::MAX;
        assert_eq!(
            jsrt_r1_open_frame(
                WINDOWS_X64_GNU.as_ptr(),
                WINDOWS_X64_GNU.len(),
                binding.as_ptr(),
                binding.len(),
                frame.as_ptr(),
                frame.len(),
                short_output.as_mut_ptr(),
                short_output.len(),
                &mut output_len,
            ),
            JSRT_R1_BUFFER_TOO_SMALL
        );
        assert_eq!(output_len, 7);

        let mut tampered = frame;
        *tampered.last_mut().expect("authentication tag") ^= 1;
        let mut output = [0; 7];
        output_len = usize::MAX;
        assert_eq!(
            jsrt_r1_open_frame(
                WINDOWS_X64_GNU.as_ptr(),
                WINDOWS_X64_GNU.len(),
                binding.as_ptr(),
                binding.len(),
                tampered.as_ptr(),
                tampered.len(),
                output.as_mut_ptr(),
                output.len(),
                &mut output_len,
            ),
            JSRT_R1_AUTHENTICATION_FAILED
        );
        assert_eq!(output_len, 0);
    }

    #[test]
    fn specialization_is_nonsecret_and_locked_to_r1_targets() {
        assert_eq!(PAYLOAD_PROFILE, "aken-r1-rust-ffi-v1");
        assert_eq!(SPECIALIZATION_DIGEST.len(), DIGEST_SIZE);
        assert!(
            TARGET_TRIPLE == "x86_64-pc-windows-gnu"
                || TARGET_TRIPLE == "x86_64-unknown-linux-gnu.2.17"
                || TARGET_TRIPLE == "unsupported"
        );
    }
}
