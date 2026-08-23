#![allow(unsafe_code, clippy::not_unsafe_ptr_arg_deref)]

mod relocation;
mod specialization;

pub use specialization::{
    PACKING_LEVEL, PAYLOAD_PROFILE, PROTECTION_LEVEL, SPECIALIZATION_DIGEST, TARGET_TRIPLE,
};

use jsrt_crypto::{Binding, RuntimeBindingDigest, DIGEST_SIZE, MAX_BINDING_SIZE, MAX_PAYLOAD_SIZE};
use jsrt_page::MAX_FRAME_SIZE;
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
    use std::os::raw::{c_char, c_void};
    use std::sync::{Mutex, MutexGuard, OnceLock};

    type JInt = i32;
    type JLong = i64;
    type JBoolean = u8;
    type JSize = i32;
    type JObject = *mut c_void;
    type JClass = JObject;
    type JString = JObject;
    type JByteArray = JObject;
    type JNIEnv = *mut *const JniNativeInterface;
    type JavaVM = *mut *const JniInvokeInterface;

    const JNI_OK: JInt = 0;
    const JNI_ERR: JInt = -1;
    const JNI_ABORT: JInt = 2;
    const JNI_VERSION_1_8: JInt = 0x0001_0008;
    const JNI_NATIVE_INTERFACE_SIZE: usize = 303;
    const JNI_INVOKE_INTERFACE_SIZE: usize = 8;

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
    const DELETE_LOCAL_REF_INDEX: usize = 23;
    const EXCEPTION_CLEAR_INDEX: usize = 17;
    const GET_STATIC_METHOD_ID_INDEX: usize = 113;
    const CALL_STATIC_OBJECT_METHOD_A_INDEX: usize = 116;
    const NEW_STRING_UTF_INDEX: usize = 167;
    const NEW_BYTE_ARRAY_INDEX: usize = 176;
    const SET_BYTE_ARRAY_REGION_INDEX: usize = 208;
    const GET_STRING_UTF_LENGTH_INDEX: usize = 168;
    const GET_STRING_UTF_CHARS_INDEX: usize = 169;
    const RELEASE_STRING_UTF_CHARS_INDEX: usize = 170;
    const GET_ARRAY_LENGTH_INDEX: usize = 171;
    const GET_BYTE_ARRAY_ELEMENTS_INDEX: usize = 184;
    const RELEASE_BYTE_ARRAY_ELEMENTS_INDEX: usize = 192;
    const REGISTER_NATIVES_INDEX: usize = 215;
    const UNREGISTER_NATIVES_INDEX: usize = 216;
    const EXCEPTION_CHECK_INDEX: usize = 228;
    const GET_ENV_INDEX: usize = 6;

    const TARGET_CLASS: &[u8] =
        b"io/github/hht0rro/javashroud/transforms/protection/JniMicrokernelHelper\0";
    const SECURITY_EXCEPTION_CLASS: &[u8] = b"java/lang/SecurityException\0";

    #[derive(Default)]
    struct BridgeState {
        target: Option<SupportedTarget>,
        initialized: bool,
        session_nonce: Option<Vec<u8>>,
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

    unsafe extern "system" fn native_execute_aken_vm_page(
        env: JNIEnv,
        _class: JClass,
        _entry_token: JLong,
        handle: JByteArray,
        page_index: JInt,
        proof: JByteArray,
        _args: JObject,
    ) -> JObject {
        match open_page_route(env, _entry_token, handle, page_index, proof, PageKind::Vm) {
            Ok(_opened) => core::ptr::null_mut(),
            Err(failure) => {
                throw_new(env, failure.0.as_bytes());
                core::ptr::null_mut()
            }
        }
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

    fn registered_methods() -> [JniNativeMethod; 7] {
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
        let value = call_static_object_method_a(env, system, method.unwrap(), args.as_ptr());
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
            Some(text) => crate::relocation::parse_binding_map(text).map_err(BridgeFailure)?,
        };
        crate::relocation::resolve_registration(loader_owner.as_deref(), &method_map)
            .map_err(BridgeFailure)
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
        let methods: [JniNativeMethod; 7] = core::array::from_fn(|index| JniNativeMethod {
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

        const EXPECTED_ROUTES: [(&str, &str); 7] = [
            ("nativeInit", "(Ljava/lang/String;)I"),
            ("nativeHeartbeat", "()I"),
            ("nativeInstallAkenSessionNonce", "([B)Z"),
            (
                "nativeExecuteAkenVmPage",
                "(J[BI[B[Ljava/lang/Object;)Ljava/lang/Object;",
            ),
            ("nativeOpenAkenString", "([BI[B)Ljava/lang/String;"),
            ("nativeReadAkenClassPage", "([BI[B)[B"),
            ("nativeConsumeAkenNativeChunk", "([BI[B)V"),
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
        fn registration_table_is_exactly_the_seven_typed_r1_methods() {
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
        fn register_natives_receives_all_seven_typed_methods_in_one_call() {
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
            assert_eq!(EXCEPTION_CLEAR_INDEX, 17);
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
