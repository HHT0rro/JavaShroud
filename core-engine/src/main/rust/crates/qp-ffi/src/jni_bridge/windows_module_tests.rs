use super::{hostile_module_present, windows_hostile_module_path_present};
use core::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};

#[link(name = "kernel32")]
extern "system" {
    fn GetCurrentProcess() -> *mut c_void;
    fn K32EnumProcessModules(
        process: *mut c_void,
        modules: *mut *mut c_void,
        size: u32,
        needed: *mut u32,
    ) -> i32;
    fn K32GetModuleFileNameExW(
        process: *mut c_void,
        module: *mut c_void,
        filename: *mut u16,
        size: u32,
    ) -> u32;
    fn GetModuleFileNameW(module: *mut c_void, filename: *mut u16, size: u32) -> u32;
    fn LoadLibraryW(path: *const u16) -> *mut c_void;
    fn FreeLibrary(module: *mut c_void) -> i32;
}

// These tests deliberately load detectable names into the current process.
static MODULE_TEST_LOCK: Mutex<()> = Mutex::new(());
static NEXT_FIXTURE: AtomicUsize = AtomicUsize::new(0);

struct FixtureDirectory(PathBuf);

impl FixtureDirectory {
    fn new() -> Self {
        let id = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("qp-module-test-{}-{id}", std::process::id()));
        std::fs::create_dir(&path).expect("create isolated fixture directory");
        Self(path)
    }

    fn copy_module(&self, relative: &str) -> PathBuf {
        let path = self.0.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).expect("create fixture parent");
        let source = PathBuf::from(std::env::var_os("SystemRoot").expect("SystemRoot"))
            .join("System32/version.dll");
        std::fs::copy(source, &path).expect("copy system version DLL as test fixture");
        path
    }
}

impl Drop for FixtureDirectory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).expect("remove unloaded fixtures");
    }
}

struct Module(*mut c_void);

impl Module {
    fn load(path: &Path) -> Self {
        // The extended path also permits the long-path fixture on Windows.
        let path = format!("\\\\?\\{}", path.display());
        let wide: Vec<u16> = std::ffi::OsStr::new(&path)
            .encode_wide()
            .chain(Some(0))
            .collect();
        let module = unsafe { LoadLibraryW(wide.as_ptr()) };
        assert!(!module.is_null(), "LoadLibraryW failed for {path}");
        Self(module)
    }
}

impl Drop for Module {
    fn drop(&mut self) {
        assert_ne!(unsafe { FreeLibrary(self.0) }, 0, "release owned module");
    }
}

fn assert_path_parity(module: *mut c_void) {
    for capacity in [0, 1, 2, 8, 16, 64, 128, 259, 260, 261, 512] {
        let mut previous = vec![0u16; capacity];
        let mut current = vec![0u16; capacity];
        let old_length = unsafe {
            K32GetModuleFileNameExW(
                GetCurrentProcess(),
                module,
                previous.as_mut_ptr(),
                capacity as u32,
            )
        };
        let new_length =
            unsafe { GetModuleFileNameW(module, current.as_mut_ptr(), capacity as u32) };
        assert_eq!(old_length, new_length, "capacity {capacity}");
        assert_eq!(previous, current, "UTF-16 buffer at capacity {capacity}");
    }
}

#[test]
fn current_process_module_paths_match_at_buffer_boundaries() {
    let _guard = MODULE_TEST_LOCK.lock().unwrap();
    let mut modules = [core::ptr::null_mut(); 512];
    let mut needed = 0;
    assert_ne!(
        unsafe {
            K32EnumProcessModules(
                GetCurrentProcess(),
                modules.as_mut_ptr(),
                core::mem::size_of_val(&modules) as u32,
                &mut needed,
            )
        },
        0
    );
    let count = needed as usize / core::mem::size_of::<*mut c_void>();
    assert!(count > 0 && count <= modules.len());
    for &module in &modules[..count] {
        assert_path_parity(module);
    }
    let fixtures = FixtureDirectory::new();
    let unicode_path = fixtures.copy_module("unicode_路径/owned_unicode.dll");
    let long_path = fixtures.copy_module(&format!(
        "{}/{}/{}/owned_long.dll",
        "a".repeat(90),
        "b".repeat(90),
        "c".repeat(90)
    ));
    for path in [unicode_path, long_path] {
        let module = Module::load(&path);
        assert_path_parity(module.0);
    }
}

#[test]
fn invalid_and_unloaded_handles_return_zero() {
    let _guard = MODULE_TEST_LOCK.lock().unwrap();
    let fixtures = FixtureDirectory::new();
    let path = fixtures.copy_module("owned_unloaded.dll");
    let module = Module::load(&path);
    let unloaded = module.0;
    drop(module);
    for handle in [1usize as *mut c_void, usize::MAX as *mut c_void, unloaded] {
        let mut buffer = [0u16; 260];
        assert_eq!(
            unsafe {
                K32GetModuleFileNameExW(GetCurrentProcess(), handle, buffer.as_mut_ptr(), 260)
            },
            0
        );
        assert_eq!(
            unsafe { GetModuleFileNameW(handle, buffer.as_mut_ptr(), 260) },
            0
        );
    }
}

#[test]
fn module_detection_preserves_all_name_predicates() {
    let _guard = MODULE_TEST_LOCK.lock().unwrap();
    let fixtures = FixtureDirectory::new();
    assert!(!windows_hostile_module_path_present().unwrap());
    for name in [
        "owned_FrIdA_suffix.dll",
        "owned_GaDgEt_suffix.dll",
        "owned_WiNjEcT_suffix.dll",
        "SbIeDlL.DlL",
        "JdWp.DlL",
        "InStRuMeNt.DlL",
        "JvMtI.DlL",
    ] {
        let path = fixtures.copy_module(name);
        let module = Module::load(&path);
        assert!(windows_hostile_module_path_present().unwrap(), "{name}");
        assert!(hostile_module_present().unwrap(), "{name}");
        drop(module);
        assert!(
            !windows_hostile_module_path_present().unwrap(),
            "unloaded {name}"
        );
    }
    for name in [
        "frida_gadget_winject/owned_clean.dll",
        "owned_instrument.dll",
        "jvmti.dll.extra",
    ] {
        let path = fixtures.copy_module(name);
        let _module = Module::load(&path);
        assert!(!windows_hostile_module_path_present().unwrap(), "{name}");
        assert!(!hostile_module_present().unwrap(), "{name}");
    }
}

fn scan_during_module_churn(benign_path: PathBuf, expected: bool) {
    let barrier = Arc::new(Barrier::new(3));
    let start = Arc::clone(&barrier);
    let loader = std::thread::spawn(move || {
        start.wait();
        for _ in 0..2000 {
            let module = Module::load(&benign_path);
            std::thread::yield_now();
            drop(module);
        }
    });
    let scanners: Vec<_> = (0..2)
        .map(|_| {
            let start = Arc::clone(&barrier);
            std::thread::spawn(move || {
                start.wait();
                for _ in 0..1000 {
                    assert_eq!(windows_hostile_module_path_present().unwrap(), expected);
                }
            })
        })
        .collect();
    loader.join().unwrap();
    for scanner in scanners {
        scanner.join().unwrap();
    }
}

#[test]
fn concurrent_load_free_preserves_negative_and_pinned_positive_detection() {
    let _guard = MODULE_TEST_LOCK.lock().unwrap();
    let fixtures = FixtureDirectory::new();
    let benign_path = fixtures.copy_module("owned_churn.dll");
    scan_during_module_churn(benign_path.clone(), false);
    let hostile_path = fixtures.copy_module("owned_GaDgEt_pinned.dll");
    let _pinned = Module::load(&hostile_path);
    scan_during_module_churn(benign_path, true);
}
