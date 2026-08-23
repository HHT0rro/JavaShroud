use jsrt_shell::{
    is_supported_target, reject_legacy_or_macos_name, PlatformError, SupportedTarget,
    LINUX_X64_GNU_217, WINDOWS_X64_GNU,
};

#[test]
fn only_windows_and_linux_r1_targets_are_supported() {
    assert_eq!(
        SupportedTarget::parse(WINDOWS_X64_GNU),
        Ok(SupportedTarget::WindowsX64Gnu)
    );
    assert_eq!(
        SupportedTarget::parse(LINUX_X64_GNU_217),
        Ok(SupportedTarget::LinuxX64Gnu217)
    );
    assert_eq!(SupportedTarget::all().len(), 2);
    assert!(!is_supported_target("x86_64-pc-windows-msvc"));
    assert!(!is_supported_target("x86_64-unknown-linux-gnu"));
}

#[test]
fn macos_host_and_targets_fail_closed() {
    for target in ["x86_64-apple-darwin", "aarch64-apple-darwin"] {
        assert!(matches!(
            SupportedTarget::parse(target),
            Err(PlatformError::UnsupportedTarget(_))
        ));
    }
    assert!(reject_legacy_or_macos_name("macOS-host").is_err());
    assert!(reject_legacy_or_macos_name("Mach-O-image").is_err());
}

#[test]
fn macho_dylib_and_legacy_c_zig_artifacts_fail_closed() {
    for name in [
        "libjsrt.dylib",
        "jsrt-macho",
        "legacy-runtime.c",
        "legacy-zig-runtime",
    ] {
        assert!(
            matches!(
                reject_legacy_or_macos_name(name),
                Err(PlatformError::UnsupportedArtifact { .. })
            ),
            "retired artifact accepted: {name}"
        );
    }
    assert!(reject_legacy_or_macos_name("jsrt_ffi.dll").is_ok());
    assert!(reject_legacy_or_macos_name("libjsrt_ffi.so").is_ok());
}
