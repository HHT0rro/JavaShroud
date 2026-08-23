use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const EXPECTED_EXPORTS: [&str; 4] = [
    "JNI_OnLoad",
    "JNI_OnUnload",
    "jsrt_r1_open_frame",
    "jsrt_r1_runtime_binding_digest",
];

struct BuildDirectory(PathBuf);

impl Drop for BuildDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn release_cdylib_exports_exactly_the_r1_surface() {
    let workspace = workspace_root();
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let target_dir = std::env::temp_dir().join(format!(
        "jsrt-r1-release-exports-{}-{unique}",
        std::process::id()
    ));
    let _build_directory = BuildDirectory(target_dir.clone());
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = Command::new(cargo)
        .current_dir(&workspace)
        .args([
            "build",
            "--quiet",
            "--locked",
            "--offline",
            "--release",
            "--package",
            "jsrt-ffi",
            "--lib",
            "--target-dir",
        ])
        .arg(&target_dir)
        .env("CARGO_INCREMENTAL", "0")
        .output()
        .expect("run release cdylib build");
    assert!(
        output.status.success(),
        "release cdylib build failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );

    let library = if cfg!(target_os = "windows") {
        target_dir.join("release/jsrt_ffi.dll")
    } else if cfg!(target_os = "linux") {
        target_dir.join("release/libjsrt_ffi.so")
    } else {
        panic!("AKEN-R1 release export checks support only Windows x64 and Linux x64");
    };
    let bytes = fs::read(&library)
        .unwrap_or_else(|error| panic!("read release cdylib {}: {error}", library.display()));
    let actual = if cfg!(target_os = "windows") {
        pe_exports(&bytes)
    } else {
        elf64_exports(&bytes)
    };
    let expected = EXPECTED_EXPORTS.into_iter().collect::<BTreeSet<_>>();
    assert_eq!(
        actual,
        expected,
        "unexpected release exports in {}",
        library.display()
    );
}

#[test]
fn workspace_config_distinguishes_rustup_from_the_glibc_217_zigbuild_target() {
    let workspace = workspace_root();
    let manifest = fs::read_to_string(workspace.join("Cargo.toml")).expect("workspace manifest");
    assert!(manifest.contains("panic = \"abort\""));
    assert!(!manifest.contains("panic = \"unwind\""));
    assert!(manifest.contains("linux_rustup_target = \"x86_64-unknown-linux-gnu\""));
    assert!(manifest.contains("linux_zigbuild_target = \"x86_64-unknown-linux-gnu.2.17\""));
    assert!(!manifest.contains("linux_rust_target ="));

    let config = fs::read_to_string(workspace.join(".cargo/config.toml")).expect("Cargo config");
    assert!(config.contains(
        "r1-linux-release = \"zigbuild --locked --offline --release --package jsrt-ffi --lib --target x86_64-unknown-linux-gnu.2.17\""
    ));
    assert!(config.contains(
        "r1-windows-release = \"build --locked --offline --release --package jsrt-ffi --lib --target x86_64-pc-windows-gnu\""
    ));
    assert!(!config.contains("r1-linux-release = \"build "));
    assert!(!config.contains("--workspace"));

    let toolchain =
        fs::read_to_string(workspace.join("rust-toolchain.toml")).expect("Rust toolchain lock");
    assert!(toolchain.contains("\"x86_64-unknown-linux-gnu\""));
    assert!(!toolchain
        .lines()
        .any(|line| line.trim() == "\"x86_64-unknown-linux-gnu.2.17\","));

    let ffi_manifest =
        fs::read_to_string(workspace.join("crates/jsrt-ffi/Cargo.toml")).expect("FFI manifest");
    assert!(ffi_manifest.contains("crate-type = [\"rlib\", \"cdylib\"]"));
    assert!(!ffi_manifest.contains("staticlib"));
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("Rust workspace root")
        .to_path_buf()
}

fn pe_exports(bytes: &[u8]) -> BTreeSet<&str> {
    assert!(
        bytes.len() >= 0x40 && &bytes[..2] == b"MZ",
        "release artifact is not PE"
    );
    let pe = read_u32(bytes, 0x3c) as usize;
    assert_eq!(slice(bytes, pe, 4), b"PE\0\0");
    assert_eq!(read_u16(bytes, pe + 4), 0x8664, "PE target must be AMD64");
    let section_count = read_u16(bytes, pe + 6) as usize;
    let optional_size = read_u16(bytes, pe + 20) as usize;
    let optional = pe + 24;
    assert_eq!(read_u16(bytes, optional), 0x20b, "PE target must be PE32+");
    let export_rva = read_u32(bytes, optional + 112);
    assert_ne!(export_rva, 0, "PE export directory is missing");
    let sections = optional + optional_size;
    let export = pe_rva_to_offset(bytes, sections, section_count, export_rva);
    let name_count = read_u32(bytes, export + 24) as usize;
    let names_rva = read_u32(bytes, export + 32);
    let names = pe_rva_to_offset(bytes, sections, section_count, names_rva);
    (0..name_count)
        .map(|index| {
            let name_rva = read_u32(bytes, names + index * 4);
            let name = pe_rva_to_offset(bytes, sections, section_count, name_rva);
            read_c_string(bytes, name)
        })
        .collect()
}

fn pe_rva_to_offset(bytes: &[u8], sections: usize, section_count: usize, rva: u32) -> usize {
    for index in 0..section_count {
        let section = sections + index * 40;
        let virtual_size = read_u32(bytes, section + 8);
        let virtual_address = read_u32(bytes, section + 12);
        let raw_size = read_u32(bytes, section + 16);
        let raw_offset = read_u32(bytes, section + 20);
        let span = virtual_size.max(raw_size);
        if rva >= virtual_address && rva - virtual_address < span {
            let offset = raw_offset as usize + (rva - virtual_address) as usize;
            assert!(offset < bytes.len(), "PE RVA points outside the file");
            return offset;
        }
    }
    panic!("PE RVA 0x{rva:08x} does not map to a section");
}

fn elf64_exports(bytes: &[u8]) -> BTreeSet<&str> {
    assert!(
        bytes.len() >= 64 && &bytes[..4] == b"\x7fELF",
        "release artifact is not ELF",
    );
    assert_eq!(bytes[4], 2, "ELF target must be 64-bit");
    assert_eq!(bytes[5], 1, "ELF target must be little-endian");
    assert_eq!(
        read_u16(bytes, 16),
        3,
        "ELF artifact must be a shared object"
    );
    assert_eq!(read_u16(bytes, 18), 0x3e, "ELF target must be AMD64");

    let section_table = read_u64(bytes, 40) as usize;
    let section_size = read_u16(bytes, 58) as usize;
    let section_count = read_u16(bytes, 60) as usize;
    assert!(
        section_size >= 64 && section_count > 0,
        "ELF section table is invalid"
    );
    slice(bytes, section_table, section_size * section_count);

    let dynamic_symbols = (0..section_count)
        .map(|index| section_table + index * section_size)
        .find(|section| read_u32(bytes, *section + 4) == 11)
        .expect("ELF .dynsym section");
    let symbol_offset = read_u64(bytes, dynamic_symbols + 24) as usize;
    let symbol_bytes = read_u64(bytes, dynamic_symbols + 32) as usize;
    let string_section_index = read_u32(bytes, dynamic_symbols + 40) as usize;
    let symbol_size = read_u64(bytes, dynamic_symbols + 56) as usize;
    assert!(symbol_size >= 24 && symbol_bytes % symbol_size == 0);
    assert!(string_section_index < section_count);

    let strings = section_table + string_section_index * section_size;
    let string_offset = read_u64(bytes, strings + 24) as usize;
    let string_bytes = read_u64(bytes, strings + 32) as usize;
    slice(bytes, string_offset, string_bytes);
    slice(bytes, symbol_offset, symbol_bytes);

    let mut exports = BTreeSet::new();
    for index in 0..(symbol_bytes / symbol_size) {
        let symbol = symbol_offset + index * symbol_size;
        let name_offset = read_u32(bytes, symbol) as usize;
        let binding = bytes[symbol + 4] >> 4;
        let visibility = bytes[symbol + 5] & 0x03;
        let section_index = read_u16(bytes, symbol + 6);
        if name_offset == 0
            || section_index == 0
            || !matches!(binding, 1 | 2)
            || matches!(visibility, 1 | 2)
        {
            continue;
        }
        assert!(
            name_offset < string_bytes,
            "ELF symbol name is out of bounds"
        );
        exports.insert(read_c_string(bytes, string_offset + name_offset));
    }
    exports
}

fn read_c_string(bytes: &[u8], offset: usize) -> &str {
    let tail = bytes.get(offset..).expect("string offset");
    let length = tail
        .iter()
        .position(|byte| *byte == 0)
        .expect("NUL terminator");
    std::str::from_utf8(&tail[..length]).expect("ASCII export name")
}

fn slice(bytes: &[u8], offset: usize, length: usize) -> &[u8] {
    bytes
        .get(offset..offset.checked_add(length).expect("range overflow"))
        .expect("binary range")
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(slice(bytes, offset, 2).try_into().expect("u16"))
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(slice(bytes, offset, 4).try_into().expect("u32"))
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(slice(bytes, offset, 8).try_into().expect("u64"))
}
