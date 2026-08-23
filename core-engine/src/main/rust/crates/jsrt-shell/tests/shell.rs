use jsrt_crypto::sha256;
use jsrt_shell::SupportedTarget;
use jsrt_shell::{
    Compression, Elf64Image, ParseError, PayloadDecompressor, PayloadEnvelope, PayloadManifest,
    Pe64Image, R1Decompressor, R1_PAYLOAD_PROFILE,
};

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn put_i64(bytes: &mut [u8], offset: usize, value: i64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn put_c_string(bytes: &mut [u8], file_offset: usize, rva: u32, value: &[u8]) -> u32 {
    bytes[file_offset..file_offset + value.len()].copy_from_slice(value);
    rva
}

fn pe_fixture() -> Vec<u8> {
    let mut bytes = vec![0u8; 0xa00];
    bytes[..2].copy_from_slice(b"MZ");
    put_u32(&mut bytes, 0x3c, 0x80);
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    put_u16(&mut bytes, 0x84, 0x8664);
    put_u16(&mut bytes, 0x86, 1);
    put_u16(&mut bytes, 0x94, 240);
    put_u16(&mut bytes, 0x96, 0x2000);
    let optional = 0x98;
    put_u16(&mut bytes, optional, 0x20b);
    put_u32(&mut bytes, optional + 16, 0x1000);
    put_u64(&mut bytes, optional + 24, 0x0001_8000_0000);
    put_u32(&mut bytes, optional + 32, 0x1000);
    put_u32(&mut bytes, optional + 36, 0x200);
    put_u32(&mut bytes, optional + 56, 0x2000);
    put_u32(&mut bytes, optional + 60, 0x200);
    put_u16(&mut bytes, optional + 68, 3);
    put_u32(&mut bytes, optional + 108, 16);
    put_u32(&mut bytes, optional + 112, 0x1100);
    put_u32(&mut bytes, optional + 116, 0x100);
    let section = optional + 240;
    bytes[section..section + 5].copy_from_slice(b".text");
    put_u32(&mut bytes, section + 8, 0x1000);
    put_u32(&mut bytes, section + 12, 0x1000);
    put_u32(&mut bytes, section + 16, 0x800);
    put_u32(&mut bytes, section + 20, 0x200);
    put_u32(&mut bytes, section + 36, 0x6000_0020);

    let export = 0x200 + 0x100;
    put_u32(&mut bytes, export + 12, 0x1180);
    put_u32(&mut bytes, export + 16, 1);
    put_u32(&mut bytes, export + 20, 4);
    put_u32(&mut bytes, export + 24, 4);
    put_u32(&mut bytes, export + 28, 0x1140);
    put_u32(&mut bytes, export + 32, 0x1150);
    put_u32(&mut bytes, export + 36, 0x1160);
    let string_file_offset = 0x200 + 0x170;
    let string_rva = 0x1170;
    let names = [
        b"JNI_OnLoad\0".as_slice(),
        b"JNI_OnUnload\0".as_slice(),
        b"jsrt_r1_runtime_binding_digest\0".as_slice(),
        b"jsrt_r1_open_frame\0".as_slice(),
    ];
    let mut name_rvas = Vec::new();
    let mut next_file_offset = string_file_offset;
    let mut next_rva = string_rva;
    for name in names {
        name_rvas.push(put_c_string(&mut bytes, next_file_offset, next_rva, name));
        next_file_offset += name.len();
        next_rva += name.len() as u32;
    }
    let dll_name_rva = put_c_string(&mut bytes, next_file_offset, next_rva, b"jsrt.dll\0");
    put_u32(&mut bytes, export + 12, dll_name_rva);
    for (index, address) in [0x1000u32, 0x1010, 0x1020, 0x1030].into_iter().enumerate() {
        put_u32(&mut bytes, 0x200 + 0x140 + index * 4, address);
        put_u32(&mut bytes, 0x200 + 0x150 + index * 4, name_rvas[index]);
        put_u16(&mut bytes, 0x200 + 0x160 + index * 2, index as u16);
    }
    bytes
}

fn elf_fixture() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x2000];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    put_u16(&mut bytes, 16, 3);
    put_u16(&mut bytes, 18, 0x3e);
    put_u32(&mut bytes, 20, 1);
    put_u64(&mut bytes, 24, 0x500);
    put_u64(&mut bytes, 32, 64);
    put_u16(&mut bytes, 52, 64);
    put_u16(&mut bytes, 54, 56);
    put_u16(&mut bytes, 56, 3);

    let ph0 = 64;
    put_u32(&mut bytes, ph0, 1);
    put_u32(&mut bytes, ph0 + 4, 5);
    put_u64(&mut bytes, ph0 + 8, 0);
    put_u64(&mut bytes, ph0 + 16, 0);
    put_u64(&mut bytes, ph0 + 32, 0x1000);
    put_u64(&mut bytes, ph0 + 40, 0x1000);
    put_u64(&mut bytes, ph0 + 48, 0x1000);
    let ph1 = ph0 + 56;
    put_u32(&mut bytes, ph1, 1);
    put_u32(&mut bytes, ph1 + 4, 6);
    put_u64(&mut bytes, ph1 + 8, 0x1000);
    put_u64(&mut bytes, ph1 + 16, 0x1000);
    put_u64(&mut bytes, ph1 + 32, 0x1000);
    put_u64(&mut bytes, ph1 + 40, 0x1000);
    put_u64(&mut bytes, ph1 + 48, 0x1000);

    let dynamic_ph = 64 + 112;
    put_u32(&mut bytes, dynamic_ph, 2);
    put_u32(&mut bytes, dynamic_ph + 4, 6);
    put_u64(&mut bytes, dynamic_ph + 8, 0x1100);
    put_u64(&mut bytes, dynamic_ph + 16, 0x1100);
    put_u64(&mut bytes, dynamic_ph + 32, 0x70);
    put_u64(&mut bytes, dynamic_ph + 40, 0x70);
    put_u64(&mut bytes, dynamic_ph + 48, 8);

    let dynamic = 0x1100;
    let entries = [
        (5i64, 0x1400),
        (10, 128),
        (6, 0x1200),
        (11, 24),
        (4, 0x1300),
        (12, 0x500),
        (0, 0),
    ];
    for (index, (tag, value)) in entries.into_iter().enumerate() {
        put_i64(&mut bytes, dynamic + index * 16, tag);
        put_u64(&mut bytes, dynamic + index * 16 + 8, value);
    }
    put_u32(&mut bytes, 0x1300, 1);
    put_u32(&mut bytes, 0x1304, 5);
    put_u32(&mut bytes, 0x1308, 1);
    for index in 0..5 {
        put_u32(
            &mut bytes,
            0x130c + index * 4,
            if index == 0 { 0 } else { 1 },
        );
    }
    let names = [
        b"JNI_OnLoad\0".as_slice(),
        b"JNI_OnUnload\0".as_slice(),
        b"jsrt_r1_runtime_binding_digest\0".as_slice(),
        b"jsrt_r1_open_frame\0".as_slice(),
    ];
    let mut name_offsets = Vec::new();
    let mut name_position = 1usize;
    for name in names {
        name_offsets.push(name_position as u32);
        bytes[0x1400 + name_position..0x1400 + name_position + name.len()].copy_from_slice(name);
        name_position += name.len();
    }
    for index in 0..5 {
        let entry = 0x1200 + index * 24;
        if index != 0 {
            put_u32(&mut bytes, entry, name_offsets[index - 1]);
            bytes[entry + 4] = 0x12;
            put_u16(&mut bytes, entry + 6, 1);
            put_u64(
                &mut bytes,
                entry + 8,
                [0x500u64, 0x510, 0x520, 0x530][index - 1],
            );
        }
    }
    bytes
}

#[test]
fn pe64_plan_checks_sections_exports_and_wx() {
    let bytes = pe_fixture();
    let image = Pe64Image::parse(&bytes).expect("PE fixture");
    let plan = image.map_plan().expect("PE plan");
    plan.require_r1_exports().expect("R1 exports");
    assert_eq!(plan.relocations().len(), 0);
    assert_eq!(plan.executable_ranges().len(), 1);

    let mut tampered = bytes;
    put_u32(&mut tampered, 0x188 + 36, 0xe000_0020);
    assert!(matches!(
        Pe64Image::parse(&tampered),
        Err(ParseError::WriteExecute)
    ));
}

#[test]
fn elf64_plan_checks_dynamic_symbols_and_initializers() {
    let image = Elf64Image::parse(&elf_fixture()).expect("ELF fixture");
    let plan = image.map_plan().expect("ELF plan");
    plan.require_r1_exports().expect("R1 exports");
    assert_eq!(plan.imports().len(), 0);
    assert_eq!(plan.init().entry_point(), Some(0x500));
    assert_eq!(plan.executable_ranges().len(), 1);
}

#[test]
fn authenticated_payload_rejects_tamper_and_wipes_decoder_state() {
    let payload = b"native-bytes";
    let digest = sha256(payload).into_bytes();
    let manifest = PayloadManifest::new(
        SupportedTarget::WindowsX64Gnu,
        [1u8; 32],
        digest,
        [2u8; 32],
        [3u8; 32],
        Compression::None,
        payload.len(),
        payload.len(),
    )
    .expect("manifest");
    assert_eq!(manifest.profile(), R1_PAYLOAD_PROFILE);
    let binding = b"shell-binding";
    let frame = PayloadEnvelope::encode(binding, &manifest, payload).expect("frame");
    assert_eq!(
        PayloadEnvelope::open(binding, &frame)
            .expect("open")
            .plaintext(),
        payload
    );

    let mut tampered = frame;
    let index = tampered.len() - 1;
    tampered[index] ^= 0x40;
    assert!(PayloadEnvelope::open(binding, &tampered).is_err());

    let mut decoder = R1Decompressor::new();
    let encoded = [0x28, 0xb5, 0x2f, 0xfd, 0x20, 0x01, 0x01, 0x00, 0x00, 0x00];
    assert!(decoder.decompress(Compression::Zstd, &encoded, 1).is_err());
    decoder.reset_and_wipe();
    assert_eq!(decoder.workspace_len(), 0);
}
