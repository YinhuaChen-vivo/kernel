// NEWLINE-TIMEOUT: 10
// ASSERT-SUCC: Loader integration test ended
// ASSERT-FAIL: Backtrace in Panic.*

#![no_main]
#![no_std]
#![feature(custom_test_frameworks)]
#![test_runner(loader_test_runner)]
#![reexport_test_harness_main = "loader_test_main"]
#![feature(c_size_t)]
#![feature(thread_local)]
#![feature(c_variadic)]

extern crate alloc;
extern crate rsrt;
// Import it just for the global allocator.
use alloc::vec::Vec;
use blueos_loader as loader;
use core::ffi::c_char;
use librs::pthread;
use semihosting::{io::Read, println};

extern "C" {
    static LOADER_TEST_ELF_PATH: *const c_char;
    #[cfg(loader_test_large_exec)]
    static LOADER_TEST_USELIBRS_ELF_PATH: *const c_char;
    static INVALID_MAGIC_ELF_PATH: *const c_char;
    static INVALID_ENTRY_ELF_PATH: *const c_char;
    static INVALID_SEGMENT_SIZE_ELF_PATH: *const c_char;
}

#[cfg(loader_test_exec)]
mod loader_test_config {
    use blueos_loader as loader;

    pub const fn parse_hex(value: &str) -> usize {
        let bytes = value.as_bytes();
        if bytes.len() <= 2 || bytes[0] != b'0' || (bytes[1] != b'x' && bytes[1] != b'X') {
            panic!("loader test relocation value must be hexadecimal");
        }

        let mut index = 2;
        let mut result = 0usize;
        while index < bytes.len() {
            let digit = match bytes[index] {
                b'0'..=b'9' => (bytes[index] - b'0') as usize,
                b'a'..=b'f' => (bytes[index] - b'a' + 10) as usize,
                b'A'..=b'F' => (bytes[index] - b'A' + 10) as usize,
                _ => panic!("invalid loader test relocation hex value"),
            };
            result = result * 16 + digit;
            index += 1;
        }
        result
    }

    pub const fn parse_permissions(value: &str) -> loader::MemoryPermissions {
        let bytes = value.as_bytes();
        let mut index = 0;
        let mut permissions = loader::MemoryPermissions::NONE;
        while index < bytes.len() {
            let permission = match bytes[index] {
                b'r' => loader::MemoryPermissions::READ,
                b'w' => loader::MemoryPermissions::WRITE,
                b'x' => loader::MemoryPermissions::EXECUTE,
                _ => panic!("invalid loader test relocation permission"),
            };
            permissions = permissions.bitor(permission);
            index += 1;
        }
        permissions
    }

    pub const TEST_REGION_START: usize = parse_hex(env!("LOADER_TEST_RELOCATION_ORIGIN"));
    pub const TEST_REGION_END: usize =
        TEST_REGION_START + parse_hex(env!("LOADER_TEST_RELOCATION_LENGTH"));
    pub const TEST_REGION_PERMISSIONS: loader::MemoryPermissions =
        parse_permissions(env!("LOADER_TEST_RELOCATION_PERMISSIONS"));

    pub static TEST_REGIONS: [loader::MemoryRegion; 1] = [unsafe {
        loader::MemoryRegion::new(TEST_REGION_START, TEST_REGION_END, TEST_REGION_PERMISSIONS)
    }];

    #[cfg(loader_test_large_exec)]
    pub const LARGE_TEST_REGION_START: usize =
        parse_hex(env!("LOADER_TEST_LARGE_RELOCATION_ORIGIN"));
    #[cfg(loader_test_large_exec)]
    pub const LARGE_TEST_REGION_END: usize =
        LARGE_TEST_REGION_START + parse_hex(env!("LOADER_TEST_LARGE_RELOCATION_LENGTH"));
    #[cfg(loader_test_large_exec)]
    pub const LARGE_TEST_REGION_PERMISSIONS: loader::MemoryPermissions =
        parse_permissions(env!("LOADER_TEST_LARGE_RELOCATION_PERMISSIONS"));
    #[cfg(loader_test_large_exec)]
    pub const LARGE_RODATA_REGION_START: usize = parse_hex(env!("LOADER_TEST_LARGE_RODATA_ORIGIN"));
    #[cfg(loader_test_large_exec)]
    pub const LARGE_RODATA_REGION_END: usize =
        LARGE_RODATA_REGION_START + parse_hex(env!("LOADER_TEST_LARGE_RELOCATION_LENGTH"));
    #[cfg(loader_test_large_exec)]
    pub const LARGE_DATA_REGION_START: usize = parse_hex(env!("LOADER_TEST_LARGE_DATA_ORIGIN"));
    #[cfg(loader_test_large_exec)]
    pub const LARGE_DATA_REGION_END: usize =
        LARGE_DATA_REGION_START + parse_hex(env!("LOADER_TEST_LARGE_DATA_LENGTH"));

    #[cfg(loader_test_large_exec)]
    pub static LARGE_TEST_REGIONS: [loader::MemoryRegion; 3] = [
        unsafe {
            loader::MemoryRegion::new(
                LARGE_TEST_REGION_START,
                LARGE_TEST_REGION_END,
                LARGE_TEST_REGION_PERMISSIONS,
            )
        },
        unsafe {
            loader::MemoryRegion::new(
                LARGE_RODATA_REGION_START,
                LARGE_RODATA_REGION_END,
                loader::MemoryPermissions::READ,
            )
        },
        unsafe {
            loader::MemoryRegion::new(
                LARGE_DATA_REGION_START,
                LARGE_DATA_REGION_END,
                loader::MemoryPermissions::READ.bitor(loader::MemoryPermissions::WRITE),
            )
        },
    ];

    #[cfg(loader_test_large_exec)]
    pub static LARGE_XIP_REGIONS: [loader::XipRegion; 2] = [
        loader::XipRegion::new(LARGE_TEST_REGION_START, LARGE_TEST_REGION_END),
        loader::XipRegion::new(LARGE_RODATA_REGION_START, LARGE_RODATA_REGION_END),
    ];
}

fn read_all(ptr: *const core::ffi::c_char) -> semihosting::io::Result<Vec<u8>> {
    let path = unsafe { core::ffi::CStr::from_ptr(ptr) };
    let mut file = semihosting::fs::File::open(path)?;
    let mut tmp = [0u8; 512];
    let mut buf = Vec::new();
    loop {
        let size = file.read(&mut tmp)?;
        if size == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..size]);
    }
    Ok(buf)
}

mod test_elf_loader {
    #[cfg(loader_test_large_exec)]
    use super::loader_test_config::{
        LARGE_DATA_REGION_START, LARGE_RODATA_REGION_END, LARGE_RODATA_REGION_START,
        LARGE_TEST_REGIONS, LARGE_TEST_REGION_END, LARGE_TEST_REGION_START, LARGE_XIP_REGIONS,
    };
    #[cfg(loader_test_exec)]
    use super::loader_test_config::{
        TEST_REGIONS, TEST_REGION_END, TEST_REGION_PERMISSIONS, TEST_REGION_START,
    };
    use super::*;
    use blueos_test_macro::test;

    #[cfg(loader_test_exec)]
    const EXPECTED_RESULT: u32 = 0x9afc_e987;

    #[cfg(loader_test_large_exec)]
    const USELIBRS_EXPECTED_RESULT: u32 = 0x4c49_4252;

    #[cfg(loader_test_large_exec)]
    const FLASH_DEVICE_PATH: &[u8] = b"/dev/esp32-flash0\0";
    #[cfg(loader_test_large_exec)]
    const ESP32_FLASH_ERASE_RANGE: u32 = 0x40;
    #[cfg(loader_test_large_exec)]
    const ESP32_FLASH_MAP_EXEC: u32 = 0x44;
    #[cfg(loader_test_large_exec)]
    const ESP32_FLASH_UNMAP: u32 = 0x45;
    #[cfg(loader_test_large_exec)]
    const ESP32_FLASH_QUERY_DRAM_SAFE: u32 = 0x46;
    #[cfg(loader_test_large_exec)]
    const FLASH_IOCTL_ABI_VERSION: u32 = 1;
    #[cfg(loader_test_large_exec)]
    const IROM_VADDR_BASE: u32 = 0x4200_0000;
    #[cfg(loader_test_large_exec)]
    const DROM_VADDR_BASE: u32 = 0x3c00_0000;
    #[cfg(loader_test_large_exec)]
    const LOADABLE_REGION_BASE: u32 = 0x0011_0000;
    #[cfg(loader_test_large_exec)]
    const XIP_IMAGE_SIZE: u32 = 0x0002_0000;

    #[cfg(loader_test_large_exec)]
    #[repr(C)]
    struct EraseRangeRequest {
        version: u32,
        size: u32,
        flags: u32,
        region_offset: u32,
        length: u32,
    }

    #[cfg(loader_test_large_exec)]
    #[repr(C)]
    struct MapExecRequest {
        version: u32,
        size: u32,
        flags: u32,
        region_offset: u32,
        image_size: u32,
        mapped_address: u32,
    }

    #[cfg(loader_test_large_exec)]
    fn flash_region_offset(vaddr: u32) -> Option<u32> {
        let physical =
            if (LARGE_TEST_REGION_START as u32..LARGE_TEST_REGION_END as u32).contains(&vaddr) {
                vaddr.checked_sub(IROM_VADDR_BASE)?
            } else if (LARGE_RODATA_REGION_START as u32..LARGE_RODATA_REGION_END as u32)
                .contains(&vaddr)
            {
                vaddr.checked_sub(DROM_VADDR_BASE)?
            } else {
                return None;
            };
        physical.checked_sub(LOADABLE_REGION_BASE)
    }

    #[cfg(loader_test_large_exec)]
    fn seek_flash(fd: i32, offset: u32) {
        use librs::syscall::{Sys, Syscall};

        assert_eq!(
            Sys::lseek(fd, offset as libc::off_t, libc::SEEK_SET),
            offset as libc::off_t
        );
    }

    #[cfg(loader_test_large_exec)]
    fn erase_flash(fd: i32, region_offset: u32, length: u32) {
        use librs::syscall::{Sys, Syscall};

        println!(
            "flash erase: offset={:#x}, length={:#x}",
            region_offset, length
        );
        let mut erase = EraseRangeRequest {
            version: FLASH_IOCTL_ABI_VERSION,
            size: core::mem::size_of::<EraseRangeRequest>() as u32,
            flags: 0,
            region_offset,
            length,
        };
        unsafe {
            Sys::ioctl(
                fd,
                ESP32_FLASH_ERASE_RANGE as libc::c_ulong,
                (&mut erase as *mut EraseRangeRequest).cast(),
            )
            .unwrap_or_else(|_| panic!("flash erase ioctl failed"));
        }
        println!("flash erase done");
    }

    #[cfg(loader_test_large_exec)]
    fn install_xip_segments(fd: i32, elf_data: &[u8]) {
        use librs::syscall::{Sys, Syscall};

        // Decode only the ELF32 program-header fields needed for flash
        // installation. `load_xip_elf` performs the one full Goblin parse;
        // avoiding a second parse keeps the ESP32-C3 test's heap footprint low.
        fn u16_at(data: &[u8], offset: usize) -> u16 {
            u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap())
        }
        fn u32_at(data: &[u8], offset: usize) -> u32 {
            u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
        }

        assert_eq!(&elf_data[..4], b"\x7fELF");
        assert_eq!(elf_data[4], 1, "XIP test image must be ELF32");
        assert_eq!(elf_data[5], 1, "XIP test image must be little-endian");
        let phoff = u32_at(elf_data, 28) as usize;
        let phentsize = u16_at(elf_data, 42) as usize;
        let phnum = u16_at(elf_data, 44) as usize;
        assert!(phentsize >= 32);
        let mut installed = 0;
        for index in 0..phnum {
            let ph = phoff + index * phentsize;
            assert!(ph + phentsize <= elf_data.len());
            let p_type = u32_at(elf_data, ph);
            let p_offset = u32_at(elf_data, ph + 4);
            let p_vaddr = u32_at(elf_data, ph + 8);
            let p_filesz = u32_at(elf_data, ph + 16);
            if p_type != 1 || p_filesz == 0 {
                continue;
            }
            let Some(region_offset) = flash_region_offset(p_vaddr) else {
                continue;
            };
            let file_start = p_offset as usize;
            let file_end = file_start + p_filesz as usize;
            let segment = &elf_data[file_start..file_end];
            assert!(region_offset + segment.len() as u32 <= XIP_IMAGE_SIZE);
            const SECTOR_SIZE: u32 = 4096;
            let erase_start = region_offset & !(SECTOR_SIZE - 1);
            let erase_end =
                (region_offset + segment.len() as u32 + SECTOR_SIZE - 1) & !(SECTOR_SIZE - 1);
            erase_flash(fd, erase_start, erase_end - erase_start);
            println!(
                "flash program: offset={:#x}, length={:#x}",
                region_offset,
                segment.len()
            );
            seek_flash(fd, region_offset);
            assert_eq!(
                Sys::write(fd, segment).unwrap_or_else(|_| panic!("flash write failed")),
                segment.len()
            );

            seek_flash(fd, region_offset);
            let mut checked = 0;
            let mut scratch = [0u8; 128];
            while checked < segment.len() {
                let count = core::cmp::min(scratch.len(), segment.len() - checked);
                assert_eq!(
                    Sys::read(fd, &mut scratch[..count])
                        .unwrap_or_else(|_| panic!("flash read-back failed")),
                    count
                );
                assert_eq!(&scratch[..count], &segment[checked..checked + count]);
                checked += count;
            }
            println!("flash program and verify done");
            installed += 1;
        }
        assert_eq!(installed, 2);
    }

    #[cfg(loader_test_exec)]
    static SHORT_REGIONS: [loader::MemoryRegion; 1] = [unsafe {
        // SAFETY: This is a valid subset of the configured loader test range.
        loader::MemoryRegion::new(
            TEST_REGION_START,
            TEST_REGION_START + 16,
            TEST_REGION_PERMISSIONS,
        )
    }];

    #[cfg(loader_test_exec)]
    static NON_EXEC_REGIONS: [loader::MemoryRegion; 1] = [unsafe {
        // SAFETY: The configured region supports read and write accesses.
        loader::MemoryRegion::new(
            TEST_REGION_START,
            TEST_REGION_END,
            loader::MemoryPermissions::READ.bitor(loader::MemoryPermissions::WRITE),
        )
    }];

    fn new_mapper() -> loader::MemoryMapper {
        #[cfg(loader_test_exec)]
        {
            loader::MemoryMapper::new(Some(&TEST_REGIONS))
        }
        #[cfg(not(loader_test_exec))]
        {
            loader::MemoryMapper::new(None)
        }
    }

    // FIXME: The PIC ELF file is too large in debug mode. We should use
    // lseek to parse the ELF file.
    #[cfg(not(debug_assertions))]
    #[test]
    fn test_load_elf_and_run() {
        let buf = read_all(unsafe { LOADER_TEST_ELF_PATH }).unwrap();
        let mut mapper = new_mapper();
        assert!(loader::load_elf(&buf, &mut mapper).is_ok());
        let entry = mapper.real_entry().unwrap();

        #[cfg(loader_test_exec)]
        {
            let run = unsafe { core::mem::transmute::<usize, extern "C" fn() -> u32>(entry) };
            assert_eq!(run(), EXPECTED_RESULT);
        }
        #[cfg(not(loader_test_exec))]
        {
            let run = unsafe { core::mem::transmute::<usize, fn()>(entry) };
            run();
        }
    }

    #[cfg(all(not(debug_assertions), loader_test_large_exec))]
    #[test]
    fn test_flash_load_uselibrs_elf_and_run_from_irom() {
        use librs::{
            c_str::CStr,
            syscall::{Sys, Syscall},
        };

        println!("reading XIP ELF");
        let buf = read_all(unsafe { LOADER_TEST_USELIBRS_ELF_PATH }).unwrap();
        println!("XIP ELF read: {} bytes", buf.len());
        let path = CStr::from_bytes_with_nul(FLASH_DEVICE_PATH).unwrap();
        let fd = Sys::open(path, libc::O_RDWR, 0);
        assert!(fd >= 0);
        println!("flash device opened");
        install_xip_segments(fd, &buf);
        println!("XIP segments installed");

        let mut map = MapExecRequest {
            version: FLASH_IOCTL_ABI_VERSION,
            size: core::mem::size_of::<MapExecRequest>() as u32,
            flags: 0,
            region_offset: 0,
            image_size: XIP_IMAGE_SIZE,
            mapped_address: 0,
        };
        unsafe {
            Sys::ioctl(
                fd,
                ESP32_FLASH_MAP_EXEC as libc::c_ulong,
                (&mut map as *mut MapExecRequest).cast(),
            )
            .unwrap_or_else(|_| panic!("flash map ioctl failed"));
        }
        assert_eq!(map.mapped_address as usize, LARGE_TEST_REGION_START);
        println!("flash mapped at {:#x}", map.mapped_address);

        let mut dram_safe = 0u32;
        unsafe {
            Sys::ioctl(
                fd,
                ESP32_FLASH_QUERY_DRAM_SAFE as libc::c_ulong,
                (&mut dram_safe as *mut u32).cast(),
            )
            .unwrap_or_else(|_| panic!("flash DRAM query ioctl failed"));
        }
        assert_eq!(dram_safe as usize, LARGE_DATA_REGION_START);
        Sys::close(fd).unwrap_or_else(|_| panic!("flash device close failed"));
        println!("flash device closed with XIP mapping retained");

        let mut mapper = loader::MemoryMapper::new(Some(&LARGE_TEST_REGIONS));
        assert!(loader::load_xip_elf(&buf, &mut mapper, &LARGE_XIP_REGIONS).is_ok());
        println!("non-XIP segments loaded");
        let entry = mapper.real_entry().unwrap();
        assert_eq!(entry, LARGE_TEST_REGION_START);
        let run = unsafe { core::mem::transmute::<usize, extern "C" fn() -> u32>(entry) };
        assert_eq!(run(), USELIBRS_EXPECTED_RESULT);
        println!("IROM entry returned");

        let fd = Sys::open(path, libc::O_RDWR, 0);
        assert!(fd >= 0);
        unsafe {
            Sys::ioctl(
                fd,
                ESP32_FLASH_UNMAP as libc::c_ulong,
                core::ptr::null_mut(),
            )
            .unwrap_or_else(|_| panic!("flash unmap ioctl failed"));
        }
        Sys::close(fd).unwrap_or_else(|_| panic!("flash device close failed"));
    }

    // FIXME: We should use FS's lseek API to get lower footprint.
    // TODO: Use semihosting's seek API to parse the ELF file.
    #[cfg(not(loader_test_exec))]
    #[test]
    fn test_seek_and_parse_elf() {}

    #[cfg(not(debug_assertions))]
    #[test]
    fn test_invalid_entry() {
        let res = read_all(unsafe { INVALID_ENTRY_ELF_PATH });
        assert!(res.is_ok());
        let buf = res.unwrap();
        let mut mapper = new_mapper();
        let res = loader::load_elf(buf.as_slice(), &mut mapper);
        assert!(res.is_err());
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn test_invalid_magic() {
        let res = read_all(unsafe { INVALID_MAGIC_ELF_PATH });
        assert!(res.is_ok());
        let buf = res.unwrap();
        let mut mapper = new_mapper();
        let res = loader::load_elf(buf.as_slice(), &mut mapper);
        assert!(res.is_err());
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn test_invalid_segment_size() {
        let res = read_all(unsafe { INVALID_SEGMENT_SIZE_ELF_PATH });
        assert!(res.is_ok());
        let buf = res.unwrap();
        let mut mapper = new_mapper();
        let res = loader::load_elf(buf.as_slice(), &mut mapper);
        assert!(res.is_err());
    }

    #[cfg(loader_test_exec)]
    #[test]
    fn test_exec_rejects_allocated_mapper() {
        let buf = read_all(unsafe { LOADER_TEST_ELF_PATH }).unwrap();
        let mut mapper = loader::MemoryMapper::new(None);
        assert!(loader::load_elf(&buf, &mut mapper).is_err());
    }

    #[cfg(loader_test_exec)]
    #[test]
    fn test_exec_rejects_out_of_range_without_writing() {
        let buf = read_all(unsafe { LOADER_TEST_ELF_PATH }).unwrap();
        let before = unsafe { (TEST_REGION_START as *const u32).read_volatile() };
        let mut mapper = loader::MemoryMapper::new(Some(&SHORT_REGIONS));
        assert!(loader::load_elf(&buf, &mut mapper).is_err());
        let after = unsafe { (TEST_REGION_START as *const u32).read_volatile() };
        assert_eq!(after, before);
    }

    #[cfg(loader_test_exec)]
    #[test]
    fn test_exec_rejects_non_executable_region() {
        let buf = read_all(unsafe { LOADER_TEST_ELF_PATH }).unwrap();
        let mut mapper = loader::MemoryMapper::new(Some(&NON_EXEC_REGIONS));
        assert!(loader::load_elf(&buf, &mut mapper).is_err());
    }
}

#[no_mangle]
pub fn loader_test_runner(tests: &[&dyn Fn()]) {
    println!("Loader integration test started");
    println!("Running {} tests", tests.len());
    for test in tests {
        test();
    }
    println!("Loader integration test ended");
}

#[no_mangle]
pub extern "C" fn main() -> i32 {
    pthread::register_my_posix_tcb();
    loader_test_main();
    #[cfg(coverage)]
    common_cov::write_coverage_data();
    0
}
