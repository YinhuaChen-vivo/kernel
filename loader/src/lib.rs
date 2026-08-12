// Copyright (c) 2025 vivo Mobile Communication Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![no_std]
#![feature(c_size_t)]

mod memory_mapper;
use goblin::elf::{
    header::{ET_DYN, ET_EXEC},
    reloc::R_RISCV_RELATIVE,
    Elf, Reloc,
};
use memory_mapper::MappingModeKind;
pub use memory_mapper::{MemoryMapper, MemoryPermissions, MemoryRegion};

pub type Result = core::result::Result<(), &'static str>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct XipRegion {
    start: usize,
    end: usize,
}

impl XipRegion {
    pub const fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    fn contains(self, start: usize, end: usize) -> bool {
        self.start < self.end && start >= self.start && end <= self.end
    }

    fn intersects(self, start: usize, end: usize) -> bool {
        self.start < end && start < self.end
    }
}

fn build_memory_layout(binary: &Elf, mapper: &mut MemoryMapper) -> Result {
    for ph in &binary.program_headers {
        match ph.p_type {
            goblin::elf::program_header::PT_LOAD => {
                // We're assuming loadable segments are compact.
                mapper
                    .update_start(ph.p_vaddr as usize)
                    .update_end((ph.p_vaddr + ph.p_memsz) as usize);
            }
            _ => continue,
        }
    }
    mapper.set_entry(binary.entry as usize);
    Ok(())
}

fn allocate_memory_for_segments(_binary: &Elf, mapper: &mut MemoryMapper) -> Result {
    mapper.allocate_memory()?;
    Ok(())
}

fn copy_content_to_memory(
    buffer: &[u8],
    binary: &Elf,
    mapper: &mut MemoryMapper,
    xip_regions: &[XipRegion],
) -> Result {
    for ph in &binary.program_headers {
        match ph.p_type {
            goblin::elf::program_header::PT_LOAD => {
                if ph.p_filesz > ph.p_memsz {
                    return Err("ELF segment file size exceeds memory size");
                }
                let start = usize::try_from(ph.p_vaddr).map_err(|_| "ELF address overflow")?;
                let mem_size = usize::try_from(ph.p_memsz).map_err(|_| "ELF size overflow")?;
                let end = start.checked_add(mem_size).ok_or("ELF address overflow")?;
                let in_xip = xip_regions
                    .iter()
                    .copied()
                    .any(|region| region.contains(start, end));
                if in_xip {
                    if ph.p_flags & goblin::elf::program_header::PF_W != 0 {
                        return Err("Writable ELF segment cannot execute in place");
                    }
                    continue;
                }
                if xip_regions
                    .iter()
                    .copied()
                    .any(|region| region.intersects(start, end))
                {
                    return Err("ELF segment crosses an XIP region boundary");
                }

                let file_offset =
                    usize::try_from(ph.p_offset).map_err(|_| "ELF file offset overflow")?;
                let file_size = usize::try_from(ph.p_filesz).map_err(|_| "ELF size overflow")?;
                let file_end = file_offset
                    .checked_add(file_size)
                    .ok_or("ELF file offset overflow")?;
                let Some(src) = buffer.get(file_offset..file_end) else {
                    return Err("Invalid indices to the buffer");
                };
                mapper.write_slice_at(start, src)?;
                let zero_size = mem_size - file_size;
                let zero_start = start.checked_add(file_size).ok_or("ELF address overflow")?;
                mapper.write_zeroes_at(zero_start, zero_size)?;
            }
            _ => continue,
        }
    }
    Ok(())
}

fn handle_riscv_relative_reloc(mapper: &mut MemoryMapper, reloc: &Reloc) -> Result {
    let vaddr = reloc.r_offset as usize;
    let val = mapper.real_start()? + reloc.r_addend.unwrap_or(0) as usize;
    mapper.write_value_at(vaddr, val)?;
    Ok(())
}

#[allow(clippy::single_match)]
fn relocate(binary: &Elf, mapper: &mut MemoryMapper) -> Result {
    let reloc_section = &binary.dynrelas;
    for reloc in reloc_section.iter() {
        match reloc.r_type {
            R_RISCV_RELATIVE => {
                handle_riscv_relative_reloc(mapper, &reloc)?;
            }
            _ => {}
        }
    }
    Ok(())
}

fn load_dyn_elf(buffer: &[u8], binary: &Elf, mapper: &mut MemoryMapper) -> Result {
    if mapper.mode_kind() != MappingModeKind::Allocated {
        return Err("ET_DYN requires Allocated mapping mode");
    }
    build_memory_layout(binary, mapper)?;
    allocate_memory_for_segments(binary, mapper)?;
    copy_content_to_memory(buffer, binary, mapper, &[])?;
    relocate(binary, mapper)?;
    mapper.real_entry()?;
    Ok(())
}

fn load_exec_elf(
    buffer: &[u8],
    binary: &Elf,
    mapper: &mut MemoryMapper,
    xip_regions: &[XipRegion],
) -> Result {
    if mapper.mode_kind() != MappingModeKind::Fixed {
        return Err("ET_EXEC requires Fixed mapping mode");
    }
    build_memory_layout(binary, mapper)?;
    copy_content_to_memory(buffer, binary, mapper, xip_regions)?;
    synchronize_instruction_stream();
    mapper.real_entry()?;
    Ok(())
}

/// Finish loading an ET_EXEC image whose read-only XIP segments have already
/// been installed in flash and mapped at their linked virtual addresses.
/// Non-XIP PT_LOAD segments are copied and zero-filled through `mapper`.
pub fn load_xip_elf(buffer: &[u8], mapper: &mut MemoryMapper, xip_regions: &[XipRegion]) -> Result {
    if mapper.mode_kind() != MappingModeKind::Fixed {
        return Err("XIP ET_EXEC requires Fixed mapping mode");
    }
    if xip_regions.is_empty() {
        return Err("XIP load requires at least one mapped region");
    }
    let binary = Elf::parse(buffer).map_err(|_| "Unable to parse the buffer")?;
    if binary.header.e_type != ET_EXEC {
        return Err("XIP load requires an ET_EXEC image");
    }
    let entry = usize::try_from(binary.entry).map_err(|_| "ELF entry overflow")?;
    if !xip_regions
        .iter()
        .copied()
        .any(|region| region.contains(entry, entry.saturating_add(1)))
    {
        return Err("ELF entry is outside mapped XIP regions");
    }
    load_exec_elf(buffer, &binary, mapper, xip_regions)
}

#[inline]
fn synchronize_instruction_stream() {
    #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
    unsafe {
        // PT_LOAD contents were written through the data path and may replace
        // instructions that are still present in the instruction cache.
        core::arch::asm!("fence.i", options(nostack, preserves_flags));
    }
}

// FIXME: We should use lseek to parse ELF files to achieve low footprint.
pub fn load_elf(buffer: &[u8], mapper: &mut MemoryMapper) -> Result {
    let binary = Elf::parse(buffer).map_err(|_| "Unable to parse the buffer")?;
    match binary.header.e_type {
        ET_DYN => load_dyn_elf(buffer, &binary, mapper),
        ET_EXEC => load_exec_elf(buffer, &binary, mapper, &[]),
        _ => Err("Unsupported ELF type"),
    }
}
