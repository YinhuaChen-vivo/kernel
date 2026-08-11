// Copyright (c) 2026 vivo Mobile Communication Co., Ltd.
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

#![no_main]
#![no_std]

use core::{
    alloc::{GlobalAlloc, Layout},
    sync::atomic::{compiler_fence, Ordering},
};

const EXPECTED_RESULT: u32 = 0x4c49_4252;

// librs links liballoc even though msleep itself does not allocate.
struct NoAlloc;

unsafe impl GlobalAlloc for NoAlloc {
    unsafe fn alloc(&self, _layout: Layout) -> *mut u8 {
        core::ptr::null_mut()
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

#[global_allocator]
static GLOBAL_ALLOCATOR: NoAlloc = NoAlloc;

// RV32IMC has no A extension. The linked libatomic implementation serializes
// its fallback operations by calling these IRQ save/restore hooks.
#[no_mangle]
pub extern "C" fn disable_local_irq_save() -> usize {
    const MSTATUS_MIE: usize = 1 << 3;
    compiler_fence(Ordering::SeqCst);
    let old: usize;
    unsafe {
        core::arch::asm!(
            "csrrci {old}, mstatus, {bit}",
            bit = const MSTATUS_MIE,
            old = out(reg) old,
            options(nostack),
        );
    }
    old
}

#[no_mangle]
pub extern "C" fn enable_local_irq_restore(old: usize) {
    unsafe {
        core::arch::asm!("csrw mstatus, {old}", old = in(reg) old, options(nostack));
    }
    compiler_fence(Ordering::SeqCst);
}

#[no_mangle]
pub extern "C" fn _start() -> u32 {
    if librs::time::msleep(1000) == 0 {
        EXPECTED_RESULT
    } else {
        0
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
