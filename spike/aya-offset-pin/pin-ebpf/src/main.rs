#![no_std]
#![no_main]

use aya_ebpf::macros::{map, uprobe};
use aya_ebpf::maps::Array;
use aya_ebpf::programs::ProbeContext;

#[map]
static HITS: Array<u64> = Array::with_max_entries(1, 0);

#[uprobe]
pub fn pin(_ctx: ProbeContext) -> u32 {
    if let Some(v) = HITS.get_ptr_mut(0) {
        unsafe { *v += 1 };
    }
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
