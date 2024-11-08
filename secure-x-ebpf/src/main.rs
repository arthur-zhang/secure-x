#![no_std]
#![no_main]

mod utils;
pub mod firewall;
mod anti_debugging;

use aya_ebpf::bindings::xdp_action;
use aya_ebpf::macros::{lsm, xdp};
use aya_ebpf::programs::XdpContext;
use aya_ebpf::{programs::LsmContext, EbpfContext};
use aya_log_ebpf::info;
use crate::anti_debugging::try_ptrace_anti_debugging;

#[xdp]
pub fn incoming_port_firewall(ctx: XdpContext) -> u32 {
    match firewall::try_port_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED
    }
}

#[lsm]
pub fn ptrace_anti_debugging(ctx: LsmContext) -> i32 {
    match try_ptrace_anti_debugging(&ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
