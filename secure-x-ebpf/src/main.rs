#![no_std]
#![no_main]

mod utils;
pub mod firewall;

use aya_ebpf::{macros::lsm, programs::LsmContext};
use aya_ebpf::bindings::xdp_action;
use aya_ebpf::macros::xdp;
use aya_ebpf::programs::XdpContext;
use aya_log_ebpf::info;


#[xdp]
pub fn incoming_port_firewall(ctx: XdpContext) -> u32 {
    match firewall::try_port_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
