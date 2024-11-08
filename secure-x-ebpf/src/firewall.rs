use aya_ebpf::macros::map;
use aya_ebpf::maps::HashMap;

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_ebpf::bindings::BPF_ANY;
use aya_log_ebpf::info;
use network_types::eth::{EthHdr, EtherType};
use network_types::ip::{IpHdr, IpProto, Ipv4Hdr, Ipv6Hdr};
use network_types::tcp::TcpHdr;
use utils::xdp::ptr_at;
use crate::utils;

#[repr(C)]
enum EbpfInboundAction {
    Accept = 1,
    Deny = 0,
}

#[map(name = "FIREWALL_STATUS")]
pub static mut FIREWALL_STATUS: HashMap<u8, u8> = HashMap::with_max_entries(1, 0);


pub fn get_firewall_status() -> u8 {
    unsafe {
        match FIREWALL_STATUS.get(&0) {
            None => {
                0
            }
            Some(&v) => {
                v
            }
        }
    }
}
pub fn set_firewall_status(status: u8) {
    unsafe {
        match FIREWALL_STATUS.insert(&0, &status, BPF_ANY as u64) {
            Ok(_) => {}
            Err(_) => {}
        }
    }
}

#[map(name = "PORT_RULES")]
static mut PORT_RULES: HashMap<u16, u8> = HashMap::with_max_entries(1024, 0);


#[map(name = "INCOMING_DEFAULT")]
static mut INCOMING_DEFAULT: HashMap<u8, u8> = HashMap::with_max_entries(1, 0);

fn get_inbound_default() -> u8 {
    unsafe {
        match INCOMING_DEFAULT.get(&0) {
            None => {
                1
            }
            Some(&v) => {
                v
            }
        }
    }
}
fn port_rule(port: u16) -> Option<EbpfInboundAction> {
    unsafe {
        match PORT_RULES.get(&port) {
            None => {
                None
            }
            Some(&v) => {
                match v {
                    0 => Some(EbpfInboundAction::Deny),
                    1 => Some(EbpfInboundAction::Accept),
                    _ => None,
                }
            }
        }
    }
}
pub fn try_port_firewall(ctx: XdpContext) -> Result<u32, ()> {
    if 0 == get_firewall_status() {
        return Ok(xdp_action::XDP_PASS);
    }

    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0) }?;
    let proto = unsafe { *ethhdr }.ether_type;
    if proto != EtherType::Ipv4 && proto != EtherType::Ipv6 {
        return Ok(xdp_action::XDP_PASS);
    }
    match proto {
        EtherType::Ipv4 => {
            let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
            let proto = unsafe { (*ipv4hdr).proto };
            match proto {
                IpProto::Tcp => {
                    let tcphdr: *const TcpHdr =
                        unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN) }?;
                    unsafe {
                        if (*tcphdr).syn() == 0 {
                            return Ok(xdp_action::XDP_PASS);
                        }
                    }

                    let port = unsafe { u16::from_be((*tcphdr).dest) };

                    match port_rule(port) {
                        None => {
                            if get_inbound_default() == 0 {
                                return Ok(xdp_action::XDP_DROP);
                            }
                        }
                        Some(EbpfInboundAction::Accept) => {
                            return Ok(xdp_action::XDP_PASS);
                        }
                        Some(EbpfInboundAction::Deny) => {
                            return Ok(xdp_action::XDP_DROP);
                        }
                    };
                }
                IpProto::Udp => {}
                _ => {
                    return Ok(xdp_action::XDP_PASS);
                }
            }
        }
        EtherType::Ipv6 => {
            // let ipv6hdr: *const Ipv6Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
            // unreachable!()
            return Ok(xdp_action::XDP_PASS);
        }
        _ => {
            return Ok(xdp_action::XDP_PASS);
        }
    }


    Ok(xdp_action::XDP_PASS)
}

