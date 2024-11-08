use aya_ebpf::EbpfContext;
use aya_ebpf::macros::map;
use aya_ebpf::maps::HashMap;
use aya_ebpf::programs::{LsmContext, RetProbeContext};
use aya_log_ebpf::info;

#[map(name = "ANTI_DEBUGGING")]
pub static mut ANTI_DEBUGGING: HashMap<u8, u8> = HashMap::with_max_entries(1, 0);

pub fn is_anti_debugging_enabled() -> bool {
    unsafe {
        match ANTI_DEBUGGING.get(&0) {
            None => {
                false
            }
            Some(&v) => {
                v == 1
            }
        }
    }
}

pub fn try_ptrace_anti_debugging(ctx: &LsmContext) -> Result<i32, i32> {
    info!(ctx, ">>>>>");
    if !is_anti_debugging_enabled() {
        Ok(0)
    } else {
        let comm_bytes = match ctx.command() {
            Ok(bytes) => { bytes }
            Err(_) => { return Err(0); }
        };

        let len = comm_bytes.iter()
            .position(|&x| x == 0)
            .unwrap_or(comm_bytes.len());
        let comm_name = unsafe { core::str::from_utf8_unchecked(&comm_bytes[..len]) };
        info!(ctx, "ptrace detected {}/{}", ctx.pid(), comm_name);
        Ok(-1)
    }
}
