use anyhow::Context;
use aya::{Btf, Ebpf};
use aya::maps::HashMap;
use aya::programs::{KProbe, Lsm, Xdp, XdpFlags};
use aya::programs::ProbeKind::KRetProbe;
use log::{debug, info, warn};
use crate::conf::{Conf, FirewallConf, IncomingPolicy, Rule, Status};

pub struct EbpfManager {
    ebpf: Ebpf,
}
impl EbpfManager {
    pub fn new(iface: &str) -> anyhow::Result<Self> {

        // Bump the memlock rlimit. This is needed for older kernels that don't use the
        // new memcg based accounting, see https://lwn.net/Articles/837122/
        let rlim = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
        if ret != 0 {
            debug!("remove limit on locked memory failed, ret is: {}", ret);
        }

        // This will include your eBPF object file as raw bytes at compile-time and load it at
        // runtime. This approach is recommended for most real-world use cases. If you would
        // like to specify the eBPF program at runtime rather than at compile-time, you can
        // reach for `Bpf::load_file` instead.
        let bpf_path = concat!(env!("OUT_DIR"), "/secure-x");
        info!("Loading eBPF program from {:?}", bpf_path);
        let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/secure-x")))?;
        if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {}", e);
        }

        let firewall_prog: &mut Xdp =
            ebpf.program_mut("incoming_port_firewall").unwrap().try_into()?;
        firewall_prog.load()?;
        firewall_prog.attach(&iface, XdpFlags::SKB_MODE)
            .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;


        let btf = Btf::from_sys_fs()?;
        let program: &mut Lsm = ebpf.program_mut("ptrace_anti_debugging").unwrap().try_into()?;
        program.load("ptrace_access_check", &btf)?;
        program.attach()?;

        Ok(Self { ebpf })
    }
    pub fn set_firewall_status(&mut self, status: Status) -> anyhow::Result<()> {
        let mut firewall_status: HashMap<_, u8, u8> =
            HashMap::try_from(self.ebpf.map_mut("FIREWALL_STATUS").unwrap())?;
        let ebpf_status: u8 = status.into();
        firewall_status.insert(&0, &ebpf_status, 0)?;

        Ok(())
    }
    pub fn set_anti_debugging(&mut self, flag: Status) -> anyhow::Result<()> {
        println!("set_anti_debugging {:?}", flag);
        let mut anti_debugging: HashMap<_, u8, u8> =
            HashMap::try_from(self.ebpf.map_mut("ANTI_DEBUGGING").unwrap())?;
        let ebpf_status: u8 = flag.into();
        anti_debugging.insert(&0, &ebpf_status, 0)?;

        Ok(())
    }
    pub fn init_rules(&mut self, rules: &[Rule]) -> anyhow::Result<()> {
        let mut port_rules: HashMap<_, u16, u8> =
            HashMap::try_from(self.ebpf.map_mut("PORT_RULES").unwrap())?;

        for rule in rules {
            let action: u8 = rule.action.into();
            port_rules.insert(&rule.port, &action, 0)?;
        }

        Ok(())
    }

    pub fn update_incoming_policy(&mut self, policy: IncomingPolicy) -> anyhow::Result<()> {
        let mut inbound_default: HashMap<_, u8, u8> =
            HashMap::try_from(self.ebpf.map_mut("INCOMING_DEFAULT").unwrap())?;
        let action: u8 = policy.into();
        inbound_default.insert(&0, &action, 0)?;

        Ok(())
    }
    pub fn init(&mut self, conf: &Conf) -> anyhow::Result<()> {
        self.init_basic(&conf)?;
        self.init_firewall(&conf)?;
        Ok(())
    }

    pub fn init_firewall(&mut self, conf: &Conf) -> anyhow::Result<()> {
        self.set_firewall_status(conf.firewall.status)?;
        self.init_rules(&conf.firewall.rules)?;
        self.update_incoming_policy(conf.firewall.incoming_policy)?;
        Ok(())
    }
    pub fn init_basic(&mut self, conf: &Conf) -> anyhow::Result<()> {
        self.set_anti_debugging(conf.basic.anti_debugging)?;
        Ok(())
    }
}