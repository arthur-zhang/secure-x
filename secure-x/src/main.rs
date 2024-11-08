mod ebpf;
mod conf;
mod error;
use tokio::signal;
use crate::conf::get_conf;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    std::env::set_var("RUST_LOG", "debug");
    env_logger::init();

    let iface = "eth0";

    let mut ebpf_manager = match ebpf::EbpfManager::new(iface) {
        Ok(ebpf) => {
            println!("ebpf manager created");
            ebpf
        }
        Err(err) => {
            eprintln!("Failed to create ebpf manager: {}", err);
            return Err(err.into());
        }
    };

    let conf = get_conf().await?;

    ebpf_manager.init_from_conf(&conf)?;

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
