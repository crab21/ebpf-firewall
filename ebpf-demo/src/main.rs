use std::fs::File;
use std::io::BufRead;
use std::net::{self, Ipv4Addr};
use std::path::Path;
use std::{io, vec};

use anyhow::Context;
use aya::maps::perf::AsyncPerfEventArray;
use aya::maps::HashMap;
use aya::programs::{Xdp, XdpFlags};
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use bytes::BytesMut;
use clap::{Parser, ArgAction};
use ebpf_demo_common::PacketLog;
use log::{info, warn, debug};
use tokio::{signal, task};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
    #[arg(short, long, default_value = "false")]
    udp_disable: bool,
    #[arg(short, long, default_value = "1")]
    action: u32,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/ebpf-demo"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/ebpf-demo"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut Xdp = bpf.program_mut("ebpf_demo").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::SKB_MODE)
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    let mut config: HashMap<_, u32, u32> = HashMap::try_from(bpf.map_mut("CONFIG")?)?;

    if opt.udp_disable {
        info!("===============> disable udp <==============");
        let u = 0u32.try_into()?;
        config.insert(u, 0, 0)?;
    }

    // tokio================>
    let mut blocklist: HashMap<_, u32, u32> = HashMap::try_from(bpf.map_mut("BLOCKLIST")?)?;

    //
    let ip_ww: Vec<String> = read_from_file();
    for vv in ip_ww {
        let v = vv.trim();
        let tmp: Result<Ipv4Addr, _> = v.parse();
        let tmpp = tmp.unwrap().try_into()?;
        blocklist.insert(tmpp, 0, 0)?;
        info!("ip_white: {:?}", v);
    }
    // ******************dns ip **********************

    let mut perf_array = AsyncPerfEventArray::try_from(bpf.map_mut("EVENTS")?)?;

    for cpu_id in online_cpus()? {
        //

        let mut buf = perf_array.open(cpu_id, None)?;

        //

        task::spawn(async move {
            //
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(256))
                .collect::<Vec<_>>();
            loop {
                //
                let events = buf.read_events(&mut buffers).await.unwrap();
                for i in 0..events.read {
                    let buf = &mut buffers[i];
                    let ptr = buf.as_ptr() as *const PacketLog;
                    //

                    let data = unsafe { ptr.read_unaligned() };
                    let src_addr = net::Ipv4Addr::from(data.ipv4_address);
                    let dst_addr = net::Ipv4Addr::from(data.dest_address);
                    //
                    if data.action == opt.action {
                        debug!(
                            "LOG: SRC {}-{} dst {}-{}, ACTION {}",
                            src_addr, data.source_port, dst_addr, data.dest_port, data.action
                        );
                    }
                }
                buffers = (0..10)
                    .map(|_| BytesMut::with_capacity(256))
                    .collect::<Vec<_>>();
            }
        });
    }

    signal::ctrl_c().await.expect("failed to listen for event");
    Ok::<_, anyhow::Error>(())
    // info!("Waiting for Ctrl-C...");
    // signal::ctrl_c().await?;
    // info!("Exiting...");

    // Ok(())
}

fn read_from_file() -> Vec<String> {
    let mut vc: Vec<String> = vec::Vec::new();
    if let Ok(lines) = read_lines("/root/ip_white") {
        for line in lines {
            if let Ok(ip) = line {
                let iip = ip.clone();
                vc.insert(0, iip);
            }
        }
    }
    vc
}

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}
