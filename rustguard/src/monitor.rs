use std::{
    collections::HashMap,
    fs, mem,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    thread,
    time::{Duration, Instant},
};

use anyhow::Context;
use aya::{Btf, maps::RingBuf, programs::FExit};
use rustguard_common::event::NetEvent;

pub fn monitor_run() -> anyhow::Result<()> {
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/rustguard"
    )))?;

    let btf = Btf::from_sys_fs()?;

    let prog: &mut FExit = ebpf.program_mut("tcp_v4_connect").unwrap().try_into()?;

    prog.load(
        "tcp_v4_connect", // kernel function name
        &btf,             // kernel BTF
    )?;
    prog.attach()?;

    // let prog: &mut KProbe = ebpf.program_mut("tcp_v4_connect").unwrap().try_into()?;
    // prog.load()?;
    // prog.attach("tcp_v4_connect", 0)?;

    let mut ring = RingBuf::try_from(ebpf.take_map("EVENTS").context("EVENTS map missing")?)?;

    let mut cache = ProcessCache::default();

    println!(
        "{:<16} {:<28} {:>6} {:>6} {:<10} {:<6} {:<7} {:<22} -> {:<22}",
        "COMM", "EXE", "PID", "TID", "EVENT", "PROTO", "DIR", "SOURCE", "DESTINATION"
    );

    loop {
        while let Some(item) = ring.next() {
            let bytes = item.as_ref();

            if bytes.len() != mem::size_of::<NetEvent>() {
                continue;
            }

            let event = unsafe { &*(bytes.as_ptr() as *const NetEvent) };

            let exe = cache.exe(event.pid);

            println!(
                "{:<16} {:<28} {:>6} {:>6} {:<10} {:<6} {:<7} {:<22} -> {:<22}",
                comm_to_string(&event.comm),
                exe,
                event.pid,
                event.tid,
                event.event,
                event.protocol,
                event.direction,
                format!("{}:{}", ip_to_string(&event.src_ip), event.src_port),
                format!("{}:{}", ip_to_string(&event.dst_ip), event.dst_port),
            );
        }

        thread::sleep(Duration::from_millis(10));
    }
}

fn comm_to_string(comm: &[u8]) -> String {
    let len = comm.iter().position(|&b| b == 0).unwrap_or(comm.len());
    String::from_utf8_lossy(&comm[..len]).into_owned()
}

fn ip_to_string(ip: &[u8; 16]) -> String {
    // IPv4 stored in first 4 bytes
    if ip[4..].iter().all(|&b| b == 0) {
        return IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])).to_string();
    }

    // IPv4-mapped IPv6 (::ffff:a.b.c.d)
    if ip[..10].iter().all(|&b| b == 0) && ip[10] == 0xff && ip[11] == 0xff {
        return IpAddr::V4(Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15])).to_string();
    }

    IpAddr::V6(Ipv6Addr::from(*ip)).to_string()
}

#[derive(Default)]
struct ProcessCache {
    cache: HashMap<u32, (String, Instant)>,
}

impl ProcessCache {
    fn exe(&mut self, pid: u32) -> String {
        const TTL: Duration = Duration::from_secs(30);

        if let Some((exe, ts)) = self.cache.get(&pid)
            && ts.elapsed() < TTL
        {
            return exe.clone();
        }

        let exe = fs::read_link(format!("/proc/{pid}/exe"))
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "<unknown>".into());

        self.cache.insert(pid, (exe.clone(), Instant::now()));

        exe
    }
}
