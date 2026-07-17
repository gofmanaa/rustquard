use std::{
    collections::HashMap,
    fs, mem,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use aya::{Btf, maps::RingBuf, programs::FExit};
use aya_log::EbpfLogger;
use log::warn;
use rustguard_common::event::{EventType, NetEvent};

pub fn monitor_run() -> anyhow::Result<()> {
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/rustguard"
    )))?;

    match EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }

    let btf = Btf::from_sys_fs()?;

    let prog_egress: &mut FExit = ebpf
        .program_mut("tcp_v4_connect_exit")
        .unwrap()
        .try_into()?;

    prog_egress.load(
        "tcp_v4_connect", // kernel function name
        &btf,             // kernel BTF
    )?;
    prog_egress.attach()?;

    let prog_accept: &mut FExit = ebpf
        .program_mut("incoming_connection")
        .unwrap()
        .try_into()?;

    prog_accept.load(
        "inet_csk_accept", // kernel function name
        &btf,              // kernel BTF
    )?;
    prog_accept.attach()?;

    let mut ring = RingBuf::try_from(ebpf.take_map("EVENTS").context("EVENTS map missing")?)?;

    let mut cache = ProcessCache::default();

    println!(
        "{:<12} {:<16} {:>6} {:<5} {:<9} {:<10} CONNECTION",
        "TIME", "COMM", "PID", "PROTO", "EVENT", "RESULT",
    );

    loop {
        while let Some(item) = ring.next() {
            let bytes = item.as_ref();

            if bytes.len() != mem::size_of::<NetEvent>() {
                continue;
            }

            let event = unsafe { &*(bytes.as_ptr() as *const NetEvent) };

            print_event(event, &mut cache);
        }

        thread::sleep(Duration::from_millis(10));
    }
}

fn print_event(event: &NetEvent, cache: &mut ProcessCache) {
    let _exe = cache.exe(event.pid);

    let src = format!("{}:{}", ip_to_string(&event.src_ip), event.src_port);
    let dst = format!("{}:{}", ip_to_string(&event.dst_ip), event.dst_port);

    println!(
        "{:<12} {:<16} {:>6} {:<5} {:<9} {:<10} {} {} {}",
        now_string(),
        comm_to_string(&event.comm),
        event.pid,
        event.protocol,
        event.event,
        result_string(event.ret),
        src,
        arrow(event.event),
        dst,
    );
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

fn now_string() -> String {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();

    let secs = now.as_secs() % 86_400;
    let ms = now.subsec_millis();

    format!(
        "{:02}:{:02}:{:02}.{:03}",
        secs / 3600,
        (secs / 60) % 60,
        secs % 60,
        ms
    )
}

fn result_string(ret: i32) -> String {
    if ret == 0 {
        "OK".into()
    } else {
        format!("ERR({})", ret)
    }
}

fn arrow(event: EventType) -> &'static str {
    match event {
        EventType::Connect => "─────▶",
        EventType::Accept => "◀─────",
        _ => "──────",
    }
}
