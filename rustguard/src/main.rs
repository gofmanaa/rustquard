use anyhow::Context as _;
use aya::{
    maps::HashMap,
    programs::{Xdp, XdpMode},
};
use clap::{Parser, Subcommand};
#[rustfmt::skip]
use log::{debug, info, warn};
use std::{net::Ipv4Addr, str::FromStr};

use rustguard_common::BanValue;
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    signal,
};

const SOCKET_PATH: &str = "/tmp/rustguard.sock";

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None, arg_required_else_help = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Start the rustguard daemon
    Daemon {
        #[clap(short, long, default_value = "eth0")]
        iface: String,
    },
    /// Ban a target (IP, CIDR, ASN, or Country)
    Ban {
        /// The target to ban (e.g., 1.2.3.4, 192.168.1.0/24, AS123, US)
        target: String,
        /// Time-to-live for the ban in seconds (_bin ban 1.2.3.4 --ttl 60)
        #[clap(long)]
        ttl: Option<u64>,
    },
    /// Unban a target
    Unban {
        /// The target to unban
        target: String,
    },
    /// List all active bans
    List,
    /// Show statistics
    Stats,
}

#[derive(Debug, Serialize, Deserialize)]
enum DaemonRequest {
    Ban { target: String, ttl: Option<u64> },
    Unban { target: String },
    List,
    Stats,
}

#[derive(Debug, Serialize, Deserialize)]
enum DaemonResponse {
    Ok,
    Error(String),
    List(Vec<String>),
    Stats(String),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    if let Commands::Daemon { .. } = &cli.command {
        env_logger::init();
    }

    match cli.command {
        Commands::Daemon { iface } => {
            run_daemon(iface).await?;
        }
        cmd => {
            send_command(cmd).await?;
        }
    }

    Ok(())
}

async fn send_command(cmd: Commands) -> anyhow::Result<()> {
    let mut stream = UnixStream::connect(SOCKET_PATH)
        .await
        .context("Failed to connect to rustguard daemon. Is it running?")?;

    let request = match cmd {
        Commands::Ban { target, ttl } => DaemonRequest::Ban { target, ttl },
        Commands::Unban { target } => DaemonRequest::Unban { target },
        Commands::List => DaemonRequest::List,
        Commands::Stats => DaemonRequest::Stats,
        _ => return Err(anyhow::anyhow!("Command not implemented for CLI")),
    };

    let req_bytes = serde_json::to_vec(&request)?;
    stream.write_u32(req_bytes.len() as u32).await?;
    stream.write_all(&req_bytes).await?;
    stream.flush().await?;

    let resp_len = match stream.read_u32().await {
        Ok(v) => v,
        Err(e) => {
            return Err(anyhow::anyhow!(
                "failed to read response length from daemon: {e}"
            ));
        }
    };

    if resp_len == 0 {
        return Err(anyhow::anyhow!("daemon returned empty response"));
    }

    let mut resp_buf = vec![0u8; resp_len as usize];

    stream
        .read_exact(&mut resp_buf)
        .await
        .context("failed to read full response body")?;

    let response: DaemonResponse = serde_json::from_slice(&resp_buf)?;

    match response {
        DaemonResponse::Ok => println!("Success"),
        DaemonResponse::Error(e) => println!("Error: {}", e),
        DaemonResponse::List(list) => {
            println!("Active bans:");
            for item in list {
                println!("  {}", item);
            }
        }
        DaemonResponse::Stats(s) => println!("Stats: {}", s),
    }

    Ok(())
}

fn get_boot_time_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) };
    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_nsec as u64)
}

async fn run_daemon(iface: String) -> anyhow::Result<()> {
    // Bump the memlock rlimit.
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/rustguard"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("failed to initialize eBPF logger: {e}");
    }

    let program: &mut Xdp = ebpf.program_mut("rustguard").unwrap().try_into()?;
    program.load()?;
    program
        .attach(&iface, XdpMode::default())
        .context("failed to attach the XDP program")?;

    // Prepare maps for access
    let mut banned_ips: HashMap<_, u32, BanValue> =
        ebpf.take_map("BANNED_IPS").unwrap().try_into()?;

    let stats: HashMap<_, u32, rustguard_common::StatsValue> =
        ebpf.take_map("STATS").unwrap().try_into()?;

    // Setup UDS
    let _ = std::fs::remove_file(SOCKET_PATH);
    let listener = UnixListener::bind(SOCKET_PATH)?;
    info!("Daemon started. Listening on {}", SOCKET_PATH);

    // Accept connections
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    warn!("accept error: {e}");
                    continue;
                }
            };

            let len = match stream.read_u32().await {
                Ok(v) => v,
                Err(e) => {
                    warn!("read len failed: {e}");
                    continue;
                }
            };

            let mut buf = vec![0u8; len as usize];

            if let Err(e) = stream.read_exact(&mut buf).await {
                warn!("read body failed: {e}");
                continue;
            }

            let resp = match serde_json::from_slice::<DaemonRequest>(&buf) {
                Ok(req) => match req {
                    DaemonRequest::Ban { target, ttl } => match Ipv4Addr::from_str(&target) {
                        Ok(ip) => {
                            let now = get_boot_time_ns();
                            let end_time = ttl.map(|t| now + t * 1_000_000_000).unwrap_or(0);

                            let value = BanValue { end_time };
                            let _ = banned_ips.insert(u32::from(ip), value, 0);

                            DaemonResponse::Ok
                        }
                        Err(_) => DaemonResponse::Error("invalid ip".into()),
                    },

                    DaemonRequest::Unban { target } => match Ipv4Addr::from_str(&target) {
                        Ok(ip) => {
                            let _ = banned_ips.remove(&u32::from(ip));
                            DaemonResponse::Ok
                        }
                        Err(_) => DaemonResponse::Error("invalid ip".into()),
                    },

                    DaemonRequest::List => {
                        let mut list = Vec::new();
                        for ip in banned_ips.keys().flatten() {
                            list.push(Ipv4Addr::from(ip).to_string());
                        }
                        DaemonResponse::List(list)
                    }

                    DaemonRequest::Stats => match stats.get(&0, 0) {
                        Ok(v) => DaemonResponse::Stats(format!(
                            "Packets dropped: {}, Bytes dropped: {}",
                            v.packets_dropped, v.bytes_dropped
                        )),
                        Err(_) => DaemonResponse::Stats("No stats".into()),
                    },
                },

                Err(e) => {
                    warn!("bad request json: {e}");
                    DaemonResponse::Error("invalid request".into())
                }
            };

            let resp_bytes = serde_json::to_vec(&resp).unwrap();

            if stream.write_u32(resp_bytes.len() as u32).await.is_err() {
                continue;
            }

            if stream.write_all(&resp_bytes).await.is_err() {
                continue;
            }

            let _ = stream.flush().await;
        }
    });

    let ctrl_c = signal::ctrl_c();
    println!(
        "Daemon running on interface {}. Press Ctrl-C to exit.",
        iface
    );
    ctrl_c.await?;
    println!("Exiting...");
    let _ = std::fs::remove_file(SOCKET_PATH);

    Ok(())
}
