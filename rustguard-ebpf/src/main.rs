#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_ktime_get_ns,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
};
use rustguard_common::{BanValue, StatsValue};

#[map]
static BANNED_IPS: HashMap<u32, BanValue> = HashMap::with_max_entries(1024, 0); //4096

#[map]
static STATS: HashMap<u32, StatsValue> = HashMap::with_max_entries(1024, 0);
//static STATS: PerCpuHashMap<u32, StatsValue, 1024, 0> = PerCpuHashMap::new();

#[xdp]
pub fn rustguard(ctx: XdpContext) -> u32 {
    match try_rustguard(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

fn try_rustguard(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;
    match unsafe { (*ethhdr).ether_type() } {
        Ok(EtherType::Ipv4) => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let src_addr = u32::from_be_bytes(unsafe { (*ipv4hdr).src_addr });

    if let Some(ban_ptr) = BANNED_IPS.get_ptr(&src_addr) {
        let ban = unsafe { &*ban_ptr };
        if ban.end_time != 0 {
            let now = unsafe { bpf_ktime_get_ns() };
            if now > ban.end_time {
                return Ok(xdp_action::XDP_PASS);
            }
        }

        let key = 0u32;
        if let Some(stat) = STATS.get_ptr_mut(&key) {
            unsafe {
                (*stat).packets_dropped += 1;
            }
        } else {
            let new_stat = StatsValue {
                packets_dropped: 1,
                bytes_dropped: 0,
            };
            let _ = STATS.insert(&key, &new_stat, 0);
        }

        return Ok(xdp_action::XDP_DROP);
    }

    Ok(xdp_action::XDP_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
