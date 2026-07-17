use aya_ebpf::{helpers::bpf_probe_read_kernel, macros::map, maps::RingBuf};
use rustguard_common::event::*;

use crate::vmlinux::{sock, sock_common};

#[map(name = "EVENTS")]
pub static EVENTS: RingBuf = RingBuf::with_byte_size(1024 * 1024, 0);

#[inline(always)]
pub fn fill_socket(event: &mut NetEvent, sk: *const sock) -> Result<(), i64> {
    let common: sock_common = unsafe { bpf_probe_read_kernel(&(*sk).__sk_common)? };

    match common.skc_family as u16 {
        AF_INET => fill_ipv4(event, &common),
        AF_INET6 => fill_ipv6(event, &common),
        _ => {}
    }

    Ok(())
}

#[inline(always)]
fn fill_ipv4(event: &mut NetEvent, common: &sock_common) {
    let src = unsafe { common.__bindgen_anon_1.__bindgen_anon_1.skc_rcv_saddr };

    let dst = unsafe { common.__bindgen_anon_1.__bindgen_anon_1.skc_daddr };

    event.src_ip = [0; 16];
    event.dst_ip = [0; 16];

    event.src_ip[..4].copy_from_slice(&src.to_ne_bytes());
    event.dst_ip[..4].copy_from_slice(&dst.to_ne_bytes());

    event.src_port = unsafe { common.__bindgen_anon_3.__bindgen_anon_1.skc_num };

    event.dst_port = u16::from_be(unsafe { common.__bindgen_anon_3.__bindgen_anon_1.skc_dport });
}

#[inline(always)]
fn fill_ipv6(event: &mut NetEvent, common: &sock_common) {
    unsafe {
        event
            .src_ip
            .copy_from_slice(&common.skc_v6_rcv_saddr.in6_u.u6_addr8);

        event
            .dst_ip
            .copy_from_slice(&common.skc_v6_daddr.in6_u.u6_addr8);

        event.src_port = common.__bindgen_anon_3.__bindgen_anon_1.skc_num;

        event.dst_port = u16::from_be(common.__bindgen_anon_3.__bindgen_anon_1.skc_dport);
    }
}

#[inline(always)]
pub fn protocol(sk: *const sock) -> Result<TransportProtocol, i64> {
    let proto: u16 = unsafe { bpf_probe_read_kernel(&(*sk).sk_protocol)? };

    Ok(match proto {
        IPPROTO_TCP => TransportProtocol::Tcp,
        IPPROTO_UDP => TransportProtocol::Udp,
        _ => TransportProtocol::Unknown,
    })
}
