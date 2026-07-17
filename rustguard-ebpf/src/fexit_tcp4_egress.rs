use core::ffi::c_long;

use aya_ebpf::{macros::fexit, programs::FExitContext};
use rustguard_common::event::{EventType, NetEvent};

use crate::{
    kernel::{current_comm, pid, tid, timestamp_ns, uid},
    socket::{EVENTS, fill_socket, protocol},
    vmlinux::sock,
};

#[fexit(function = "tcp_v4_connect_exit")]
pub fn tcp_v4_connect_exit(ctx: FExitContext) -> u32 {
    match try_tcp_v4_connect_exit(ctx) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

fn try_tcp_v4_connect_exit(ctx: FExitContext) -> Result<(), u32> {
    let sk = ctx.arg::<*const sock>(0);
    let ret = ctx.arg::<c_long>(3);
    let ret = ret as i32;
    // ret == 0      -> connect succeeded immediately
    // ret < 0       -> error (or -EINPROGRESS for non-blocking sockets)

    let mut event = NetEvent::default();

    event.ret = ret;

    event.timestamp_ns = timestamp_ns();
    event.socket_id = sk as u64;

    event.pid = pid();
    event.tid = tid();
    event.uid = uid();

    event.event = EventType::Connect;
    event.direction = event.event.direction();

    event.protocol = protocol(sk).map_err(|e| e as u32)?;
    fill_socket(&mut event, sk).map_err(|e| e as u32)?;

    event.comm = current_comm().map_err(|e| e as u32)?;

    EVENTS.output::<NetEvent>(&event, 0).map_err(|e| e as u32)?;

    Ok(())
}
