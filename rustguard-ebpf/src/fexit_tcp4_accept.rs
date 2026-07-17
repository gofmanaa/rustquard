use aya_ebpf::{macros::fexit, programs::FExitContext};
use rustguard_common::event::{EventType, NetEvent};

use crate::{
    kernel::{current_comm, pid, tid, timestamp_ns, uid},
    socket::{EVENTS, fill_socket, protocol},
    vmlinux::sock,
};

#[fexit(function = "inet_csk_accept")]
pub fn incoming_connection(ctx: FExitContext) -> u32 {
    match try_incoming_connection(ctx) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

fn try_incoming_connection(ctx: FExitContext) -> Result<(), u32> {
    // Adjust index if your kernel has a different prototype.
    //let newsk = ctx.arg::<*const sock>(4);

    let newsk: *const sock = ctx.ret().map_err(|e| e as u32)?;

    if newsk.is_null() {
        return Ok(());
    }

    let mut event = NetEvent::default();

    event.timestamp_ns = timestamp_ns();
    event.socket_id = newsk as u64;

    event.pid = pid();
    event.tid = tid();
    event.uid = uid();

    event.event = EventType::Accept;
    event.direction = event.event.direction();

    event.protocol = protocol(newsk).map_err(|e| e as u32)?;
    fill_socket(&mut event, newsk).map_err(|e| e as u32)?;

    event.comm = current_comm().map_err(|e| e as u32)?;

    EVENTS.output::<NetEvent>(&event, 0).map_err(|e| e as u32)?;

    Ok(())
}
