#![allow(dead_code)]

use aya_ebpf::{
    EbpfContext,
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_get_socket_cookie, bpf_ktime_get_ns,
    },
    programs::ProbeContext,
};

pub const TASK_COMM_LEN: usize = 16;

#[inline(always)]
pub fn timestamp_ns() -> u64 {
    unsafe { bpf_ktime_get_ns() }
}

#[inline(always)]
pub fn pid() -> u32 {
    (bpf_get_current_pid_tgid() >> 32) as u32
}

#[inline(always)]
pub fn tid() -> u32 {
    bpf_get_current_pid_tgid() as u32
}

#[inline(always)]
pub fn uid() -> u32 {
    bpf_get_current_uid_gid() as u32
}

#[inline(always)]
pub fn pid_tgid() -> u64 {
    bpf_get_current_pid_tgid()
}

#[inline(always)]
pub fn current_comm() -> Result<[u8; TASK_COMM_LEN], i32> {
    bpf_get_current_comm()
}

#[inline(always)]
pub fn socket_cookie(ctx: &ProbeContext) -> u64 {
    unsafe { bpf_get_socket_cookie(ctx.as_ptr()) }
}

#[inline(always)]
pub fn ns_since(start: u64) -> u64 {
    timestamp_ns().wrapping_sub(start)
}

#[inline(always)]
pub fn is_zero_cookie(cookie: u64) -> bool {
    cookie == 0
}

#[inline(always)]
pub fn comm_to_str(comm: &[u8; TASK_COMM_LEN]) -> &[u8] {
    let mut len = TASK_COMM_LEN;

    let mut i = 0;

    while i < TASK_COMM_LEN {
        if comm[i] == 0 {
            len = i;
            break;
        }

        i += 1;
    }

    &comm[..len]
}
