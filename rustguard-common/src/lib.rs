#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BanValue {
    pub end_time: u64, // timestamp when ban expires, 0 for permanent
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for BanValue {}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct StatsValue {
    pub packets_dropped: u64,
    pub bytes_dropped: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for StatsValue {}
