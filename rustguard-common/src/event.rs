use core::{fmt, mem};

pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;

pub const IPPROTO_IP: u16 = 0;
pub const IPPROTO_ICMP: u16 = 1;
pub const IPPROTO_TCP: u16 = 6;
pub const IPPROTO_UDP: u16 = 17;
pub const IPPROTO_IPV6: u16 = 41;
pub const IPPROTO_ICMPV6: u16 = 58;
pub const IPPROTO_SCTP: u16 = 132;

/// Process name length used by Linux (`TASK_COMM_LEN`).
pub const TASK_COMM_LEN: usize = 16;

/// IPv6 address size (IPv4 is stored as IPv4-mapped IPv6).
pub const IP_ADDR_LEN: usize = 16;

#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EventType {
    #[default]
    Unknown = 0,

    /// Outgoing connection initiated.
    Connect = 1,

    /// Incoming connection accepted.
    Accept = 2,

    /// Data transmitted.
    Send = 3,

    /// Data received.
    Recv = 4,

    /// Socket closed.
    Close = 5,

    /// Socket state changed (optional, for TCP state tracking).
    StateChange = 6,

    /// DNS query.
    Dns = 7,

    /// TLS handshake detected.
    TlsHandshake = 8,
}

impl EventType {
    #[inline(always)]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "UNKNOWN",
            Self::Connect => "CONNECT",
            Self::Accept => "ACCEPT",
            Self::Send => "SEND",
            Self::Recv => "RECV",
            Self::Close => "CLOSE",
            Self::StateChange => "STATE",
            Self::Dns => "DNS",
            Self::TlsHandshake => "TLS",
        }
    }

    #[inline(always)]
    pub const fn direction(self) -> Direction {
        match self {
            Self::Connect | Self::Send => Direction::Egress,
            Self::Accept | Self::Recv => Direction::Ingress,
            Self::Close | Self::StateChange | Self::Dns | Self::TlsHandshake | Self::Unknown => {
                Direction::Unknown
            }
        }
    }
}

impl fmt::Display for EventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub enum TransportProtocol {
    #[default]
    Unknown = 0,
    Tcp = 6,
    Udp = 17,
}
impl fmt::Display for TransportProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportProtocol::Unknown => write!(f, "UNKNOWN"),
            TransportProtocol::Tcp => write!(f, "TCP"),
            TransportProtocol::Udp => write!(f, "UDP"),
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub enum Direction {
    #[default]
    Unknown = 0,
    Ingress = 1,
    Egress = 2,
}
impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Direction::Unknown => write!(f, "UNKNOWN"),
            Direction::Ingress => write!(f, "INGRESS"),
            Direction::Egress => write!(f, "EGRESS"),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct NetEvent {
    /// Monotonic timestamp
    pub timestamp_ns: u64,

    /// Temporary socket identifier (struct sock *)
    pub socket_id: u64,

    /// Process information
    pub pid: u32,
    pub tid: u32,
    pub uid: u32,

    /// Event metadata
    pub event: EventType,
    pub protocol: TransportProtocol,
    pub direction: Direction,

    /// Process name
    pub comm: [u8; TASK_COMM_LEN],

    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub ret: i32,
}

impl NetEvent {
    // #[inline]
    // pub const fn new() -> Self {
    //     Self {
    //         timestamp_ns: 0,
    //         socket_cookie: 0,

    //         pid: 0,
    //         tid: 0,
    //         uid: 0,

    //         event: EventType::Unknown,
    //         protocol: TransportProtocol::Unknown,
    //         direction: Direction::Unknown,

    //         flags: 0,
    //         bytes: 0,

    //         src_ip: [0; IP_ADDR_LEN],
    //         dst_ip: [0; IP_ADDR_LEN],

    //         src_port: 0,
    //         dst_port: 0,

    //         comm: [0; TASK_COMM_LEN],
    //     }
    // }

    #[inline]
    pub const fn size() -> usize {
        mem::size_of::<Self>()
    }
}
