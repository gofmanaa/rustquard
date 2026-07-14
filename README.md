# RustGuard

RustGuard is an eBPF-based host firewall and connection monitor written in Rust.

It provides real-time visibility into outbound network connections and is designed as a foundation for building host-based firewall, intrusion detection, and internal network monitoring tools.

Features:

- Monitor all TCP connections on the host using eBPF
- Display process name, executable, PID, TID, protocol, and connection endpoints
- Block IP addresses from userspace
- List currently banned IP addresses
- Minimal overhead using eBPF
- Written entirely in Rust with Aya

# Install

Generate kernel bindings:

```bash
aya-tool generate task_struct > rustguard-ebpf/src/vmlinux.rs
```

Build the project:

```bash
cargo build --release
```

### Connection Monitor

Run monitor all connection on host:

```
RUST_LOG=info cargo run -- monitor

or

cargo build --release
sudo -E ./target/release/rustguard monitor
```

output:

```bash
COMM             EXE                             PID    TID EVENT      PROTO  DIR     SOURCE                 -> DESTINATION
nmap             /usr/bin/nmap                396730 396730 CONNECT TCP EGRESS 192.168.1.2:60308      -> 140.82.121.6:55055
nmap             /usr/bin/nmap                396730 396730 CONNECT TCP EGRESS 192.168.1.2:36938      -> 140.82.121.6:6566
nmap             /usr/bin/nmap                396730 396730 CONNECT TCP EGRESS 192.168.1.2:60544      -> 140.82.121.6:7070
Socket Thread    /usr/lib/firefox/firefox       7023   7266 CONNECT TCP EGRESS 192.168.1.2:41910      -> 140.82.114.25:443
Socket Thread    /usr/lib/firefox/firefox       7023   7266 CONNECT TCP EGRESS 192.168.1.2:41712      -> 140.82.121.4:443
Socket Thread    /usr/lib/firefox/firefox       7023   7266 CONNECT TCP EGRESS 192.168.1.2:41912      -> 140.82.114.25:443
NetworkManager   /usr/bin/NetworkManager         573    573 CONNECT TCP EGRESS 192.168.1.2:52364      -> 95.216.195.133:80
```

### Install as a System Service

```
sudo cp target/release/rustguard /usr/local/bin/
sudo cp rustguard.service /etc/systemd/system/

sudo systemctl daemon-reload
sudo systemctl enable rustguard
sudo systemctl start rustguard
```

check logs:

```
journalctl -u rustguard -f
```

Ban IP:

```bash
rustguard ban 1.1.1.1
```

List banned IP:

```bash
rustguard list
```

## Prerequisites

1. stable rust toolchains: `rustup toolchain install stable`
1. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
1. (if cross-compiling) rustup target: `rustup target add ${ARCH}-unknown-linux-musl`
1. (if cross-compiling) LLVM: (e.g.) `brew install llvm` (on macOS)
1. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)

## Build & Run

Use `cargo build`, `cargo check`, etc. as normal. Run your program with:

```shell
cargo run --release
```

Cargo build scripts are used to automatically build the eBPF correctly and include it in the
program.

## Cross-compiling on macOS

Cross compilation should work on both Intel and Apple Silicon Macs.

```shell
cargo build --package rustguard --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"rust-lld\"
```

The cross-compiled program `target/${ARCH}-unknown-linux-musl/release/rustguard` can be
copied to a Linux server or VM and run there.

## License

With the exception of eBPF code, rustguard is distributed under the terms
of either the [MIT license] or the [Apache License] (version 2.0), at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

### eBPF

All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2] or the [MIT license], at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the GPL-2 license, shall be
dual licensed as above, without any additional terms or conditions.

[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2
