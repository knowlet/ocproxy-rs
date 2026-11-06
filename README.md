# ocproxy-rs

An independent Rust implementation of the documented [ocproxy](https://github.com/cernekee/ocproxy) interface: **SOCKS5 and local TCP forwarding through OpenConnect, without a TUN device or changes to host routing and DNS**.

OpenConnect authenticates to the VPN and encrypts its traffic. `ocproxy-rs` runs as its `--script-tun` child, reads raw IP packets from the inherited `VPNFD` UNIX datagram socket, and supplies a userspace TCP/IP stack using **smoltcp 0.14 with CUBIC congestion control**. **Tokio 1** drives listeners, bounded relays, packet readiness, and protocol timers.

Status: initial implementation. Automated tests use local socket pairs and synthetic packet peers; access to a real VPN gateway is not required. Actual gateway interoperability and performance need deployment testing. Linux and macOS are the intended platforms; Windows is not supported.

## Install

Rust **1.91 or newer** is required. Install [OpenConnect](https://www.infradead.org/openconnect/) separately.

```sh
cargo install --git https://github.com/knowlet/ocproxy-rs --branch develop --locked
```

Or build a checkout:

```sh
git clone https://github.com/knowlet/ocproxy-rs.git
cd ocproxy-rs
cargo build --locked --release
./target/release/ocproxy-rs --help
```

No root privileges or `/dev/net/tun` access are needed by this proxy. OpenConnect authentication requirements still depend on your VPN deployment.

## Forward a single endpoint

For a Palo Alto GlobalProtect VPN, expose one internal service locally:

```sh
openconnect --protocol=gp --script-tun \
  --script 'ocproxy-rs -L 15432:database.corp.example:5432' \
  https://vpn.example.com
```

Connect your database client to `127.0.0.1:15432`. The hostname is resolved by the VPN's DNS servers. Other application traffic continues to use the host's ordinary network configuration.

For Cisco AnyConnect, omit `--protocol=gp` (or select the appropriate OpenConnect protocol for your server).

## SOCKS5

```sh
openconnect --script-tun \
  --script 'ocproxy-rs -D 1080' \
  https://vpn.example.com
```

Have the client send the hostname to the proxy:

```sh
curl --socks5-hostname 127.0.0.1:1080 https://intranet.corp.example/
# Equivalent proxy URL:
curl --proxy socks5h://127.0.0.1:1080 https://intranet.corp.example/
```

A client using `socks5://` may resolve the hostname itself. Choose `socks5h://` or the client's remote-DNS setting when you want the VPN to resolve it.

SOCKS5 supports **CONNECT** with IPv4, IPv6, or a hostname and the no-authentication method. BIND, UDP ASSOCIATE, SOCKS4, HTTP CONNECT, and SOCKS username/password authentication are not implemented. A CONNECT success reply is sent only after the VPN TCP handshake completes.

## Multiple listeners and forwards

```sh
openconnect --script-tun \
  --script 'ocproxy-rs -D 1080 -L 2222:ssh.corp.example:22 -L 8443:web.corp.example:443' \
  https://vpn.example.com
```

```sh
ssh -p 2222 user@127.0.0.1
```

Listeners bind to `127.0.0.1` by default. An explicit bind address takes precedence over `-g`:

```sh
ocproxy-rs -D 127.0.0.2:1080 -L 127.0.0.2:8443:web.corp.example:443
ocproxy-rs -D '[::1]:1080' -L '[::1]:8443:[fd00::123]:443'
```

The commands above must run as an OpenConnect script with its inherited `VPNFD` and address configuration. They are not standalone VPN clients. The listener address family is independent of the VPN destination address family.

`-g` binds unspecified listeners to `0.0.0.0`. **There is no client authentication:** anyone who can reach an exposed listener can use its VPN access. Bind to an appropriate interface and apply your own network access controls when sharing it.

## Configuration

| Option | Meaning | Default |
| --- | --- | --- |
| `-D`, `--dynfw [IP:]PORT` | SOCKS5 listener; repeatable | None |
| `-L`, `--localfw [BIND_IP:]PORT:HOST:DEST_PORT` | TCP forward; repeatable | None |
| `-g`, `--allow-remote` | Default bind address becomes `0.0.0.0` | Loopback |
| `-I`, `--ip ADDRESS` | VPN-side IPv4 address | `INTERNAL_IP4_ADDRESS` |
| `--ipv6 ADDRESS` | VPN-side IPv6 address | `INTERNAL_IP6_ADDRESS` |
| `-M`, `--mtu BYTES` | Raw IP MTU | `INTERNAL_IP4_MTU`, else 1400 |
| `-d`, `--dns ADDRESS` | VPN DNS servers; repeatable, replaces environment list | `INTERNAL_IP4_DNS` and `INTERNAL_IP6_DNS` |
| `-o`, `--domain SUFFIX` | Search suffix for single-label names | `CISCO_DEF_DOMAIN` |
| `-k`, `--keepalive SECONDS` | VPN-side TCP keepalive interval | Disabled |
| `--vpn-fd FD` | Override inherited packet descriptor | `VPNFD` |
| `--connect-timeout SECONDS` | Overall DNS/TCP setup deadline | 30 |
| `--tcp-timeout SECONDS` | TCP transport stall / half-close cleanup timeout | 300 |
| `--handshake-timeout SECONDS` | SOCKS negotiation deadline | 10 |
| `--max-connections N` | Accepted-client limit shared by all listeners | 256 |
| `--buffer-size BYTES` | TCP/relay per-direction buffer size | 65536 |
| `-v`, `--verbose` | Debug diagnostics | Info |

At least one listener and one VPN address are required. Ports must be nonzero. Bind addresses must be IP literals. IPv6 addresses in listener and forwarding expressions require brackets.

The MTU is validated between 576 and 65535 bytes, with a minimum of 1280 when the VPN has IPv6. At most eight VPN DNS servers and 64 listeners are accepted. DNS-server address families must be configured on the VPN interface. Configuration limits bound connection count, packet queues, and relay memory; oversized configurations fail at startup.

When enabled, the keepalive interval must be shorter than `--tcp-timeout`. The transport timeout bounds stalled TCP transfers and half-closed connections. Ordinary idle established connections remain open when keepalives are disabled.

Logs go to stderr; `RUST_LOG=ocproxy_rs=debug` is also supported. Payload logging and the legacy `-T` option are deliberately unavailable.

## DNS behavior and limits

All proxy-side DNS packets use the userspace stack and the VPN socket. There is **no host resolver fallback**. IP-literal destinations work without DNS configuration; names fail when no usable DNS server is supplied.

A short name such as `database` can use `CISCO_DEF_DOMAIN` (or `-o`) as its suffix. An explicit trailing dot preserves an absolute name. Internal ASCII labels with underscores and IDNA A-labels are accepted; encode internationalized names as IDNA before passing them to the proxy.

DNS uses smoltcp's UDP resolver. A and AAAA queries are available for the configured VPN families. DNS over TCP, EDNS, and a separate CNAME chase are not implemented; an alias can resolve when the final address is present in the same response. There is no TCP retry for a truncated UDP reply: resolution may fail or use only the usable address records present in that reply. Unanswered queries are bounded by the setup deadline. See [the compatibility contract](docs/COMPATIBILITY.md) for address-family selection and fallback behavior.

## Lifecycle and failure behavior

- The inherited descriptor must be a connected UNIX datagram socket. Files, host UDP sockets, streams, invalid descriptors, and standard I/O descriptors are rejected.
- All configured listeners bind before readiness is announced. A failed bind stops startup.
- The accept limit includes clients still negotiating SOCKS or resolving DNS. Saturated listeners close new accepted connections.
- Relays propagate half-close independently so a server can respond after a client finishes sending its request.
- `SIGINT`, `SIGTERM`, and OpenConnect's `SIGHUP` stop listeners and cancel active connections. Shutdown does not promise to drain traffic after the tunnel is gone.
- VPN errors do not trigger any direct connection to a destination through the host network. OpenConnect owns reconnection and authentication.

An inherited UNIX datagram socket has no universal EOF notification when its peer disappears. OpenConnect's hangup signal is the normal shutdown mechanism; failed socket writes and TCP/setup timeouts cover other observable failures.

## Development and validation

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo build --locked --release
```

CI runs these checks on Linux and macOS, plus a Rust 1.91 compatibility check. The test suite covers configuration, inherited-descriptor validation, SOCKS byte framing, independent packet traffic, DNS, timeouts, cancellation, and process lifecycle. It does not require credentials, a VPN gateway, elevated privileges, or changes to routing.

The implementation uses original code and public interface/protocol information. The original ocproxy implementation, tests, patches, and bundled lwIP code were not used as implementation input. [CLEAN_ROOM.md](docs/CLEAN_ROOM.md) records the consulted sources and boundaries; [COMPATIBILITY.md](docs/COMPATIBILITY.md) distinguishes the documented legacy surface from extensions and limitations.

## License

Original project code is provided under the [MIT license](LICENSE). Dependencies retain their own licenses. OpenConnect is installed and run separately.
