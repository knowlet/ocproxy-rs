# Compatibility contract

`ocproxy-rs` targets ocproxy's documented SOCKS5 and TCP-forwarding use case.
The contract below defines the initial release's interface; it does not promise
equivalence for undocumented behavior or every legacy diagnostic option.
Reference provenance is recorded in [CLEAN_ROOM.md](CLEAN_ROOM.md).

## Traffic path

OpenConnect owns VPN authentication and encrypted transport. It launches this
program with `--script-tun --script`, supplying a connected UNIX datagram socket
through `VPNFD`. Each datagram contains one raw IP packet, without an Ethernet
header, TUN packet-information header, or BSD address-family prefix.

Tokio handles local application sockets; smoltcp 0.14 handles the VPN-side IP,
TCP, and DNS traffic with an IP-layer device and CUBIC congestion control. The
proxy does not create a kernel TUN interface, install routes, or change the host
resolver. It never opens a host
TCP connection to a requested VPN destination or uses the host resolver as a
fallback for that destination.

For example:

```sh
openconnect --script-tun \
  --script 'ocproxy-rs -D 11080 -L 2222:internal-host:22' \
  vpn.example.com
```

VPN protocol selection remains an OpenConnect setting. For GlobalProtect, add
`--protocol=gp` to the OpenConnect command. This does not change the proxy's
packet interface.

## Original command-line surface

| Option | Contract |
| --- | --- |
| `-D`, `--dynfw [bind_address:]port` | Start a SOCKS5 listener. |
| `-L`, `--localfw port:host:hostport` | Forward a local TCP port to a VPN destination; multiple forwards are supported. |
| `-g`, `--allow-remote` | Change the default listener address from `127.0.0.1` to `0.0.0.0`. |
| `-k`, `--keepalive seconds` | Configure TCP keepalives on VPN-side connections. This is separate from OpenConnect's encrypted-transport keepalive. |
| `-I`, `--ip address` | Override `INTERNAL_IP4_ADDRESS`. |
| `-M`, `--mtu bytes` | Override `INTERNAL_IP4_MTU`. |
| `-d`, `--dns address` | Override the VPN DNS-server configuration. |
| `-o`, `--domain suffix` | Override `CISCO_DEF_DOMAIN` for short destination names. |
| `-v`, `--verbose` | Increase diagnostics. |

The legacy `-T`/`--tcpdump` option is deliberately unsupported and is rejected
as an unknown argument. This implementation does not reproduce the original
text packet log at `/tmp/tcpdump` and does not log packet payloads.

Listeners use loopback by default. A non-loopback bind, including `-g`, exposes
an unauthenticated proxy to hosts that can reach that socket. It is an explicit
configuration choice, not an access-control mechanism.

## Configuration and extensions

| Input | Meaning |
| --- | --- |
| `VPNFD` | Inherited connected UNIX datagram descriptor. |
| `INTERNAL_IP4_ADDRESS` | VPN-side IPv4 address. |
| `INTERNAL_IP4_MTU` | Maximum IP packet size used by the stack. |
| `INTERNAL_IP4_DNS` | Space-separated VPN DNS-server addresses; optional when only numeric destinations are used. |
| `INTERNAL_IP6_DNS` | Space-separated IPv6 VPN DNS-server addresses; an extension to the original documented surface. |
| `CISCO_DEF_DOMAIN` | Optional suffix for unqualified destination names. |
| `INTERNAL_IP6_ADDRESS`, `--ipv6` | IPv6 address configuration, an extension to the original documented surface. |
| `--vpn-fd` | Explicit override for the inherited descriptor number. |
| `--connect-timeout` | Bound DNS/connection setup time. |
| `--tcp-timeout` | Bound stalled VPN TCP transport and half-close cleanup; defaults to 300 seconds. |
| `--handshake-timeout` | Bound the SOCKS greeting/request phase. |
| `--max-connections` | Bound concurrently handled application connections. |
| `--buffer-size` | Bound per-connection relay buffering. |

Run `ocproxy-rs --help` for exact argument syntax, defaults, and validation
rules. `INTERNAL_IP4_NETMASK` and VPN split-route variables do not install host
routes. The interface is a point-to-point packet transport; it does not use ARP
or neighbor discovery to reach the VPN gateway.

Additional syntax supported by this implementation includes repeated `-D`
listeners, repeated `-d` DNS-server overrides, and
`-L [BIND_IP:]PORT:HOST:DEST_PORT`. Bracket IPv6 literals when they appear in
listener/forward syntax, for example `-D '[::1]:11080'` or
`-L '[::1]:2222:[fd00::10]:22'`. Bind addresses must be IP literals and ports
must be in `1..=65535`; hostname binds and ephemeral listener port `0` are not
accepted. The VPN source address needs at least one configured IP family.

Up to eight distinct DNS-server addresses are accepted from the environment.
Each server must have a matching VPN source-address family. Explicit `-d`
arguments replace the environment's server list. The default MTU is 1400;
accepted values are 576 through 65535, with a minimum of 1280 when IPv6 is
configured. These defaults and validation choices are specific to this
implementation, not claims about undocumented ocproxy behavior.

`--tcp-timeout` is not an ordinary idle-session timeout. It limits stalled
transmission and keepalive failure through smoltcp's TCP timeout, and bounds
cleanup after the local application finishes sending. Delivered remote data
refreshes that half-close cleanup deadline. Idle established connections can
remain open when keepalives are disabled. When `-k` enables keepalives, its
interval must be shorter than `--tcp-timeout`.

Application buffers, packet queues, and fragment reassembly are bounded.
The four configured queues per flow have a combined limit of 1 GiB across
the configured maximum number of flows;
metadata, packet storage, and local TCP relay overhead are additional memory.
Up to four fragmented IP packets can be reassembled with 64 KiB buffers.

## SOCKS and DNS scope

The SOCKS server implements the no-authentication CONNECT subset of SOCKS5.
IPv4 addresses, domain names, and configured IPv6 destinations are accepted.
SOCKS4, authentication methods, BIND, and UDP ASSOCIATE are outside this
release's scope. Unsupported methods and commands fail explicitly; they do not
silently switch protocols. A successful reply means that the VPN-side TCP
connection was established.

Destination names are sent to the configured VPN DNS servers using smoltcp's
UDP DNS client. Single-label names use the configured domain suffix; a trailing
root dot makes a name absolute and prevents suffixing. Names must be ASCII DNS
names; clients must supply international names in IDNA A-label form. Numeric
destinations do not require DNS. If no usable VPN resolver is configured,
hostname connections fail without consulting `/etc/resolv.conf`, operating
system search domains, mDNS, or a public fallback resolver.

The resolver supports A/AAAA address queries for the configured IP families.
With both families configured, those queries run concurrently. Once at least
one query has usable answers, the actor uses answers already available and
cancels any still-pending query. Candidates are attempted sequentially, within
the overall connection deadline; there is no Happy Eyeballs connection race.
A successful answer from one family does not promise a later attempt using
the other family's answer.

Configured DNS servers are tried in order with smoltcp's resolver timeouts;
the overall connection deadline can expire before every server is attempted.
This failover handles missing replies; a negative or empty reply can end the
query without trying the next server.
CNAME responses work when the final address is included in the same response.
Separate CNAME chasing, EDNS, DNS-over-TLS, DNS-over-HTTPS, DNSSEC validation,
and DNS-over-TCP fallback are not implemented. Truncated replies cannot be
retried over TCP: a reply containing usable complete answer records may yield
only those addresses, while an incomplete record can cause the query to time
out. The resolver is not a recursive resolver or a local DNS forwarding service.
Application UDP forwarding is not
provided by the presence of internal UDP DNS support.

## Scope and validation limits

- `SIGHUP` from OpenConnect, `SIGINT`, and `SIGTERM` stop listeners and cancel
  active sessions. Tunnel-driver failure also stops the proxy. Shutdown does
  not promise to drain application sessions after the VPN has gone away.
- UNIX descriptor inheritance is required; Linux and macOS are the intended
  platforms. This is not a native Windows implementation.
- IPv6 is an extension, not a claim about original ocproxy IPv6 compatibility.
  Its use also requires an IPv6-capable VPN session and remote route.
- The experimental `vpnns` program, network namespaces, transparent redirection,
  and arbitrary IP forwarding from local applications are not included.
- OpenVPN's historical out-of-tree integration is not implemented or validated.
- Packet-peer tests validate local SOCKS, TCP relay, DNS, and raw packet
  interoperability paths. They do not replace a test against the user's actual
  OpenConnect version, VPN gateway, authentication flow, or production network.
- No throughput or latency advantage over the original implementation is
  claimed without a reproducible benchmark.
