# Implementation provenance

This project is an independent Rust implementation of the documented ocproxy
use case: expose selected VPN destinations through local SOCKS5 and TCP
listeners without creating a host tunnel interface. The initial implementation
uses Tokio and smoltcp rather than porting ocproxy's C implementation or its
bundled network stack.

This document records the engineering process and its boundaries. It is not a
formal legal certification of a clean-room development process.

## Reference boundary

For the initial implementation, dated 2026-11-06:

- The reference repository was not cloned.
- The original project's README and manual were consulted for public behavior,
  command-line syntax, and environment-variable names.
- The original implementation source, patches, implementation tests, and
  bundled lwIP source were not used to write this project.
- SOCKS framing is specified independently by RFC 1928.
- OpenConnect's documentation was used to identify the packet-socket interface.
  A narrowly scoped inspection of the **peer application's** `tun.c` established
  descriptor type, packet boundaries, framing, and shutdown signaling where its
  manual did not give that detail. This was not an inspection of ocproxy.
- Application source, tests, and prose in this repository were written for this
  project. Third-party Rust crates retain their own licenses.

The term "clean-room" here describes an implementation derived from the public
interface and protocol contract, with the reference implementation kept outside
the implementation context. It does not claim a separate human team, legal
review, or exhaustive black-box equivalence testing.

## Reference record

Git blob identifiers below identify the documentation content that was read;
they are not release versions.

| Reference | Identity and purpose |
| --- | --- |
| [ocproxy README](https://github.com/cernekee/ocproxy/blob/master/README.md) | Git blob `31c2250891b7a7441a401c41000fd57e6dd17df1`; use cases, invocation, DNS behavior, configuration names. |
| [ocproxy manual](https://github.com/cernekee/ocproxy/blob/master/ocproxy.1) | Git blob `62f702750b476d91dec5e55cdc10a0e9e90710f1`; documented CLI and override semantics. |
| [OpenConnect manual](https://www.infradead.org/openconnect/manual.html) | Read 2026-11-06; `--script-tun` and `--script` public interface. |
| [OpenConnect non-root operation](https://www.infradead.org/openconnect/nonroot.html) | Read 2026-11-06; userspace proxy operation without host network reconfiguration. |
| [OpenConnect maintainer's packet-interface explanation](https://lists.infradead.org/pipermail/openconnect-devel/2016-January/003404.html) | David Woodhouse, 2016-01-29; the child program exchanges binary IP packets, rather than application TCP streams. |
| [OpenConnect `tun.c`](https://github.com/openconnect/openconnect/blob/ca7bc36520e53561eda2c44186dd2a2e20f69d20/tun.c) | Peer-interface source only; commit `ca7bc36520e53561eda2c44186dd2a2e20f69d20`, blob `f5aafc589bd95f481ed72a7b66565dd69bb9f92a`. |
| [RFC 1928](https://www.rfc-editor.org/rfc/rfc1928.html) | SOCKS5 negotiation, CONNECT requests, address encodings, and replies. |
| [smoltcp 0.14.0](https://docs.rs/smoltcp/0.14.0/smoltcp/) | Dependency API and source review of `socket/dns.rs`, `socket/tcp.rs`, and `iface/interface/mod.rs` for resolver behavior, timer/waker contracts, and TCP lifecycle. The locked crate checksum is `b6f8b28ad56c6e35524a37dd492af5d1a47e31e1a4d175cd12f89c075f01980f`. This is the new implementation's dependency, not ocproxy's bundled stack. |

The pinned OpenConnect source is a historical 2021 GitHub mirror snapshot,
not a claim about the current GitLab development head. The narrow peer-interface
inspection covered `openconnect_setup_tun_script`, `os_read_tun`,
`os_write_tun`, and `os_shutdown_tun`:

1. The peer creates a connected UNIX datagram socket pair and passes one
   descriptor to its child as `VPNFD`.
2. The child command is launched through a shell and inherits that descriptor.
3. Each datagram carries one IP packet. Script mode omits the address-family
   prefix used by some native tunnel devices; there is no Ethernet header.
4. Shutdown sends `SIGHUP` to the child process group.

These observations define interoperability requirements. No peer implementation
source was copied into the Rust implementation. Integration tests with an
independent packet peer can validate the Rust side of this contract; they do not
by themselves establish compatibility with every OpenConnect release or VPN
gateway.

## Future changes

Keep reference-implementation code, patches, and tests out of compatibility
research and implementation prompts. Prefer public manuals, protocol standards,
and independently recorded behavior. If another source is consulted, record its
identity and what contract it establishes here. Describe intentional extensions
and differences in [COMPATIBILITY.md](COMPATIBILITY.md).
