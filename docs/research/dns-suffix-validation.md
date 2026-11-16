# DNS suffix validation (2026-11-16)

At base c5ebe5c81587dc1c5adc3878d951d68464bc6cb5, CLI/environment suffix parsing removed every trailing dot before validation. Thus `corp.test..` and `corp.test...` silently became `corp.test`, although the same names fail `valid_hostname` and direct `NetworkConfig` validation. An invalid suffix must not silently select a different DNS name for unqualified destinations.

The existing smoltcp 0.14.0 DNS implementation is the compatibility reference: `Socket::start_query` removes at most one trailing root dot, then rejects empty labels. Source inspected: https://github.com/smoltcp-rs/smoltcp/blob/v0.14.0/src/socket/dns.rs (BSD-0-Clause; no code copied). Reuse this repository's existing hostname validator instead of adding dependencies.

Validate the original nonempty suffix first, then remove one optional root dot. Preserve empty CLI override of the environment, valid absolute/private names, and CLI precedence. Regression tests cover both CLI and CISCO_DEF_DOMAIN sources. These are offline configuration tests, not live VPN/DNS acceptance.
