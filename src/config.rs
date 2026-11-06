//! CLI parsing is independent of process environment to make configuration testable.
use crate::Target;
use anyhow::{Context, Result, bail, ensure};
use clap::Parser;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

#[derive(Debug, Parser)]
#[command(
    version,
    about = "SOCKS5 and TCP forwarding through OpenConnect without a TUN interface",
    after_help = "Example: openconnect --script-tun --script 'ocproxy-rs -D 1080 -L 2222:host:22' vpn.example.com\nNames resolve through VPN DNS only. Listeners default to loopback; no authentication is provided."
)]
pub struct Cli {
    /// SOCKS5 CONNECT listener: [IP:]PORT; use [IPv6]:PORT for IPv6
    #[arg(short = 'D', long = "dynfw", value_name = "[IP:]PORT")]
    pub dynamic: Vec<String>,
    /// TCP forward: [BIND_IP:]PORT:HOST:DEST_PORT (bracket IPv6 literals)
    #[arg(short = 'L', long = "localfw", value_name = "PORT:HOST:DEST_PORT")]
    pub local: Vec<String>,
    /// Bind unspecified listeners to 0.0.0.0; allows other hosts to use the VPN
    #[arg(short = 'g', long = "allow-remote")]
    pub allow_remote: bool,
    /// VPN-side TCP keepalive interval, seconds (0 disables)
    #[arg(short = 'k', long = "keepalive", default_value_t = 0)]
    pub keepalive: u64,
    /// VPN IPv4 address; overrides INTERNAL_IP4_ADDRESS
    #[arg(short = 'I', long = "ip")]
    pub ipv4: Option<Ipv4Addr>,
    /// VPN IPv6 address; overrides INTERNAL_IP6_ADDRESS
    #[arg(long = "ipv6")]
    pub ipv6: Option<Ipv6Addr>,
    /// Raw IP MTU; overrides INTERNAL_IP4_MTU (default 1400)
    #[arg(short = 'M', long = "mtu")]
    pub mtu: Option<usize>,
    /// VPN DNS server; repeat to override all supplied DNS servers
    #[arg(short = 'd', long = "dns")]
    pub dns: Vec<IpAddr>,
    /// Suffix for unqualified hostnames; overrides CISCO_DEF_DOMAIN
    #[arg(short = 'o', long = "domain")]
    pub domain: Option<String>,
    /// Inherited connected UNIX datagram descriptor; overrides VPNFD
    #[arg(long = "vpn-fd")]
    pub vpn_fd: Option<i32>,
    /// DNS and VPN TCP connection deadline in seconds
    #[arg(long, default_value_t = 30)]
    pub connect_timeout: u64,
    /// VPN TCP transport stall timeout in seconds (not an ordinary idle timeout)
    #[arg(long, default_value_t = 300)]
    pub tcp_timeout: u64,
    /// SOCKS greeting and request deadline in seconds
    #[arg(long, default_value_t = 10)]
    pub handshake_timeout: u64,
    /// Maximum simultaneously accepted clients across all listeners
    #[arg(long, default_value_t = 256)]
    pub max_connections: usize,
    /// Per-direction TCP buffer size in bytes
    #[arg(long, default_value_t = 65536)]
    pub buffer_size: usize,
    /// Enable debug logging (never logs packet payloads)
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    pub verbose: u8,
}

#[derive(Clone, Debug)]
pub struct NetworkConfig {
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
    pub mtu: usize,
    pub dns_servers: Vec<IpAddr>,
    pub domain: Option<String>,
    pub connect_timeout: Duration,
    pub tcp_timeout: Duration,
    pub keepalive: Option<Duration>,
    pub max_connections: usize,
    pub buffer_size: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ListenerKind {
    Socks,
    Forward(Target),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListenerSpec {
    pub bind: SocketAddr,
    pub kind: ListenerKind,
}

#[derive(Debug)]
pub struct Config {
    pub vpn_fd: i32,
    pub network: NetworkConfig,
    pub listeners: Vec<ListenerSpec>,
    pub handshake_timeout: Duration,
}

impl Cli {
    pub fn config(&self) -> Result<Config> {
        self.config_with_env(|key| std::env::var(key).ok())
    }

    pub fn config_with_env(&self, env: impl Fn(&str) -> Option<String>) -> Result<Config> {
        let vpn_fd = match self.vpn_fd {
            Some(fd) => Some(fd),
            None => env("VPNFD")
                .map(|s| s.parse().context("VPNFD must be an integer"))
                .transpose()?,
        }
        .context(
            "VPNFD is missing; launch with openconnect --script-tun --script 'ocproxy-rs ...'",
        )?;
        ensure!(vpn_fd >= 3, "VPNFD must be a descriptor >= 3");
        let ipv4 = match self.ipv4 {
            Some(ip) => Some(ip),
            None => env("INTERNAL_IP4_ADDRESS")
                .filter(|s| !s.is_empty())
                .map(|s| {
                    s.parse::<Ipv4Addr>()
                        .context("invalid INTERNAL_IP4_ADDRESS")
                })
                .transpose()?,
        };
        let ipv6 = match self.ipv6 {
            Some(ip) => Some(ip),
            None => env("INTERNAL_IP6_ADDRESS")
                .filter(|s| !s.is_empty())
                .map(|s| parse_ipv6_address(&s))
                .transpose()?,
        };
        ensure!(
            ipv4.is_some() || ipv6.is_some(),
            "a VPN IPv4 or IPv6 address is required (INTERNAL_IP4_ADDRESS / INTERNAL_IP6_ADDRESS or -I / --ipv6)"
        );
        if let Some(ip) = ipv4 {
            ensure!(
                !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast(),
                "VPN IPv4 address must be unicast"
            );
        }
        if let Some(ip) = ipv6 {
            ensure!(
                !ip.is_unspecified() && !ip.is_multicast(),
                "VPN IPv6 address must be unicast"
            );
        }
        let mtu = match self.mtu {
            Some(mtu) => mtu,
            None => env("INTERNAL_IP4_MTU")
                .filter(|s| !s.is_empty())
                .map(|s| s.parse::<usize>().context("invalid INTERNAL_IP4_MTU"))
                .transpose()?
                .unwrap_or(1400),
        };
        ensure!(
            (576..=65535).contains(&mtu),
            "MTU must be between 576 and 65535"
        );
        ensure!(
            ipv6.is_none() || mtu >= 1280,
            "IPv6 requires an MTU of at least 1280"
        );
        let dns_servers = if self.dns.is_empty() {
            let mut servers = Vec::new();
            for key in ["INTERNAL_IP4_DNS", "INTERNAL_IP6_DNS"] {
                if let Some(value) = env(key) {
                    for part in value.split_whitespace() {
                        let ip = part
                            .parse::<IpAddr>()
                            .with_context(|| format!("invalid {key} address: {part}"))?;
                        if !servers.contains(&ip) {
                            servers.push(ip);
                        }
                    }
                }
            }
            servers
        } else {
            self.dns.clone()
        };
        ensure!(
            dns_servers.len() <= 8,
            "at most 8 VPN DNS servers are supported"
        );
        for server in &dns_servers {
            ensure!(
                !server.is_unspecified() && !server.is_multicast(),
                "VPN DNS address must be unicast"
            );
            ensure!(
                match server {
                    IpAddr::V4(_) => ipv4.is_some(),
                    IpAddr::V6(_) => ipv6.is_some(),
                },
                "DNS server {server} requires a VPN address of the same family"
            );
        }
        let domain = self
            .domain
            .clone()
            .or_else(|| env("CISCO_DEF_DOMAIN"))
            .filter(|s| !s.is_empty())
            .map(|s| s.trim_end_matches('.').to_owned());
        if let Some(domain) = &domain {
            ensure!(valid_hostname(domain), "invalid DNS domain suffix");
        }
        ensure!(
            (1..=3600).contains(&self.connect_timeout),
            "connect timeout must be 1..=3600 seconds"
        );
        ensure!(
            (1..=86400).contains(&self.tcp_timeout),
            "TCP timeout must be 1..=86400 seconds"
        );
        ensure!(
            (1..=3600).contains(&self.handshake_timeout),
            "handshake timeout must be 1..=3600 seconds"
        );
        ensure!(
            self.keepalive <= 86400,
            "keepalive must be 0..=86400 seconds"
        );
        ensure!(
            self.keepalive == 0 || self.tcp_timeout > self.keepalive,
            "tcp-timeout must exceed the keepalive interval"
        );
        ensure!(
            (1..=4096).contains(&self.max_connections),
            "max-connections must be 1..=4096"
        );
        ensure!(
            (4096..=1048576).contains(&self.buffer_size),
            "buffer-size must be 4096..=1048576 bytes"
        );
        // Four queues (TCP RX/TX and the two duplex halves) are allocated per flow.
        ensure!(
            self.buffer_size
                .saturating_mul(self.max_connections)
                .saturating_mul(4)
                <= 1024 * 1024 * 1024,
            "configured connection buffers exceed the 1 GiB budget"
        );
        let default = if self.allow_remote {
            Ipv4Addr::UNSPECIFIED
        } else {
            Ipv4Addr::LOCALHOST
        };
        let mut listeners = Vec::new();
        for raw in &self.dynamic {
            listeners.push(ListenerSpec {
                bind: parse_bind(raw, default)?,
                kind: ListenerKind::Socks,
            });
        }
        for raw in &self.local {
            listeners.push(parse_forward(raw, default)?);
        }
        ensure!(
            !listeners.is_empty(),
            "configure at least one -D SOCKS listener or -L TCP forward"
        );
        ensure!(listeners.len() <= 64, "at most 64 listeners are supported");
        Ok(Config {
            vpn_fd,
            network: NetworkConfig {
                ipv4,
                ipv6,
                mtu,
                dns_servers,
                domain,
                connect_timeout: Duration::from_secs(self.connect_timeout),
                tcp_timeout: Duration::from_secs(self.tcp_timeout),
                keepalive: (self.keepalive != 0).then(|| Duration::from_secs(self.keepalive)),
                max_connections: self.max_connections,
                buffer_size: self.buffer_size,
            },
            listeners,
            handshake_timeout: Duration::from_secs(self.handshake_timeout),
        })
    }
}

fn parse_ipv6_address(value: &str) -> Result<Ipv6Addr> {
    let address = match value.split_once('/') {
        Some((address, prefix)) => {
            let prefix = prefix
                .parse::<u8>()
                .context("invalid INTERNAL_IP6_ADDRESS prefix")?;
            ensure!(prefix <= 128, "invalid INTERNAL_IP6_ADDRESS prefix");
            address
        }
        None => value,
    };
    address.parse().context("invalid INTERNAL_IP6_ADDRESS")
}

pub fn valid_hostname(name: &str) -> bool {
    let name = name.strip_suffix('.').unwrap_or(name);
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

fn port(value: &str) -> Result<u16> {
    let port: u16 = value
        .parse()
        .context("port must be an integer from 1 to 65535")?;
    ensure!(port != 0, "port 0 is not supported");
    Ok(port)
}

fn parse_bind(raw: &str, default: Ipv4Addr) -> Result<SocketAddr> {
    if !raw.contains(':') {
        return Ok(SocketAddr::new(default.into(), port(raw)?));
    }
    let addr: SocketAddr = raw
        .parse()
        .context("listener must be PORT, IPv4:PORT, or [IPv6]:PORT")?;
    ensure!(addr.port() != 0, "port 0 is not supported");
    ensure!(
        !addr.ip().is_multicast(),
        "listener address cannot be multicast"
    );
    Ok(addr)
}

// A small bracket-aware tokenizer keeps IPv6 delimiters out of the CLI field grammar.
fn fields(raw: &str) -> Result<Vec<String>> {
    let mut fields = Vec::new();
    let mut part = String::new();
    let mut bracket = false;
    let mut closed = false;
    for c in raw.chars() {
        match c {
            '[' if part.is_empty() && !bracket && !closed => bracket = true,
            ']' if bracket => {
                bracket = false;
                closed = true;
            }
            ':' if !bracket => {
                fields.push(std::mem::take(&mut part));
                closed = false;
            }
            '[' | ']' => bail!("invalid brackets in forward: {raw}"),
            _ if closed => bail!("unexpected character after ] in forward: {raw}"),
            _ => part.push(c),
        }
    }
    ensure!(!bracket, "unclosed IPv6 bracket in forward: {raw}");
    fields.push(part);
    Ok(fields)
}

fn parse_forward(raw: &str, default: Ipv4Addr) -> Result<ListenerSpec> {
    let parts = fields(raw)?;
    let (bind, listen, host, dest) = match parts.as_slice() {
        [listen, host, dest] => (IpAddr::V4(default), listen, host, dest),
        [bind, listen, host, dest] => (
            bind.parse::<IpAddr>()
                .context("forward bind address must be an IP literal")?,
            listen,
            host,
            dest,
        ),
        _ => bail!("forward must be [BIND_IP:]PORT:HOST:DEST_PORT; bracket IPv6 literals"),
    };
    ensure!(!bind.is_multicast(), "listener address cannot be multicast");
    ensure!(
        host.parse::<IpAddr>().is_ok() || valid_hostname(host),
        "invalid forward destination"
    );
    Ok(ListenerSpec {
        bind: SocketAddr::new(bind, port(listen)?),
        kind: ListenerKind::Forward(Target::new(host, port(dest)?)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config(args: &[&str], values: &[(&str, &str)]) -> Result<Config> {
        Cli::try_parse_from(std::iter::once("ocproxy-rs").chain(args.iter().copied()))?
            .config_with_env(|key| {
                values
                    .iter()
                    .find(|(k, _)| *k == key)
                    .map(|(_, v)| (*v).to_owned())
            })
    }
    const ENV: &[(&str, &str)] = &[("VPNFD", "7"), ("INTERNAL_IP4_ADDRESS", "10.20.30.40")];
    #[test]
    fn defaults_are_local_and_dns_stays_explicit() {
        let cfg = config(&["-D", "1080"], ENV).unwrap();
        assert_eq!(cfg.listeners[0].bind.to_string(), "127.0.0.1:1080");
        assert_eq!(cfg.network.mtu, 1400);
        assert!(cfg.network.dns_servers.is_empty());
    }
    #[test]
    fn explicit_bind_overrides_remote_default() {
        let cfg = config(&["-g", "-D", "127.0.0.2:1080", "-L", "2222:server:22"], ENV).unwrap();
        assert_eq!(cfg.listeners[0].bind.to_string(), "127.0.0.2:1080");
        assert_eq!(cfg.listeners[1].bind.to_string(), "0.0.0.0:2222");
    }
    #[test]
    fn forward_supports_bracketed_ipv6() {
        let cfg = config(&["-L", "[::1]:8080:[2001:db8::5]:443"], ENV).unwrap();
        assert_eq!(cfg.listeners[0].bind.to_string(), "[::1]:8080");
        assert_eq!(
            cfg.listeners[0].kind,
            ListenerKind::Forward(Target::Ip("[2001:db8::5]:443".parse().unwrap()))
        );
    }
    #[test]
    fn flags_override_supplied_environment() {
        let env = [
            ("VPNFD", "7"),
            ("INTERNAL_IP4_ADDRESS", "bad"),
            ("INTERNAL_IP4_MTU", "bad"),
            ("INTERNAL_IP4_DNS", "bad"),
            ("CISCO_DEF_DOMAIN", "bad..name"),
        ];
        let cfg = config(
            &[
                "-D",
                "1080",
                "-I",
                "10.1.0.1",
                "-M",
                "1500",
                "-d",
                "10.1.0.53",
                "-o",
                "corp.test",
            ],
            &env,
        )
        .unwrap();
        assert_eq!(cfg.network.domain.as_deref(), Some("corp.test"));
        assert_eq!(
            cfg.network.dns_servers,
            vec!["10.1.0.53".parse::<IpAddr>().unwrap()]
        );
    }
    #[test]
    fn rejects_bad_configuration_without_io() {
        for args in [
            vec![],
            vec!["-D", "0"],
            vec!["-D", "1080", "--vpn-fd", "1"],
            vec!["-D", "1080", "-M", "1"],
            vec!["-L", "8080::443"],
            vec!["-L", "8080:[::1:443"],
            vec!["-D", "1080", "--max-connections", "0"],
            vec!["-D", "1080", "--connect-timeout", "0"],
            vec!["-D", "1080", "--buffer-size", "1"],
            vec![
                "-D",
                "1080",
                "--max-connections",
                "4096",
                "--buffer-size",
                "1048576",
            ],
        ] {
            assert!(config(&args, ENV).is_err(), "accepted {args:?}");
        }
    }
    #[test]
    fn explicit_descriptor_ignores_bad_environment_value() {
        let cfg = config(
            &["-D", "1080", "--vpn-fd", "8"],
            &[
                ("VPNFD", "not-a-number"),
                ("INTERNAL_IP4_ADDRESS", "10.0.0.2"),
            ],
        )
        .unwrap();
        assert_eq!(cfg.vpn_fd, 8);
    }
    #[test]
    fn validates_ipv6_prefix_and_keepalive_relationship() {
        for address in ["fd00::1/129", "fd00::1/nope", "fd00::1/64/3"] {
            assert!(
                config(
                    &["-D", "1080"],
                    &[("VPNFD", "8"), ("INTERNAL_IP6_ADDRESS", address)]
                )
                .is_err()
            );
        }
        assert!(config(&["-D", "1080", "-k", "300", "--tcp-timeout", "300"], ENV).is_err());
        assert!(config(&["-D", "1080", "-k", "20", "--tcp-timeout", "60"], ENV).is_ok());
    }
    #[test]
    fn accepts_ipv6_only_configuration() {
        let cfg = config(
            &["-D", "1080"],
            &[
                ("VPNFD", "8"),
                ("INTERNAL_IP6_ADDRESS", "fd00::2/64"),
                ("INTERNAL_IP6_DNS", "fd00::53"),
            ],
        )
        .unwrap();
        assert!(cfg.network.ipv4.is_none());
        assert_eq!(cfg.network.ipv6, Some("fd00::2".parse().unwrap()));
    }
    #[test]
    fn hostname_validation_preserves_internal_names() {
        for host in [
            "server",
            "server.corp.test.",
            "my_host.corp",
            "xn--bcher-kva.example",
        ] {
            assert!(valid_hostname(host));
        }
        for host in ["", ".", "a..b", "-bad", "bad-", "a/b", "a\0b", "☃.example"] {
            assert!(!valid_hostname(host));
        }
    }
}
