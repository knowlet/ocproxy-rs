//! An independent OpenConnect packet-socket proxy built on Tokio and smoltcp.
#![cfg(unix)]
pub mod config;
pub mod server;
pub mod socks;
pub mod stack;
pub mod tunnel;

use std::net::{IpAddr, SocketAddr};

/// A destination supplied by a proxy client; names are resolved only over the VPN.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl Target {
    pub fn port(&self) -> u16 {
        match self {
            Self::Ip(address) => address.port(),
            Self::Domain(_, port) => *port,
        }
    }

    pub fn new(host: &str, port: u16) -> Self {
        match host.parse::<IpAddr>() {
            Ok(address) => Self::Ip(SocketAddr::new(address, port)),
            Err(_) => Self::Domain(host.to_owned(), port),
        }
    }
}
