//! SOCKS5 CONNECT framing, independently implemented from RFC 1928.
//!
//! Only the no-authentication method and the CONNECT command are supported.
//! This module parses protocol bytes; it does not resolve names or open sockets.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::Target;

const VERSION: u8 = 5;
const NO_AUTH: u8 = 0;
const NO_METHOD: u8 = 0xff;
const GENERAL_FAILURE: u8 = 1;
const COMMAND_UNSUPPORTED: u8 = 7;
const ADDRESS_UNSUPPORTED: u8 = 8;

/// Negotiate no authentication and read one SOCKS5 CONNECT request.
///
/// On success, the caller must establish the requested connection and then call
/// [`reply`]. No CONNECT success reply is sent here. Exact reads leave any
/// application data pipelined after the request available to the caller.
///
/// On a protocol error, a rejection is sent when the protocol phase permits it.
/// The caller must close the stream after an error and apply a handshake timeout
/// around this function, including its writes. Names are ASCII DNS names; clients
/// must encode international names as IDNA A-labels. Underscores, single labels,
/// and a trailing root dot are accepted for private VPN naming schemes.
pub async fn handshake<S>(stream: &mut S) -> io::Result<Target>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut greeting = [0; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting[0] != VERSION || greeting[1] == 0 {
        stream.write_all(&[VERSION, NO_METHOD]).await?;
        stream.flush().await?;
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected a SOCKS5 greeting with at least one authentication method",
        ));
    }

    // The one-byte count bounds both memory use and the amount read.
    let mut methods = [0; 255];
    let methods = &mut methods[..usize::from(greeting[1])];
    stream.read_exact(methods).await?;
    if !methods.contains(&NO_AUTH) {
        stream.write_all(&[VERSION, NO_METHOD]).await?;
        stream.flush().await?;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "client did not offer SOCKS5 no authentication",
        ));
    }

    stream.write_all(&[VERSION, NO_AUTH]).await?;
    stream.flush().await?;

    match read_request(stream).await {
        Ok(target) => Ok(target),
        Err(failure) => {
            // The original protocol/read error is more useful than a secondary
            // write error if the client has already disconnected.
            let _ = write_reply(stream, failure.code, unspecified()).await;
            Err(failure.error)
        }
    }
}

/// Send the result of establishing a VPN connection.
///
/// A successful reply advertises the VPN-side TCP socket's bound address and
/// port. An error reply uses an all-zero IPv4 bound endpoint; the caller must
/// then close the client stream. A TCP timeout is reported as general failure,
/// not as TTL expiry, which is a different condition in RFC 1928.
pub async fn reply<S>(stream: &mut S, result: Result<SocketAddr, &io::Error>) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    match result {
        Ok(bound) => write_reply(stream, 0, bound).await,
        Err(error) => write_reply(stream, error_reply_code(error), unspecified()).await,
    }
}

struct RequestFailure {
    code: u8,
    error: io::Error,
}

impl RequestFailure {
    fn invalid(message: &'static str) -> Self {
        Self {
            code: GENERAL_FAILURE,
            error: io::Error::new(io::ErrorKind::InvalidData, message),
        }
    }

    fn unsupported(code: u8, message: &'static str) -> Self {
        Self {
            code,
            error: io::Error::new(io::ErrorKind::Unsupported, message),
        }
    }
}

impl From<io::Error> for RequestFailure {
    fn from(error: io::Error) -> Self {
        Self {
            code: GENERAL_FAILURE,
            error,
        }
    }
}

async fn read_request<S>(stream: &mut S) -> Result<Target, RequestFailure>
where
    S: AsyncRead + Unpin,
{
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    if header[0] != VERSION || header[2] != 0 {
        return Err(RequestFailure::invalid(
            "invalid SOCKS5 request version or reserved byte",
        ));
    }
    if header[1] != 1 {
        return Err(RequestFailure::unsupported(
            COMMAND_UNSUPPORTED,
            "only SOCKS5 CONNECT is supported",
        ));
    }

    enum Host {
        Ip(IpAddr),
        Domain(String),
    }

    let host = match header[3] {
        1 => {
            let mut octets = [0; 4];
            stream.read_exact(&mut octets).await?;
            Host::Ip(Ipv4Addr::from(octets).into())
        }
        3 => {
            let length = usize::from(stream.read_u8().await?);
            let mut name = [0; 255];
            let name = &mut name[..length];
            stream.read_exact(name).await?;
            let name = std::str::from_utf8(name)
                .map_err(|_| RequestFailure::invalid("invalid SOCKS5 DNS name"))?;
            if !crate::config::valid_hostname(name) {
                return Err(RequestFailure::invalid("invalid SOCKS5 DNS name"));
            }
            Host::Domain(name.to_owned())
        }
        4 => {
            let mut octets = [0; 16];
            stream.read_exact(&mut octets).await?;
            Host::Ip(Ipv6Addr::from(octets).into())
        }
        _ => {
            return Err(RequestFailure::unsupported(
                ADDRESS_UNSUPPORTED,
                "unsupported SOCKS5 address type",
            ));
        }
    };

    let port = stream.read_u16().await?;
    if port == 0 {
        return Err(RequestFailure::invalid(
            "SOCKS5 CONNECT requires a nonzero destination port",
        ));
    }
    Ok(match host {
        Host::Ip(address) => Target::Ip(SocketAddr::new(address, port)),
        Host::Domain(name) => Target::Domain(name, port),
    })
}

fn unspecified() -> SocketAddr {
    SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0)
}

fn error_reply_code(error: &io::Error) -> u8 {
    match error.kind() {
        io::ErrorKind::PermissionDenied => 2,
        io::ErrorKind::NetworkUnreachable | io::ErrorKind::NetworkDown => 3,
        io::ErrorKind::HostUnreachable | io::ErrorKind::NotFound => 4,
        io::ErrorKind::ConnectionRefused => 5,
        io::ErrorKind::Unsupported => ADDRESS_UNSUPPORTED,
        _ => GENERAL_FAILURE,
    }
}

async fn write_reply<S>(stream: &mut S, code: u8, bound: SocketAddr) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let mut response = [0; 22];
    response[0] = VERSION;
    response[1] = code;
    let length = match bound {
        SocketAddr::V4(address) => {
            response[3] = 1;
            response[4..8].copy_from_slice(&address.ip().octets());
            response[8..10].copy_from_slice(&address.port().to_be_bytes());
            10
        }
        SocketAddr::V6(address) => {
            response[3] = 4;
            response[4..20].copy_from_slice(&address.ip().octets());
            response[20..22].copy_from_slice(&address.port().to_be_bytes());
            22
        }
    };
    stream.write_all(&response[..length]).await?;
    stream.flush().await
}
