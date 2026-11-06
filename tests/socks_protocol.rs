//! Protocol tests use RFC 1928 byte sequences and in-memory streams.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use ocproxy_rs::{Target, socks};
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

async fn exchange(input: &[u8]) -> (io::Result<Target>, Vec<u8>, Vec<u8>) {
    let (mut server, mut client) = duplex(2048);
    client.write_all(input).await.unwrap();
    client.shutdown().await.unwrap();
    let result = socks::handshake(&mut server).await;
    let mut remaining = Vec::new();
    server.read_to_end(&mut remaining).await.unwrap();
    drop(server);
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    (result, response, remaining)
}

fn ipv4_request(port: u16) -> Vec<u8> {
    let mut input = vec![5, 1, 0, 5, 1, 0, 1, 192, 0, 2, 7];
    input.extend(port.to_be_bytes());
    input
}

fn domain_request(name: &[u8]) -> Vec<u8> {
    let mut input = vec![5, 1, 0, 5, 1, 0, 3, u8::try_from(name.len()).unwrap()];
    input.extend(name);
    input.extend(443_u16.to_be_bytes());
    input
}

fn failure_reply(code: u8) -> Vec<u8> {
    vec![5, 0, 5, code, 0, 1, 0, 0, 0, 0, 0, 0]
}

#[tokio::test]
async fn parses_ipv4_and_defers_connect_success() {
    let (target, response, remaining) = exchange(&ipv4_request(65535)).await;
    assert_eq!(
        target.unwrap(),
        Target::Ip(SocketAddr::from(([192, 0, 2, 7], 65535)))
    );
    // Only method selection is sent; the VPN connection has not succeeded yet.
    assert_eq!(response, [5, 0]);
    assert!(remaining.is_empty());
}

#[tokio::test]
async fn parses_ipv6_request() {
    let address: Ipv6Addr = "2001:db8::7".parse().unwrap();
    let mut input = vec![5, 1, 0, 5, 1, 0, 4];
    input.extend(address.octets());
    input.extend(8443_u16.to_be_bytes());
    let (target, response, remaining) = exchange(&input).await;
    assert_eq!(
        target.unwrap(),
        Target::Ip(SocketAddr::new(address.into(), 8443))
    );
    assert_eq!(response, [5, 0]);
    assert!(remaining.is_empty());
}

#[tokio::test]
async fn accepts_private_names_absolute_names_and_idna() {
    for name in [
        "intranet",
        "internal_host.example",
        "vpn-service.example.",
        "xn--bcher-kva.example",
        "MiXeD.example",
    ] {
        let (target, response, _) = exchange(&domain_request(name.as_bytes())).await;
        assert_eq!(target.unwrap(), Target::Domain(name.to_owned(), 443));
        assert_eq!(response, [5, 0]);
    }
}

#[tokio::test]
async fn leaves_coalesced_application_bytes_unread() {
    let mut input = ipv4_request(443);
    let payload = b"\x16\x03\x01\x00\x08VPN-DATA";
    input.extend(payload);
    let (target, response, remaining) = exchange(&input).await;
    assert!(target.is_ok());
    assert_eq!(response, [5, 0]);
    assert_eq!(remaining, payload);
}

#[tokio::test]
async fn accepts_byte_at_a_time_handshake_with_backpressure() {
    let (mut server, mut client) = duplex(1);
    let task = tokio::spawn(async move { socks::handshake(&mut server).await });
    let request = domain_request(b"intranet.example");
    for byte in &request[..3] {
        client.write_u8(*byte).await.unwrap();
        tokio::task::yield_now().await;
    }
    let mut selection = [0; 2];
    client.read_exact(&mut selection).await.unwrap();
    assert_eq!(selection, [5, 0]);
    for byte in &request[3..] {
        client.write_u8(*byte).await.unwrap();
        tokio::task::yield_now().await;
    }
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        Target::Domain("intranet.example".to_owned(), 443)
    );
}

#[tokio::test]
async fn chooses_no_auth_even_when_it_is_last_of_255_methods() {
    let mut input = vec![5, 255];
    input.extend([2; 254]);
    input.push(0);
    input.extend(&ipv4_request(80)[3..]);
    let (target, response, _) = exchange(&input).await;
    assert!(target.is_ok());
    assert_eq!(response, [5, 0]);
}

#[tokio::test]
async fn rejects_unsupported_authentication_methods() {
    let (result, response, _) = exchange(&[5, 2, 1, 2]).await;
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(response, [5, 255]);
}

#[tokio::test]
async fn rejects_socks4_and_empty_method_lists() {
    for input in [&[4, 1][..], &[5, 0][..]] {
        let (result, response, _) = exchange(input).await;
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert_eq!(response, [5, 255]);
    }
}

#[tokio::test]
async fn rejects_bind_udp_associate_and_unknown_commands() {
    for command in [2, 3, 0, 255] {
        let mut input = ipv4_request(80);
        input[4] = command;
        let (result, response, _) = exchange(&input).await;
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Unsupported);
        assert_eq!(response, failure_reply(7));
    }
}

#[tokio::test]
async fn rejects_unknown_address_types() {
    for address_type in [0, 2, 5, 255] {
        let (result, response, _) = exchange(&[5, 1, 0, 5, 1, 0, address_type]).await;
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Unsupported);
        assert_eq!(response, failure_reply(8));
    }
}

#[tokio::test]
async fn rejects_invalid_request_version_and_reserved_byte() {
    for (offset, value) in [(3, 4), (5, 1)] {
        let mut input = ipv4_request(80);
        input[offset] = value;
        let (result, response, _) = exchange(&input).await;
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert_eq!(response, failure_reply(1));
    }
}

#[tokio::test]
async fn rejects_zero_destination_port() {
    let (result, response, _) = exchange(&ipv4_request(0)).await;
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    assert_eq!(response, failure_reply(1));
}

#[tokio::test]
async fn rejects_invalid_names_without_interpreting_them_as_other_protocols() {
    for name in [
        b"".to_vec(),
        b".".to_vec(),
        b"a..b".to_vec(),
        b".example".to_vec(),
        b"example..".to_vec(),
        b"-host.example".to_vec(),
        b"host-.example".to_vec(),
        b"example\0.com".to_vec(),
        b"example\n.com".to_vec(),
        b"host name".to_vec(),
        b"https://example.com".to_vec(),
        b"a\\b".to_vec(),
        "bücher.example".as_bytes().to_vec(),
        vec![b'a'; 64],
        [
            vec![b'a'; 63],
            vec![b'b'; 63],
            vec![b'c'; 63],
            vec![b'd'; 63],
        ]
        .join(&b'.'),
    ] {
        let (result, response, _) = exchange(&domain_request(&name)).await;
        assert_eq!(
            result.unwrap_err().kind(),
            io::ErrorKind::InvalidData,
            "{name:?}"
        );
        assert_eq!(response, failure_reply(1), "{name:?}");
    }
}

#[tokio::test]
async fn accepts_maximum_length_dns_name_with_optional_root_dot() {
    let mut name = [
        vec![b'a'; 63],
        vec![b'b'; 63],
        vec![b'c'; 63],
        vec![b'd'; 61],
    ]
    .join(&b'.');
    assert_eq!(name.len(), 253);
    for absolute in [false, true] {
        if absolute {
            name.push(b'.');
        }
        let (target, response, _) = exchange(&domain_request(&name)).await;
        assert_eq!(
            target.unwrap(),
            Target::Domain(String::from_utf8(name.clone()).unwrap(), 443)
        );
        assert_eq!(response, [5, 0]);
    }
}

#[tokio::test]
async fn rejects_eof_at_every_request_boundary() {
    let mut ipv6 = vec![5, 1, 0, 5, 1, 0, 4];
    ipv6.extend(Ipv6Addr::LOCALHOST.octets());
    ipv6.extend(443_u16.to_be_bytes());
    for request in [ipv4_request(443), domain_request(b"intranet"), ipv6] {
        for length in 0..request.len() {
            let (result, response, _) = exchange(&request[..length]).await;
            assert_eq!(
                result.unwrap_err().kind(),
                io::ErrorKind::UnexpectedEof,
                "prefix {length}"
            );
            if length >= 3 {
                assert_eq!(response, failure_reply(1), "prefix {length}");
            } else {
                assert!(response.is_empty(), "prefix {length}");
            }
        }
    }
}

#[tokio::test]
async fn ipv4_success_reply_uses_bound_vpn_endpoint() {
    let (mut server, mut client) = duplex(64);
    socks::reply(&mut server, Ok(SocketAddr::from(([10, 42, 0, 7], 49152))))
        .await
        .unwrap();
    drop(server);
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    assert_eq!(response, [5, 0, 0, 1, 10, 42, 0, 7, 192, 0]);
}

#[tokio::test]
async fn ipv6_success_reply_uses_bound_vpn_endpoint() {
    let (mut server, mut client) = duplex(64);
    let address: Ipv6Addr = "2001:db8::123".parse().unwrap();
    socks::reply(&mut server, Ok(SocketAddr::new(address.into(), 54321)))
        .await
        .unwrap();
    drop(server);
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    let mut expected = vec![5, 0, 0, 4];
    expected.extend(address.octets());
    expected.extend(54321_u16.to_be_bytes());
    assert_eq!(response, expected);
}

#[tokio::test]
async fn maps_network_errors_without_claiming_timeouts_are_ttl_expiry() {
    for (kind, code) in [
        (io::ErrorKind::PermissionDenied, 2),
        (io::ErrorKind::NetworkUnreachable, 3),
        (io::ErrorKind::NetworkDown, 3),
        (io::ErrorKind::HostUnreachable, 4),
        (io::ErrorKind::NotFound, 4),
        (io::ErrorKind::ConnectionRefused, 5),
        (io::ErrorKind::Unsupported, 8),
        (io::ErrorKind::TimedOut, 1),
        (io::ErrorKind::ConnectionReset, 1),
        (io::ErrorKind::Other, 1),
    ] {
        let (mut server, mut client) = duplex(64);
        let error = io::Error::new(kind, "test error");
        socks::reply(&mut server, Err(&error)).await.unwrap();
        drop(server);
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, [5, code, 0, 1, 0, 0, 0, 0, 0, 0]);
    }
}

#[tokio::test]
async fn reply_reports_transport_write_errors() {
    let (mut server, client) = duplex(64);
    drop(client);
    let error = socks::reply(
        &mut server,
        Ok(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 12345)),
    )
    .await
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
}
