//! Packet-level tests use a scripted RFC-style peer, not a second smoltcp stack.
use ocproxy_rs::{Target, config::NetworkConfig, stack};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixDatagram,
    task::JoinHandle,
    time::timeout,
};

fn configuration() -> NetworkConfig {
    NetworkConfig {
        ipv4: Some(Ipv4Addr::new(10, 20, 0, 2)),
        ipv6: None,
        mtu: 1400,
        dns_servers: vec![],
        domain: None,
        connect_timeout: Duration::from_secs(4),
        tcp_timeout: Duration::from_secs(30),
        keepalive: None,
        max_connections: 4,
        buffer_size: 4096,
    }
}

fn launch(config: NetworkConfig) -> (stack::Network, UnixDatagram, JoinHandle<io::Result<()>>) {
    let (vpn, peer) = UnixDatagram::pair().unwrap();
    let (network, driver) = stack::new(vpn, config).unwrap();
    (network, peer, tokio::spawn(driver.run()))
}

async fn receive(peer: &UnixDatagram) -> Vec<u8> {
    let mut packet = vec![0; 65536];
    let count = timeout(Duration::from_secs(5), peer.recv(&mut packet))
        .await
        .unwrap()
        .unwrap();
    packet.truncate(count);
    packet
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = bytes
        .chunks(2)
        .map(|word| u16::from_be_bytes([word[0], *word.get(1).unwrap_or(&0)]) as u32)
        .sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn address_bytes(address: IpAddr) -> Vec<u8> {
    match address {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    }
}

fn transport_packet(
    source: IpAddr,
    dest: IpAddr,
    protocol: u8,
    mut payload: Vec<u8>,
    checksum_offset: usize,
) -> Vec<u8> {
    let mut pseudo = address_bytes(source);
    pseudo.extend(address_bytes(dest));
    if source.is_ipv4() {
        pseudo.extend([0, protocol]);
        pseudo.extend((payload.len() as u16).to_be_bytes());
    } else {
        pseudo.extend((payload.len() as u32).to_be_bytes());
        pseudo.extend([0, 0, 0, protocol]);
    }
    pseudo.extend(&payload);
    let sum = checksum(&pseudo);
    payload[checksum_offset..checksum_offset + 2].copy_from_slice(&sum.to_be_bytes());
    let mut packet = if source.is_ipv4() {
        let mut ip = vec![0; 20];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&((payload.len() + 20) as u16).to_be_bytes());
        ip[6] = 0x40;
        ip[8] = 64;
        ip[9] = protocol;
        ip[12..16].copy_from_slice(&address_bytes(source));
        ip[16..20].copy_from_slice(&address_bytes(dest));
        let sum = checksum(&ip);
        ip[10..12].copy_from_slice(&sum.to_be_bytes());
        ip
    } else {
        let mut ip = vec![0; 40];
        ip[0] = 0x60;
        ip[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        ip[6] = protocol;
        ip[7] = 64;
        ip[8..24].copy_from_slice(&address_bytes(source));
        ip[24..40].copy_from_slice(&address_bytes(dest));
        ip
    };
    packet.extend(payload);
    packet
}

fn tcp(
    source: SocketAddr,
    dest: SocketAddr,
    seq: u32,
    ack: u32,
    flags: u8,
    bytes: &[u8],
) -> Vec<u8> {
    let mut payload = vec![0; 20];
    payload[..2].copy_from_slice(&source.port().to_be_bytes());
    payload[2..4].copy_from_slice(&dest.port().to_be_bytes());
    payload[4..8].copy_from_slice(&seq.to_be_bytes());
    payload[8..12].copy_from_slice(&ack.to_be_bytes());
    payload[12] = 0x50;
    payload[13] = flags;
    payload[14..16].copy_from_slice(&32768u16.to_be_bytes());
    payload.extend(bytes);
    transport_packet(source.ip(), dest.ip(), 6, payload, 16)
}

fn udp(source: SocketAddr, dest: SocketAddr, bytes: &[u8]) -> Vec<u8> {
    let mut payload = vec![0; 8];
    payload[..2].copy_from_slice(&source.port().to_be_bytes());
    payload[2..4].copy_from_slice(&dest.port().to_be_bytes());
    payload[4..6].copy_from_slice(&((bytes.len() + 8) as u16).to_be_bytes());
    payload.extend(bytes);
    transport_packet(source.ip(), dest.ip(), 17, payload, 6)
}

fn endpoints(packet: &[u8]) -> (SocketAddr, SocketAddr, &[u8]) {
    let (source, dest, offset) = if packet[0] >> 4 == 4 {
        assert_eq!(checksum(&packet[..20]), 0, "bad emitted IPv4 checksum");
        (
            IpAddr::V4(Ipv4Addr::from(
                <[u8; 4]>::try_from(&packet[12..16]).unwrap(),
            )),
            IpAddr::V4(Ipv4Addr::from(
                <[u8; 4]>::try_from(&packet[16..20]).unwrap(),
            )),
            20,
        )
    } else {
        (
            IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&packet[8..24]).unwrap(),
            )),
            IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(&packet[24..40]).unwrap(),
            )),
            40,
        )
    };
    let payload = &packet[offset..];
    (
        SocketAddr::new(source, u16::from_be_bytes(payload[..2].try_into().unwrap())),
        SocketAddr::new(dest, u16::from_be_bytes(payload[2..4].try_into().unwrap())),
        payload,
    )
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

#[tokio::test]
async fn no_dns_or_unconfigured_family_never_falls_back_to_host_network() {
    let (network, peer, driver) = launch(configuration());
    let error = network
        .connect(Target::Domain("example.com".into(), 443))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::NotFound);
    let error = network
        .connect(Target::Ip("[2001:db8::1]:443".parse().unwrap()))
        .await
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    let mut packet = [0; 1500];
    assert!(
        timeout(Duration::from_millis(30), peer.recv(&mut packet))
            .await
            .is_err()
    );
    driver.abort();
}

#[tokio::test]
async fn cancelled_connect_releases_limit_and_source_port() {
    let mut config = configuration();
    config.max_connections = 1;
    let (network, peer, driver) = launch(config);
    let remote: SocketAddr = "10.20.0.42:8080".parse().unwrap();
    let connecting = tokio::spawn({
        let network = network.clone();
        async move { network.connect(Target::Ip(remote)).await }
    });
    let first = receive(&peer).await;
    assert_eq!(endpoints(&first).2[13] & 2, 2);
    let error = network.connect(Target::Ip(remote)).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    connecting.abort();
    let _ = connecting.await;
    let reset = receive(&peer).await;
    assert_eq!(
        endpoints(&reset).2[13] & 4,
        4,
        "cancel must notify VPN peer"
    );
    let next = tokio::spawn({
        let network = network.clone();
        async move { network.connect(Target::Ip(remote)).await }
    });
    let syn = receive(&peer).await;
    let (local, remote, segment) = endpoints(&syn);
    assert_eq!(segment[13] & 2, 2, "slot was not reclaimed");
    peer.send(&tcp(
        remote,
        local,
        0,
        u32_at(segment, 4).wrapping_add(1),
        0x14,
        &[],
    ))
    .await
    .unwrap();
    assert_eq!(
        next.await.unwrap().unwrap_err().kind(),
        io::ErrorKind::ConnectionRefused
    );
    driver.abort();
}

#[tokio::test]
async fn silent_peer_obeys_connect_deadline() {
    let mut config = configuration();
    config.connect_timeout = Duration::from_millis(100);
    let (network, _peer, driver) = launch(config);
    let result = timeout(
        Duration::from_secs(1),
        network.connect(Target::Ip("10.20.0.42:443".parse().unwrap())),
    )
    .await
    .unwrap();
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert!(
        !driver.is_finished(),
        "a single timeout must not terminate the driver"
    );
    driver.abort();
}

#[tokio::test]
async fn packet_socket_failure_terminates_driver_and_pending_connect() {
    let (network, peer, driver) = launch(configuration());
    drop(peer);
    let result = timeout(
        Duration::from_secs(1),
        network.connect(Target::Ip("10.20.0.42:443".parse().unwrap())),
    )
    .await
    .unwrap();
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::BrokenPipe);
    assert!(driver.await.unwrap().is_err());
}

#[tokio::test]
async fn ipv6_retransmits_lost_syn_and_drains_response_after_half_close() {
    let mut config = configuration();
    config.ipv4 = None;
    config.ipv6 = Some("fd00::2".parse().unwrap());
    let (network, peer, driver) = launch(config);
    let server = tokio::spawn(async move {
        // Intentionally lose the first SYN; the peer has no TCP library.
        let lost = receive(&peer).await;
        let syn = receive(&peer).await;
        let (local, remote, segment) = endpoints(&syn);
        assert_eq!(syn[0] >> 4, 6);
        assert_eq!(
            u32_at(endpoints(&lost).2, 4),
            u32_at(segment, 4),
            "SYN retry changed sequence"
        );
        let mut next = u32_at(segment, 4).wrapping_add(1);
        let server_seq: u32 = 0x10203040;
        peer.send(&tcp(remote, local, server_seq, next, 0x12, &[]))
            .await
            .unwrap();
        let mut request = Vec::<u8>::new();
        loop {
            let packet = receive(&peer).await;
            let (_, _, segment) = endpoints(&packet);
            let sequence = u32_at(segment, 4);
            let data = &segment[usize::from(segment[12] >> 4) * 4..];
            if sequence == next {
                request.extend(data);
                next = next.wrapping_add(data.len() as u32);
                if segment[13] & 1 != 0 {
                    next = next.wrapping_add(1);
                    break;
                }
            }
            peer.send(&tcp(remote, local, server_seq + 1, next, 0x10, &[]))
                .await
                .unwrap();
        }
        assert_eq!(request, b"ipv6 request");
        let reply = tcp(
            remote,
            local,
            server_seq + 1,
            next,
            0x19,
            b"response after request FIN",
        );
        peer.send(&reply).await.unwrap();
        // Keep the packet socket alive until the reply and FIN are ACKed.
        loop {
            let ack = receive(&peer).await;
            let segment = endpoints(&ack).2;
            if u32_at(segment, 8) == server_seq + 1 + b"response after request FIN".len() as u32 + 1
            {
                break;
            }
        }
    });
    let mut connection = network
        .connect(Target::Ip("[fd00::42]:443".parse().unwrap()))
        .await
        .unwrap();
    assert_eq!(
        connection.local_addr.ip(),
        "fd00::2".parse::<IpAddr>().unwrap()
    );
    connection.stream.write_all(b"ipv6 request").await.unwrap();
    connection.stream.shutdown().await.unwrap();
    let mut response = Vec::new();
    timeout(
        Duration::from_secs(2),
        connection.stream.read_to_end(&mut response),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(response, b"response after request FIN");
    server.await.unwrap();
    driver.abort();
}

#[tokio::test]
async fn ipv6_dns_checks_vpn_server_source_before_connecting() {
    let mut config = configuration();
    config.ipv4 = None;
    config.ipv6 = Some("fd00::2".parse().unwrap());
    config.dns_servers = vec!["fd00::53".parse().unwrap()];
    config.domain = Some("corp.test".into());
    let (network, peer, driver) = launch(config);
    let connecting =
        tokio::spawn(async move { network.connect(Target::Domain("service".into(), 443)).await });
    let query_packet = receive(&peer).await;
    assert_eq!(query_packet[6], 17);
    let (client, server, datagram) = endpoints(&query_packet);
    assert_eq!(server.to_string(), "[fd00::53]:53");
    let query = &datagram[8..];
    assert_eq!(&query[12..], b"\x07service\x04corp\x04test\0\0\x1c\0\x01");
    let mut answer = query.to_vec();
    answer[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
    answer[6..8].copy_from_slice(&1u16.to_be_bytes());
    answer.extend(b"\xc0\x0c\0\x1c\0\x01\0\0\0\x1e\0\x10");
    answer.extend("fd00::42".parse::<Ipv6Addr>().unwrap().octets());
    let wrong_server: SocketAddr = "[fd00::99]:53".parse().unwrap();
    peer.send(&udp(wrong_server, client, &answer))
        .await
        .unwrap();
    let mut packet = [0; 1500];
    let guard = async {
        loop {
            let size = peer.recv(&mut packet).await.unwrap();
            assert_ne!(packet[6], 6, "accepted an answer from the wrong DNS server");
            assert!(size >= 40);
            // An ICMPv6 port-unreachable response to the unsolicited UDP is valid.
        }
    };
    assert!(timeout(Duration::from_millis(30), guard).await.is_err());
    peer.send(&udp(server, client, &answer)).await.unwrap();
    let syn = receive(&peer).await;
    let (local, remote, segment) = endpoints(&syn);
    assert_eq!(remote.to_string(), "[fd00::42]:443");
    peer.send(&tcp(
        remote,
        local,
        0,
        u32_at(segment, 4).wrapping_add(1),
        0x14,
        &[],
    ))
    .await
    .unwrap();
    assert_eq!(
        connecting.await.unwrap().unwrap_err().kind(),
        io::ErrorKind::ConnectionRefused
    );
    driver.abort();
}
