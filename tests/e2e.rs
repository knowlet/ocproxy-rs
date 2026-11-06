//! Real-process tests against an independent IP packet peer.
//!
//! These tests use only loopback TCP and an inherited UNIX datagram socketpair.
//! The peer constructs IPv4/TCP/UDP/DNS bytes directly, without smoltcp, a VPN
//! gateway, privileges, a TUN device, or changes to host routes/resolver settings.

#![cfg(unix)]

use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::{UnixDatagram, UnixStream};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 99, 0, 2);
const SERVICE_IP: Ipv4Addr = Ipv4Addr::new(10, 99, 0, 7);
const DNS_IP: Ipv4Addr = Ipv4Addr::new(10, 99, 0, 53);
const SERVICE_PORT: u16 = 8443;
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const PSH: u8 = 0x08;
const ACK: u8 = 0x10;

fn binary_command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ocproxy-rs"));
    // Do not inherit credentials, VPN settings, resolver overrides, or logging
    // filters from the machine running the tests.
    command.env_clear();
    command.env("NO_COLOR", "1");
    command.env("RUST_LOG", "ocproxy_rs=debug");
    command
}

/// Restore inheritance only in the child. F_SETFD does not change the parent's
/// descriptor flags, so parallel tests cannot accidentally inherit this socket.
fn inherit_fd(command: &mut Command, fd: RawFd) {
    command.env("VPNFD", fd.to_string());
    // SAFETY: The caller keeps fd open until spawn returns. After fork the
    // closure uses only async-signal-safe fcntl calls and reads errno on error.
    unsafe {
        command.pre_exec(move || {
            let flags = libc::fcntl(fd, libc::F_GETFD);
            if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

struct Process {
    child: Child,
    output: Arc<Mutex<Vec<u8>>>,
    ready: Arc<AtomicBool>,
    readers: Vec<JoinHandle<()>>,
}

impl Process {
    fn spawn(command: &mut Command) -> Self {
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("launch test binary");
        let output = Arc::new(Mutex::new(Vec::new()));
        let ready = Arc::new(AtomicBool::new(false));
        let readers = vec![
            capture(child.stdout.take().unwrap(), output.clone(), ready.clone()),
            capture(child.stderr.take().unwrap(), output.clone(), ready.clone()),
        ];
        Self {
            child,
            output,
            ready,
            readers,
        }
    }

    fn logs(&self) -> String {
        String::from_utf8_lossy(&self.output.lock().unwrap()).into_owned()
    }

    fn join_readers(&mut self) {
        for reader in self.readers.drain(..) {
            let _ = reader.join();
        }
    }

    fn wait_ready(&mut self) -> Result<(), String> {
        let deadline = Instant::now() + IO_TIMEOUT;
        loop {
            if self.ready.load(Ordering::Acquire) {
                return Ok(());
            }
            if let Some(status) = self.child.try_wait().unwrap() {
                self.join_readers();
                return Err(format!(
                    "proxy exited before readiness ({status}): {}",
                    self.logs()
                ));
            }
            if Instant::now() >= deadline {
                return Err(format!("proxy readiness timed out: {}", self.logs()));
            }
            thread::sleep(Duration::from_millis(5));
        }
    }

    fn wait_exit(&mut self) -> ExitStatus {
        let deadline = Instant::now() + IO_TIMEOUT;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                self.join_readers();
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "child did not exit: {}",
                self.logs()
            );
            thread::sleep(Duration::from_millis(5));
        }
    }

    fn hangup(&mut self) {
        assert!(self.child.try_wait().unwrap().is_none(), "{}", self.logs());
        // SAFETY: kill has no memory preconditions. This is the live child PID
        // owned by this guard; only that process receives the signal.
        let result = unsafe { libc::kill(self.child.id() as libc::pid_t, libc::SIGHUP) };
        assert_eq!(result, 0, "SIGHUP failed: {}", io::Error::last_os_error());
        let status = self.wait_exit();
        assert!(status.success(), "SIGHUP exit {status}: {}", self.logs());
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        self.join_readers();
    }
}

fn capture(
    mut pipe: impl Read + Send + 'static,
    output: Arc<Mutex<Vec<u8>>>,
    ready: Arc<AtomicBool>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let mut buffer = [0; 1024];
        while let Ok(length) = pipe.read(&mut buffer) {
            if length == 0 {
                break;
            }
            let mut output = output.lock().unwrap();
            let remaining = (64 * 1024_usize).saturating_sub(output.len());
            output.extend_from_slice(&buffer[..length.min(remaining)]);
            if output
                .windows(b"proxy ready".len())
                .any(|part| part == b"proxy ready")
            {
                ready.store(true, Ordering::Release);
            }
        }
    })
}

#[test]
fn help_does_not_require_a_vpn_descriptor() {
    let mut command = binary_command();
    command.arg("--help");
    let mut process = Process::spawn(&mut command);
    assert!(process.wait_exit().success(), "{}", process.logs());
    let output = process.logs();
    assert!(output.contains("--dynfw"), "{output}");
    assert!(output.contains("--localfw"), "{output}");
    assert!(output.contains("SOCKS5"), "{output}");
}

#[test]
fn rejects_missing_invalid_and_closed_descriptors() {
    for (descriptor, expected) in [
        (None, "VPNFD is missing"),
        (Some("not-a-number"), "VPNFD must be an integer"),
        (Some("-1"), "VPNFD must be a descriptor >= 3"),
        (Some("2147483647"), "invalid OpenConnect VPNFD"),
    ] {
        let mut command = binary_command();
        command.args(["-D", "1080", "-I", "10.99.0.2"]);
        if let Some(descriptor) = descriptor {
            command.env("VPNFD", descriptor);
        }
        let mut process = Process::spawn(&mut command);
        assert!(!process.wait_exit().success());
        let output = process.logs();
        assert!(output.contains(expected), "{output}");
        assert!(!output.contains("proxy ready"), "{output}");
    }
}

#[test]
fn rejects_a_stream_descriptor_instead_of_a_packet_socket() {
    let (stream, _peer) = UnixStream::pair().unwrap();
    let mut command = binary_command();
    command.args(["-D", "1080", "-I", "10.99.0.2"]);
    inherit_fd(&mut command, stream.as_raw_fd());
    let mut process = Process::spawn(&mut command);
    assert!(!process.wait_exit().success());
    let output = process.logs();
    assert!(output.contains("invalid OpenConnect VPNFD"), "{output}");
    assert!(!output.contains("proxy ready"), "{output}");
}

#[derive(Clone, Copy)]
enum Mode {
    Forward,
    SocksIp,
    SocksDomain,
}

struct Proxy {
    process: Process,
    tunnel: UnixDatagram,
    listen: SocketAddr,
}

impl Proxy {
    fn start(mode: Mode) -> Self {
        for attempt in 0..5 {
            // Keep the ephemeral port reserved until immediately before spawn.
            // Retry a genuine address-in-use race instead of making CI flaky.
            let reservation = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let listen = reservation.local_addr().unwrap();
            let (child_socket, tunnel) = UnixDatagram::pair().unwrap();
            tunnel
                .set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            tunnel.set_write_timeout(Some(IO_TIMEOUT)).unwrap();
            let mut command = binary_command();
            command
                .env("INTERNAL_IP4_ADDRESS", CLIENT_IP.to_string())
                .env("INTERNAL_IP4_MTU", "1400")
                .args(["--connect-timeout", "3", "--handshake-timeout", "3"]);
            match mode {
                Mode::Forward => {
                    command.args([
                        "-L",
                        &format!("{}:{SERVICE_IP}:{SERVICE_PORT}", listen.port()),
                    ]);
                }
                Mode::SocksIp | Mode::SocksDomain => {
                    command.args(["-D", &listen.port().to_string()]);
                }
            }
            if matches!(mode, Mode::SocksDomain) {
                command.env("INTERNAL_IP4_DNS", DNS_IP.to_string());
                command.env("CISCO_DEF_DOMAIN", "unit.test");
            }
            inherit_fd(&mut command, child_socket.as_raw_fd());
            drop(reservation);
            let mut process = Process::spawn(&mut command);
            drop(child_socket);
            match process.wait_ready() {
                Ok(()) => {
                    return Self {
                        process,
                        tunnel,
                        listen,
                    };
                }
                Err(error) if attempt < 4 && error.contains("Address already in use") => continue,
                Err(error) => panic!("{error}"),
            }
        }
        unreachable!("port collision retries either succeed or panic");
    }

    fn connect(&self) -> TcpStream {
        let stream = TcpStream::connect_timeout(&self.listen, IO_TIMEOUT).unwrap();
        stream.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
        stream.set_write_timeout(Some(IO_TIMEOUT)).unwrap();
        stream.set_nodelay(true).unwrap();
        stream
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        if thread::panicking() {
            eprintln!("test proxy output:\n{}", self.process.logs());
        }
    }
}

#[test]
fn openconnect_sighup_stops_the_real_binary_cleanly() {
    let mut proxy = Proxy::start(Mode::SocksIp);
    proxy.process.hangup();
    assert!(proxy.process.logs().contains("OpenConnect hangup"));
}

#[test]
fn local_forward_delivers_response_after_request_half_close() {
    exercise_proxy(Mode::Forward);
}

#[test]
fn socks_ip_keeps_pipelined_data_and_delivers_response_after_half_close() {
    exercise_proxy(Mode::SocksIp);
}

#[test]
fn socks_name_resolves_using_vpn_dns_and_default_domain() {
    exercise_proxy(Mode::SocksDomain);
}

fn exercise_proxy(mode: Mode) {
    let mut proxy = Proxy::start(mode);
    let mut client = proxy.connect();
    let request = b"request across several TCP segments\n".repeat(300);
    let response = b"response sent after the complete request and its FIN\n".repeat(4);
    let mut input = Vec::new();
    match mode {
        Mode::Forward => {}
        Mode::SocksIp => {
            input.extend([5, 1, 0, 5, 1, 0, 1]);
            input.extend(SERVICE_IP.octets());
            input.extend(SERVICE_PORT.to_be_bytes());
        }
        Mode::SocksDomain => {
            input.extend([5, 1, 0, 5, 1, 0, 3, 7]);
            input.extend(b"service");
            input.extend(SERVICE_PORT.to_be_bytes());
        }
    }
    input.extend(&request);
    client.write_all(&input).unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    if !matches!(mode, Mode::Forward) {
        let mut selection = [0; 2];
        client.read_exact(&mut selection).unwrap();
        assert_eq!(selection, [5, 0]);
        // A CONNECT success must not be sent before the VPN handshake. No peer
        // response has been sent yet, even though the local TCP socket is open.
        client
            .set_read_timeout(Some(Duration::from_millis(30)))
            .unwrap();
        let error = client.read(&mut [0; 1]).unwrap_err();
        assert!(matches!(
            error.kind(),
            io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
        ));
        client.set_read_timeout(Some(IO_TIMEOUT)).unwrap();
    }

    let dns_name = matches!(mode, Mode::SocksDomain).then_some("service.unit.test");
    let mut peer = TcpPeer::accept(&proxy.tunnel, dns_name);
    assert_eq!(peer.receive_until_fin(), request);
    peer.send(ACK | PSH | FIN, &response);

    if !matches!(mode, Mode::Forward) {
        let mut reply = [0; 10];
        client.read_exact(&mut reply).unwrap();
        assert_eq!(&reply[..4], &[5, 0, 0, 1]);
        assert_eq!(&reply[4..8], &CLIENT_IP.octets());
        assert_eq!(u16::from_be_bytes([reply[8], reply[9]]), peer.client.port());
    }
    let mut received = Vec::new();
    client.read_to_end(&mut received).unwrap();
    assert_eq!(received, response);
    peer.wait_for_response_ack();
    proxy.process.hangup();
}

struct IpPacket {
    source: Ipv4Addr,
    destination: Ipv4Addr,
    protocol: u8,
    payload: Vec<u8>,
}

fn receive_ip(socket: &UnixDatagram, deadline: Instant) -> IpPacket {
    let mut bytes = [0; 65536];
    let length = loop {
        assert!(Instant::now() < deadline, "VPN packet peer timed out");
        match socket.recv(&mut bytes) {
            Ok(length) => break length,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) => {}
            Err(error) => panic!("VPN packet read failed: {error}"),
        }
    };
    assert!(length >= 20);
    assert_eq!(bytes[0] >> 4, 4, "expected an IPv4 packet");
    let header_length = usize::from(bytes[0] & 0x0f) * 4;
    assert!((20..=length).contains(&header_length));
    let packet_length = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
    assert_eq!(packet_length, length, "one complete IP packet per datagram");
    assert_eq!(checksum(&bytes[..header_length]), 0, "IPv4 checksum");
    assert_eq!(
        u16::from_be_bytes([bytes[6], bytes[7]]) & 0x3fff,
        0,
        "unexpected fragmented packet"
    );
    IpPacket {
        source: Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]),
        destination: Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]),
        protocol: bytes[9],
        payload: bytes[header_length..length].to_vec(),
    }
}

struct TcpSegment {
    source: SocketAddrV4,
    destination: SocketAddrV4,
    sequence: u32,
    acknowledgment: u32,
    flags: u8,
    data: Vec<u8>,
}

fn tcp_segment(packet: IpPacket) -> TcpSegment {
    assert_eq!(packet.protocol, 6, "expected TCP");
    assert_eq!(
        transport_checksum(packet.source, packet.destination, 6, &packet.payload),
        0,
        "TCP checksum"
    );
    let bytes = &packet.payload;
    assert!(bytes.len() >= 20);
    let header_length = usize::from(bytes[12] >> 4) * 4;
    assert!((20..=bytes.len()).contains(&header_length));
    TcpSegment {
        source: SocketAddrV4::new(packet.source, u16::from_be_bytes([bytes[0], bytes[1]])),
        destination: SocketAddrV4::new(
            packet.destination,
            u16::from_be_bytes([bytes[2], bytes[3]]),
        ),
        sequence: u32::from_be_bytes(bytes[4..8].try_into().unwrap()),
        acknowledgment: u32::from_be_bytes(bytes[8..12].try_into().unwrap()),
        flags: bytes[13],
        data: bytes[header_length..].to_vec(),
    }
}

struct TcpPeer<'a> {
    socket: &'a UnixDatagram,
    client: SocketAddrV4,
    service: SocketAddrV4,
    next_send: u32,
    next_receive: u32,
    syn_ack: Vec<u8>,
}

impl<'a> TcpPeer<'a> {
    fn accept(socket: &'a UnixDatagram, dns_name: Option<&str>) -> Self {
        let deadline = Instant::now() + IO_TIMEOUT;
        let mut dns_queries = 0;
        let syn = loop {
            let packet = receive_ip(socket, deadline);
            assert_eq!(packet.source, CLIENT_IP);
            if packet.protocol == 17 {
                answer_dns(
                    socket,
                    packet,
                    dns_name.expect("unexpected DNS for numeric destination"),
                );
                dns_queries += 1;
                continue;
            }
            break tcp_segment(packet);
        };
        if dns_name.is_some() {
            assert!(dns_queries >= 1, "hostname was not resolved over VPNFD");
        }
        assert_eq!(syn.destination, SocketAddrV4::new(SERVICE_IP, SERVICE_PORT));
        assert_eq!(syn.flags & (SYN | ACK | RST), SYN);
        assert_ne!(syn.source.port(), 0);
        assert!(syn.data.is_empty());
        let next_send = 0x6a12_3400;
        let next_receive = syn.sequence.wrapping_add(1);
        let syn_ack = tcp_packet(
            syn.destination,
            syn.source,
            next_send,
            next_receive,
            SYN | ACK,
            &[],
        );
        assert_eq!(socket.send(&syn_ack).unwrap(), syn_ack.len());
        Self {
            socket,
            client: syn.source,
            service: syn.destination,
            next_send: next_send + 1,
            next_receive,
            syn_ack,
        }
    }

    fn send(&mut self, flags: u8, data: &[u8]) {
        let bytes = tcp_packet(
            self.service,
            self.client,
            self.next_send,
            self.next_receive,
            flags,
            data,
        );
        assert_eq!(self.socket.send(&bytes).unwrap(), bytes.len());
        self.next_send = self
            .next_send
            .wrapping_add(data.len() as u32)
            .wrapping_add(u32::from(flags & FIN != 0))
            .wrapping_add(u32::from(flags & SYN != 0));
    }

    fn receive(&self, deadline: Instant) -> TcpSegment {
        loop {
            let segment = tcp_segment(receive_ip(self.socket, deadline));
            assert_eq!(segment.source, self.client);
            assert_eq!(segment.destination, self.service);
            assert_eq!(segment.flags & RST, 0, "unexpected VPN-side TCP reset");
            if segment.flags & SYN != 0 {
                // Retransmission is legal if scheduling delayed the peer.
                assert_eq!(self.socket.send(&self.syn_ack).unwrap(), self.syn_ack.len());
                continue;
            }
            return segment;
        }
    }

    fn receive_until_fin(&mut self) -> Vec<u8> {
        let deadline = Instant::now() + IO_TIMEOUT;
        let mut request = Vec::new();
        loop {
            let segment = self.receive(deadline);
            let offset = self.next_receive.wrapping_sub(segment.sequence) as usize;
            if offset <= segment.data.len() {
                request.extend_from_slice(&segment.data[offset..]);
                self.next_receive = self
                    .next_receive
                    .wrapping_add((segment.data.len() - offset) as u32);
            }
            assert!(request.len() <= 1024 * 1024, "unexpected unbounded request");
            let fin_sequence = segment.sequence.wrapping_add(segment.data.len() as u32);
            if segment.flags & FIN != 0 && fin_sequence == self.next_receive {
                self.next_receive = self.next_receive.wrapping_add(1);
                self.send(ACK, &[]);
                return request;
            }
            if !segment.data.is_empty() || segment.flags & FIN != 0 {
                self.send(ACK, &[]);
            }
        }
    }

    fn wait_for_response_ack(&mut self) {
        let deadline = Instant::now() + IO_TIMEOUT;
        loop {
            let segment = self.receive(deadline);
            if segment.flags & ACK != 0 && segment.acknowledgment == self.next_send {
                return;
            }
            if segment.flags & FIN != 0 {
                self.send(ACK, &[]);
            }
        }
    }
}

fn answer_dns(socket: &UnixDatagram, packet: IpPacket, expected_name: &str) {
    assert_eq!(packet.destination, DNS_IP);
    assert_eq!(packet.protocol, 17);
    assert_eq!(
        transport_checksum(packet.source, packet.destination, 17, &packet.payload),
        0,
        "UDP checksum"
    );
    let udp = &packet.payload;
    assert!(udp.len() >= 20);
    assert_eq!(u16::from_be_bytes([udp[2], udp[3]]), 53);
    assert_eq!(usize::from(u16::from_be_bytes([udp[4], udp[5]])), udp.len());
    let source_port = u16::from_be_bytes([udp[0], udp[1]]);
    let query = &udp[8..];
    assert_eq!(u16::from_be_bytes([query[4], query[5]]), 1);
    let mut offset = 12;
    let mut labels = Vec::new();
    loop {
        let length = usize::from(query[offset]);
        offset += 1;
        if length == 0 {
            break;
        }
        assert!(length <= 63);
        labels.push(std::str::from_utf8(&query[offset..offset + length]).unwrap());
        offset += length;
    }
    assert_eq!(labels.join("."), expected_name);
    assert_eq!(
        &query[offset..offset + 4],
        &[0, 1, 0, 1],
        "expected an IN A question"
    );
    offset += 4;
    let mut answer = vec![query[0], query[1], 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
    answer.extend_from_slice(&query[12..offset]);
    answer.extend([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
    answer.extend(SERVICE_IP.octets());
    let mut udp = vec![0; 8];
    udp[..2].copy_from_slice(&53_u16.to_be_bytes());
    udp[2..4].copy_from_slice(&source_port.to_be_bytes());
    udp[4..6].copy_from_slice(&u16::try_from(8 + answer.len()).unwrap().to_be_bytes());
    udp.extend(answer);
    let check = transport_checksum(DNS_IP, CLIENT_IP, 17, &udp);
    udp[6..8].copy_from_slice(&(if check == 0 { 0xffff } else { check }).to_be_bytes());
    let bytes = ip_packet(DNS_IP, CLIENT_IP, 17, &udp);
    assert_eq!(socket.send(&bytes).unwrap(), bytes.len());
}

fn tcp_packet(
    source: SocketAddrV4,
    destination: SocketAddrV4,
    sequence: u32,
    acknowledgment: u32,
    flags: u8,
    data: &[u8],
) -> Vec<u8> {
    let mut tcp = vec![0; 20];
    tcp[..2].copy_from_slice(&source.port().to_be_bytes());
    tcp[2..4].copy_from_slice(&destination.port().to_be_bytes());
    tcp[4..8].copy_from_slice(&sequence.to_be_bytes());
    tcp[8..12].copy_from_slice(&acknowledgment.to_be_bytes());
    tcp[12] = 5 << 4;
    tcp[13] = flags;
    tcp[14..16].copy_from_slice(&65535_u16.to_be_bytes());
    tcp.extend_from_slice(data);
    let check = transport_checksum(*source.ip(), *destination.ip(), 6, &tcp);
    tcp[16..18].copy_from_slice(&check.to_be_bytes());
    ip_packet(*source.ip(), *destination.ip(), 6, &tcp)
}

fn ip_packet(source: Ipv4Addr, destination: Ipv4Addr, protocol: u8, payload: &[u8]) -> Vec<u8> {
    let mut ip = vec![0; 20];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&u16::try_from(20 + payload.len()).unwrap().to_be_bytes());
    ip[6..8].copy_from_slice(&0x4000_u16.to_be_bytes());
    ip[8] = 64;
    ip[9] = protocol;
    ip[12..16].copy_from_slice(&source.octets());
    ip[16..20].copy_from_slice(&destination.octets());
    let check = checksum(&ip);
    ip[10..12].copy_from_slice(&check.to_be_bytes());
    ip.extend_from_slice(payload);
    ip
}

fn transport_checksum(source: Ipv4Addr, destination: Ipv4Addr, protocol: u8, data: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + data.len());
    pseudo.extend(source.octets());
    pseudo.extend(destination.octets());
    pseudo.extend([0, protocol]);
    pseudo.extend(u16::try_from(data.len()).unwrap().to_be_bytes());
    pseudo.extend_from_slice(data);
    checksum(&pseudo)
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0_u32;
    for pair in data.chunks(2) {
        sum += u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
