//! The VPN packet socket is the only path used for outbound TCP and DNS.
//!
//! One bounded actor owns smoltcp. Application streams use bounded in-memory
//! duplex pipes, so kernel TCP sockets are needed only for the local listeners.
use std::{
    collections::{BTreeSet, VecDeque},
    future::{Future, poll_fn},
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use smoltcp::{
    iface::{Config as InterfaceConfig, Interface, PollResult, SocketHandle, SocketSet},
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::{dns, tcp},
    time::Instant as StackInstant,
    wire::{DnsQueryType, HardwareAddress, IpAddress, IpCidr, IpEndpoint},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf},
    net::UnixDatagram,
    sync::{mpsc, oneshot},
    time::{Instant, Sleep, sleep_until, timeout_at},
};

use crate::{Target, config::NetworkConfig};

const PACKET_QUEUE: usize = 64;
const WORK_BUDGET: usize = 32;
const FIRST_EPHEMERAL: u16 = 49152;
const EPHEMERAL_COUNT: u32 = 16384;
const MAX_DATAGRAM: usize = 65_535;

/// A completed VPN TCP connection and its actual VPN-side local endpoint.
#[derive(Debug)]
pub struct Connected {
    pub stream: DuplexStream,
    pub local_addr: SocketAddr,
}

/// A cloneable connection factory. Dropping a pending connect cancels its work.
#[derive(Clone)]
pub struct Network {
    commands: mpsc::Sender<ConnectCommand>,
    connect_timeout: Duration,
}

impl Network {
    /// Establish TCP through the VPN. DNS names never use the host resolver.
    pub async fn connect(&self, target: Target) -> io::Result<Connected> {
        let deadline = Instant::now() + self.connect_timeout;
        let (reply, response) = oneshot::channel();
        let operation = async {
            self.commands
                .send(ConnectCommand {
                    target,
                    deadline,
                    reply,
                })
                .await
                .map_err(|_| stopped())?;
            response.await.map_err(|_| stopped())?
        };
        timeout_at(deadline, operation)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "VPN DNS/TCP connect timed out"))?
    }
}

type ConnectReply = oneshot::Sender<io::Result<Connected>>;

struct ConnectCommand {
    target: Target,
    deadline: Instant,
    reply: ConnectReply,
}

struct Resolution {
    queries: Vec<dns::QueryHandle>,
    port: u16,
    deadline: Instant,
    reply: ConnectReply,
}

struct Flow {
    handle: SocketHandle,
    local_addr: SocketAddr,
    bridge: DuplexStream,
    client: Option<DuplexStream>,
    reply: Option<ConnectReply>,
    alternatives: VecDeque<SocketAddr>,
    deadline: Instant,
    attempt_deadline: Instant,
    local_eof: bool,
    remote_eof: bool,
    close_deadline: Option<Instant>,
}

/// Drives packets, timers, DNS queries, and application backpressure.
///
/// Run this future for as long as its [`Network`] and streams are in use. An
/// unrecoverable packet-socket error terminates it and closes all streams.
pub struct Driver {
    tunnel: UnixDatagram,
    config: NetworkConfig,
    commands: mpsc::Receiver<ConnectCommand>,
    commands_closed: bool,
    device: PacketDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
    dns: SocketHandle,
    resolutions: Vec<Resolution>,
    flows: Vec<Flow>,
    used_ports: BTreeSet<u16>,
    epoch: Instant,
    timer: Pin<Box<Sleep>>,
    receive_buffer: Vec<u8>,
}

/// Construct a VPN stack. The caller must supply a connected, nonblocking UNIX
/// datagram socket, normally created by [`crate::tunnel`]. No task is spawned.
pub fn new(tunnel: UnixDatagram, config: NetworkConfig) -> io::Result<(Network, Driver)> {
    validate_config(&config)?;
    let mut seed = [0; 8];
    getrandom::fill(&mut seed).map_err(|error| io::Error::other(error.to_string()))?;
    let mut device = PacketDevice::new(config.mtu);
    let mut interface_config = InterfaceConfig::new(HardwareAddress::Ip);
    interface_config.random_seed = u64::from_ne_bytes(seed);
    let mut iface = Interface::new(interface_config, &mut device, StackInstant::ZERO);
    iface.update_ip_addrs(|addresses| {
        if let Some(address) = config.ipv4 {
            addresses
                .push(IpCidr::new(address.into(), 32))
                .expect("two address slots");
        }
        if let Some(address) = config.ipv6 {
            addresses
                .push(IpCidr::new(address.into(), 128))
                .expect("two address slots");
        }
    });
    // On an IP medium there is no link-layer gateway to discover. The assigned
    // address is a placeholder next hop for the point-to-point default routes.
    if let Some(address) = config.ipv4 {
        iface
            .routes_mut()
            .add_default_ipv4_route(address)
            .map_err(|_| io::Error::other("no IPv4 route slot"))?;
    }
    if let Some(address) = config.ipv6 {
        iface
            .routes_mut()
            .add_default_ipv6_route(address)
            .map_err(|_| io::Error::other("no IPv6 route slot"))?;
    }
    let servers: Vec<IpAddress> = config.dns_servers.iter().copied().map(Into::into).collect();
    let mut sockets = SocketSet::new(Vec::new());
    let dns = sockets.add(dns::Socket::new(&servers, Vec::new()));
    let (send, commands) = mpsc::channel(config.max_connections.min(1024));
    let epoch = Instant::now();
    let network = Network {
        commands: send,
        connect_timeout: config.connect_timeout,
    };
    let driver = Driver {
        tunnel,
        config,
        commands,
        commands_closed: false,
        device,
        iface,
        sockets,
        dns,
        resolutions: Vec::new(),
        flows: Vec::new(),
        used_ports: BTreeSet::new(),
        epoch,
        timer: Box::pin(sleep_until(epoch)),
        // One extra byte detects a truncated datagram even at the maximum MTU.
        receive_buffer: vec![0; MAX_DATAGRAM + 1],
    };
    Ok((network, driver))
}

fn validate_config(config: &NetworkConfig) -> io::Result<()> {
    let invalid = |message| io::Error::new(io::ErrorKind::InvalidInput, message);
    if config.ipv4.is_none() && config.ipv6.is_none() {
        return Err(invalid("a VPN address is required"));
    }
    if config
        .ipv4
        .is_some_and(|ip| ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast())
        || config
            .ipv6
            .is_some_and(|ip| ip.is_unspecified() || ip.is_multicast())
    {
        return Err(invalid("VPN addresses must be unicast"));
    }
    if !(576..=MAX_DATAGRAM).contains(&config.mtu) || (config.ipv6.is_some() && config.mtu < 1280) {
        return Err(invalid("invalid VPN MTU"));
    }
    if !(1..=4096).contains(&config.max_connections)
        || !(4096..=1_048_576).contains(&config.buffer_size)
        || config
            .buffer_size
            .saturating_mul(config.max_connections)
            .saturating_mul(4)
            > 1 << 30
    {
        return Err(invalid("invalid connection buffer budget"));
    }
    if config.connect_timeout.is_zero()
        || config.connect_timeout > Duration::from_secs(3600)
        || config.tcp_timeout.is_zero()
        || config.tcp_timeout > Duration::from_secs(86400)
        || config
            .keepalive
            .is_some_and(|interval| interval.is_zero() || interval >= config.tcp_timeout)
    {
        return Err(invalid(
            "timeouts must be positive and keepalive must be shorter than TCP timeout",
        ));
    }
    if config.dns_servers.len() > smoltcp::config::DNS_MAX_SERVER_COUNT {
        return Err(invalid("too many VPN DNS servers for the compiled stack"));
    }
    if config.dns_servers.iter().any(|ip| {
        ip.is_unspecified()
            || ip.is_multicast()
            || match ip {
                IpAddr::V4(ip) => ip.is_broadcast() || config.ipv4.is_none(),
                IpAddr::V6(_) => config.ipv6.is_none(),
            }
    }) {
        return Err(invalid(
            "DNS servers require a unicast VPN address of the same family",
        ));
    }
    if config
        .domain
        .as_ref()
        .is_some_and(|name| !crate::config::valid_hostname(name))
    {
        return Err(invalid("invalid DNS suffix"));
    }
    Ok(())
}

impl Driver {
    pub async fn run(mut self) -> io::Result<()> {
        poll_fn(|cx| self.poll(cx)).await
    }

    fn stack_now(&self) -> StackInstant {
        StackInstant::from_millis(self.epoch.elapsed().as_millis().min(i64::MAX as u128) as i64)
    }

    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let now = Instant::now();
        let stack_now = self.stack_now();
        self.flush_packets(cx)?;
        self.receive_packets(cx)?;
        for _ in 0..WORK_BUDGET {
            match self.commands.poll_recv(cx) {
                Poll::Ready(Some(command)) => self.start(command),
                Poll::Ready(None) => {
                    self.commands_closed = true;
                    break;
                }
                Poll::Pending => break,
            }
        }
        if !self.commands.is_empty() {
            cx.waker().wake_by_ref();
        }
        self.iface
            .poll(stack_now, &mut self.device, &mut self.sockets);
        self.resolve(cx, now);
        let (retired, progress) = self.relay(cx, now);
        let changed = self
            .iface
            .poll(self.stack_now(), &mut self.device, &mut self.sockets)
            == PollResult::SocketStateChanged;
        self.flush_packets(cx)?;
        // Give aborts and final ACKs a chance to enter the packet queue before
        // removing closed sockets. TIME-WAIT sockets remain until expiry.
        for (handle, port) in retired {
            self.sockets.remove(handle);
            self.used_ports.remove(&port);
        }
        if self.commands_closed && self.flows.is_empty() && self.resolutions.is_empty() {
            return Poll::Ready(Ok(()));
        }
        if changed
            || progress
            || (!self.device.rx.is_empty() && self.device.tx.len() < PACKET_QUEUE)
        {
            cx.waker().wake_by_ref();
        }
        let delay = self
            .iface
            .poll_delay(self.stack_now(), &self.sockets)
            .map(Duration::from)
            .unwrap_or(Duration::from_secs(3600));
        // When the VPN transport is blocked, readiness wakes us as soon as it
        // can transmit. Do not spin on smoltcp's immediate egress deadline.
        let delay = if self.device.tx.len() == PACKET_QUEUE && delay.is_zero() {
            Duration::from_secs(1)
        } else {
            delay.max(Duration::from_millis(1))
        };
        let mut deadline = now + delay;
        for resolution in &self.resolutions {
            deadline = deadline.min(resolution.deadline);
        }
        for flow in &self.flows {
            if flow.reply.is_some() {
                deadline = deadline.min(flow.attempt_deadline);
            }
            if let Some(close) = flow.close_deadline {
                deadline = deadline.min(close);
            }
        }
        self.timer.as_mut().reset(deadline);
        if self.timer.as_mut().poll(cx).is_ready() {
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    }

    fn receive_packets(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        for _ in 0..WORK_BUDGET {
            if self.device.rx.len() == PACKET_QUEUE {
                return Ok(());
            }
            match self.tunnel.poll_recv_ready(cx) {
                Poll::Pending => return Ok(()),
                Poll::Ready(result) => result?,
            }
            match self.tunnel.try_recv(&mut self.receive_buffer) {
                Ok(size) => {
                    let packet = &self.receive_buffer[..size];
                    if size <= self.config.mtu && valid_ip_packet(packet) {
                        self.device.rx.push_back(packet.to_vec());
                    } else {
                        tracing::debug!(size, "discarding malformed or oversized VPN datagram");
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        cx.waker().wake_by_ref();
        Ok(())
    }

    fn flush_packets(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        for _ in 0..WORK_BUDGET {
            let Some(packet) = self.device.tx.front() else {
                return Ok(());
            };
            match self.tunnel.poll_send_ready(cx) {
                Poll::Pending => return Ok(()),
                Poll::Ready(result) => result?,
            }
            match self.tunnel.try_send(packet) {
                Ok(size) if size == packet.len() => {
                    self.device.tx.pop_front();
                }
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "short VPN datagram write",
                    ));
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        if !self.device.tx.is_empty() {
            cx.waker().wake_by_ref();
        }
        Ok(())
    }

    fn start(&mut self, command: ConnectCommand) {
        let ConnectCommand {
            target,
            deadline,
            reply,
        } = command;
        if reply.is_closed() {
            return;
        }
        if self.flows.len() + self.resolutions.len() >= self.config.max_connections {
            let _ = reply.send(Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "VPN connection limit reached",
            )));
            return;
        }
        if deadline <= Instant::now() {
            let _ = reply.send(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "VPN connect deadline expired",
            )));
            return;
        }
        if target.port() == 0 {
            let _ = reply.send(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "destination port must be nonzero",
            )));
            return;
        }
        match target {
            Target::Ip(address) => self.start_tcp(vec![address], deadline, reply),
            Target::Domain(name, port) => {
                let name = match qualify_name(&name, self.config.domain.as_deref()) {
                    Ok(name) => name,
                    Err(error) => {
                        let _ = reply.send(Err(error));
                        return;
                    }
                };
                if self.config.dns_servers.is_empty() {
                    let _ = reply.send(Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        "no VPN DNS server configured",
                    )));
                    return;
                }
                let mut queries = Vec::with_capacity(2);
                let query_types = [
                    self.config.ipv4.map(|_| DnsQueryType::A),
                    self.config.ipv6.map(|_| DnsQueryType::Aaaa),
                ];
                let socket = self.sockets.get_mut::<dns::Socket>(self.dns);
                for query_type in query_types.into_iter().flatten() {
                    match socket.start_query(self.iface.context(), &name, query_type) {
                        Ok(query) => queries.push(query),
                        Err(error) => {
                            for query in queries {
                                socket.cancel_query(query);
                            }
                            let _ = reply.send(Err(io::Error::new(
                                io::ErrorKind::InvalidInput,
                                error.to_string(),
                            )));
                            return;
                        }
                    }
                }
                self.resolutions.push(Resolution {
                    queries,
                    port,
                    deadline,
                    reply,
                });
            }
        }
    }

    fn resolve(&mut self, cx: &mut Context<'_>, now: Instant) {
        let pending = std::mem::take(&mut self.resolutions);
        for mut resolution in pending {
            let socket = self.sockets.get_mut::<dns::Socket>(self.dns);
            if resolution.reply.poll_closed(cx).is_ready() || resolution.deadline <= now {
                for query in resolution.queries {
                    socket.cancel_query(query);
                }
                let _ = resolution.reply.send(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "VPN DNS timed out",
                )));
                continue;
            }
            let mut queries = Vec::new();
            let mut addresses = Vec::new();
            for query in resolution.queries {
                match socket.get_query_result(query) {
                    Ok(result) => {
                        for address in result {
                            let address: IpAddr = address.into();
                            let supported = match address {
                                IpAddr::V4(ip) => self.config.ipv4.is_some() && !ip.is_broadcast(),
                                IpAddr::V6(_) => self.config.ipv6.is_some(),
                            };
                            if supported && !address.is_unspecified() && !address.is_multicast() {
                                let endpoint = SocketAddr::new(address, resolution.port);
                                if !addresses.contains(&endpoint) {
                                    addresses.push(endpoint);
                                }
                            }
                        }
                    }
                    Err(dns::GetQueryResultError::Pending) => {
                        socket.register_query_waker(query, cx.waker());
                        queries.push(query);
                    }
                    Err(dns::GetQueryResultError::Failed) => {}
                }
            }
            if !addresses.is_empty() {
                for query in queries {
                    socket.cancel_query(query);
                }
                self.start_tcp(addresses, resolution.deadline, resolution.reply);
            } else if queries.is_empty() {
                let _ = resolution.reply.send(Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "VPN DNS returned no usable address",
                )));
            } else {
                resolution.queries = queries;
                self.resolutions.push(resolution);
            }
        }
    }

    fn allocate_port(&mut self) -> io::Result<u16> {
        let mut random = [0; 2];
        getrandom::fill(&mut random).map_err(|error| io::Error::other(error.to_string()))?;
        let start = u16::from_ne_bytes(random) as u32 % EPHEMERAL_COUNT;
        for offset in 0..EPHEMERAL_COUNT {
            let port = FIRST_EPHEMERAL + ((start + offset) % EPHEMERAL_COUNT) as u16;
            if self.used_ports.insert(port) {
                return Ok(port);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "no free VPN TCP source port",
        ))
    }

    fn open_tcp(
        &mut self,
        socket: &mut tcp::Socket<'static>,
        remote: SocketAddr,
    ) -> io::Result<SocketAddr> {
        let source: IpAddr = match remote {
            SocketAddr::V4(_) => self.config.ipv4.map(IpAddr::V4),
            SocketAddr::V6(_) => self.config.ipv6.map(IpAddr::V6),
        }
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                "destination address family is not configured on the VPN",
            )
        })?;
        if remote.ip().is_unspecified()
            || remote.ip().is_multicast()
            || matches!(remote.ip(), IpAddr::V4(ip) if ip.is_broadcast())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "destination must be a unicast address",
            ));
        }
        let port = self.allocate_port()?;
        let local = SocketAddr::new(source, port);
        if let Err(error) = socket.connect(
            self.iface.context(),
            IpEndpoint::from(remote),
            IpEndpoint::from(local),
        ) {
            self.used_ports.remove(&port);
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                error.to_string(),
            ));
        }
        socket.set_keep_alive(self.config.keepalive.map(Into::into));
        socket.set_timeout(Some(self.config.tcp_timeout.into()));
        socket.set_nagle_enabled(false);
        socket.set_congestion_control(tcp::CongestionControl::Cubic);
        Ok(local)
    }

    fn start_tcp(&mut self, addresses: Vec<SocketAddr>, deadline: Instant, reply: ConnectReply) {
        let mut alternatives: VecDeque<_> = addresses.into();
        let Some(address) = alternatives.pop_front() else {
            return;
        };
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; self.config.buffer_size]),
            tcp::SocketBuffer::new(vec![0; self.config.buffer_size]),
        );
        let local_addr = match self.open_tcp(&mut socket, address) {
            Ok(local) => local,
            Err(error) => {
                let _ = reply.send(Err(error));
                return;
            }
        };
        let handle = self.sockets.add(socket);
        let (client, bridge) = tokio::io::duplex(self.config.buffer_size);
        self.flows.push(Flow {
            handle,
            local_addr,
            bridge,
            client: Some(client),
            reply: Some(reply),
            attempt_deadline: attempt_deadline(deadline, alternatives.len()),
            alternatives,
            deadline,
            local_eof: false,
            remote_eof: false,
            close_deadline: None,
        });
    }

    fn retry(&mut self, flow: &mut Flow) -> io::Result<bool> {
        let Some(address) = flow.alternatives.pop_front() else {
            return Ok(false);
        };
        let socket = self.sockets.get_mut::<tcp::Socket>(flow.handle);
        socket.abort();
        // Retire the old tuple before reusing its storage. A stale response can
        // never match the new randomly allocated source port.
        let old = self.sockets.remove(flow.handle);
        drop(old);
        self.used_ports.remove(&flow.local_addr.port());
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; self.config.buffer_size]),
            tcp::SocketBuffer::new(vec![0; self.config.buffer_size]),
        );
        match self.open_tcp(&mut socket, address) {
            Ok(local) => {
                flow.local_addr = local;
                flow.attempt_deadline = attempt_deadline(flow.deadline, flow.alternatives.len());
                flow.handle = self.sockets.add(socket);
                Ok(true)
            }
            Err(error) => {
                // Keep a valid handle for the common retirement path.
                flow.handle = self.sockets.add(socket);
                Err(error)
            }
        }
    }

    fn relay(&mut self, cx: &mut Context<'_>, now: Instant) -> (Vec<(SocketHandle, u16)>, bool) {
        let mut retired = Vec::new();
        let mut progress = false;
        let flows = std::mem::take(&mut self.flows);
        for mut flow in flows {
            let mut remove = false;
            if let Some(reply) = flow.reply.as_mut() {
                if reply.poll_closed(cx).is_ready() {
                    remove = true;
                } else {
                    let state = self.sockets.get::<tcp::Socket>(flow.handle).state();
                    if matches!(state, tcp::State::Established | tcp::State::CloseWait) {
                        let reply = flow.reply.take().expect("connecting flow reply");
                        let stream = flow.client.take().expect("connecting flow stream");
                        if reply
                            .send(Ok(Connected {
                                stream,
                                local_addr: flow.local_addr,
                            }))
                            .is_err()
                        {
                            remove = true;
                        }
                    } else if now >= flow.attempt_deadline || state == tcp::State::Closed {
                        let timed_out = now >= flow.attempt_deadline;
                        let retry = if now < flow.deadline {
                            self.retry(&mut flow)
                        } else {
                            Ok(false)
                        };
                        match retry {
                            Ok(true) => {}
                            result => {
                                let error = result.err().unwrap_or_else(|| {
                                    if timed_out {
                                        io::Error::new(
                                            io::ErrorKind::TimedOut,
                                            "VPN TCP connect timed out",
                                        )
                                    } else {
                                        io::Error::new(
                                            io::ErrorKind::ConnectionRefused,
                                            "VPN peer refused the TCP connection",
                                        )
                                    }
                                });
                                let _ = flow
                                    .reply
                                    .take()
                                    .expect("connecting flow reply")
                                    .send(Err(error));
                                remove = true;
                            }
                        }
                    }
                }
            }
            let socket = self.sockets.get_mut::<tcp::Socket>(flow.handle);
            socket.register_recv_waker(cx.waker());
            socket.register_send_waker(cx.waker());
            if !remove && flow.reply.is_none() {
                // Pull directly into smoltcp's free buffer. A pending local read
                // registers the actor's waker and cannot consume unbuffered data.
                if !flow.local_eof && socket.can_send() {
                    let result = socket.send(|bytes| {
                        let mut read = ReadBuf::new(bytes);
                        match Pin::new(&mut flow.bridge).poll_read(cx, &mut read) {
                            Poll::Ready(Ok(())) => {
                                (read.filled().len(), Poll::Ready(Ok(read.filled().len())))
                            }
                            Poll::Ready(Err(error)) => (0, Poll::Ready(Err(error))),
                            Poll::Pending => (0, Poll::Pending),
                        }
                    });
                    match result {
                        Ok(Poll::Ready(Ok(0))) => {
                            flow.local_eof = true;
                            flow.close_deadline = Some(now + self.config.tcp_timeout);
                            socket.close();
                            progress = true;
                        }
                        Ok(Poll::Ready(Ok(_))) => progress = true,
                        Ok(Poll::Ready(Err(_))) | Err(_) => remove = true,
                        Ok(Poll::Pending) => {}
                    }
                }
                if !remove && socket.can_recv() {
                    let result = socket.recv(|bytes| {
                        match Pin::new(&mut flow.bridge).poll_write(cx, bytes) {
                            Poll::Ready(Ok(size)) => (size, Poll::Ready(Ok(size))),
                            Poll::Ready(Err(error)) => (0, Poll::Ready(Err(error))),
                            Poll::Pending => (0, Poll::Pending),
                        }
                    });
                    match result {
                        Ok(Poll::Ready(Ok(0))) | Ok(Poll::Ready(Err(_))) | Err(_) => remove = true,
                        Ok(Poll::Ready(Ok(_))) => {
                            progress = true;
                            if flow.local_eof {
                                flow.close_deadline = Some(now + self.config.tcp_timeout);
                            }
                        }
                        Ok(Poll::Pending) => {}
                    }
                }
                if !remove && !flow.remote_eof && !socket.may_recv() {
                    match Pin::new(&mut flow.bridge).poll_shutdown(cx) {
                        Poll::Ready(Ok(())) => {
                            flow.remote_eof = true;
                            progress = true;
                        }
                        Poll::Ready(Err(_)) => remove = true,
                        Poll::Pending => {}
                    }
                }
                // A peer may acknowledge our FIN and then disappear forever.
                // Bound FIN-WAIT cleanup while preserving both halves until then.
                if flow.close_deadline.is_some_and(|deadline| now >= deadline) {
                    remove = true;
                }
                if socket.state() == tcp::State::Closed && !socket.can_recv() {
                    remove = true;
                }
            }
            if remove {
                socket.abort();
                retired.push((flow.handle, flow.local_addr.port()));
            } else {
                self.flows.push(flow);
            }
        }
        (retired, progress)
    }
}

fn stopped() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "VPN packet driver stopped")
}

fn attempt_deadline(deadline: Instant, alternatives: usize) -> Instant {
    let now = Instant::now();
    let remaining = deadline.saturating_duration_since(now);
    now + (remaining / (alternatives as u32 + 1))
        .max(Duration::from_millis(1))
        .min(remaining)
}

fn qualify_name(name: &str, domain: Option<&str>) -> io::Result<String> {
    let qualified = if !name.contains('.') {
        match domain {
            Some(domain) => format!("{name}.{}", domain.trim_end_matches('.')),
            None => name.to_owned(),
        }
    } else {
        name.to_owned()
    };
    if !crate::config::valid_hostname(&qualified) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid or oversized DNS name",
        ));
    }
    Ok(qualified)
}

fn valid_ip_packet(packet: &[u8]) -> bool {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) if packet.len() >= 20 => {
            let header = usize::from(packet[0] & 15) * 4;
            header >= 20
                && header <= packet.len()
                && usize::from(u16::from_be_bytes([packet[2], packet[3]])) == packet.len()
        }
        Some(6) if packet.len() >= 40 => {
            usize::from(u16::from_be_bytes([packet[4], packet[5]])) + 40 == packet.len()
        }
        _ => false,
    }
}

struct PacketDevice {
    mtu: usize,
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
}

impl PacketDevice {
    fn new(mtu: usize) -> Self {
        Self {
            mtu,
            rx: VecDeque::new(),
            tx: VecDeque::new(),
        }
    }
}

struct ReceivedPacket(Vec<u8>);
struct TransmitPacket<'a>(&'a mut VecDeque<Vec<u8>>);

impl Device for PacketDevice {
    type RxToken<'a> = ReceivedPacket;
    type TxToken<'a> = TransmitPacket<'a>;

    fn receive(&mut self, _: StackInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if self.tx.len() >= PACKET_QUEUE {
            return None;
        }
        self.rx
            .pop_front()
            .map(|packet| (ReceivedPacket(packet), TransmitPacket(&mut self.tx)))
    }

    fn transmit(&mut self, _: StackInstant) -> Option<Self::TxToken<'_>> {
        (self.tx.len() < PACKET_QUEUE).then_some(TransmitPacket(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = self.mtu;
        capabilities
    }
}

impl RxToken for ReceivedPacket {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, function: F) -> R {
        function(&self.0)
    }
}

impl TxToken for TransmitPacket<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, size: usize, function: F) -> R {
        let mut packet = vec![0; size];
        let result = function(&mut packet);
        self.0.push_back(packet);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suffix_applies_only_to_unqualified_names() {
        assert_eq!(
            qualify_name("host", Some("corp.test")).unwrap(),
            "host.corp.test"
        );
        assert_eq!(qualify_name("host.", Some("corp.test")).unwrap(), "host.");
        assert_eq!(
            qualify_name("host.other", Some("corp.test")).unwrap(),
            "host.other"
        );
        assert!(qualify_name("", None).is_err());
        assert!(qualify_name(&"x".repeat(64), Some("corp.test")).is_err());
    }

    #[test]
    fn packet_envelope_rejects_truncation_and_prefixes() {
        let mut packet = vec![0; 20];
        packet[0] = 0x45;
        packet[3] = 20;
        assert!(valid_ip_packet(&packet));
        assert!(!valid_ip_packet(&packet[..19]));
        packet.push(0);
        assert!(!valid_ip_packet(&packet));
        assert!(!valid_ip_packet(&[0, 0, 0, 2, 0x45]));
        let mut ipv6 = vec![0; 40];
        ipv6[0] = 0x60;
        assert!(valid_ip_packet(&ipv6));
        ipv6[5] = 1;
        assert!(!valid_ip_packet(&ipv6));
    }

    #[test]
    fn packet_queues_apply_backpressure() {
        let mut device = PacketDevice::new(1400);
        for _ in 0..PACKET_QUEUE {
            device
                .transmit(StackInstant::ZERO)
                .unwrap()
                .consume(20, |packet| packet.fill(0));
        }
        device.rx.push_back(vec![0; 20]);
        assert!(device.transmit(StackInstant::ZERO).is_none());
        assert!(device.receive(StackInstant::ZERO).is_none());
        device.tx.pop_front();
        assert!(device.receive(StackInstant::ZERO).is_some());
    }
    fn test_config() -> NetworkConfig {
        NetworkConfig {
            ipv4: Some("10.20.0.2".parse().unwrap()),
            ipv6: None,
            mtu: 1400,
            dns_servers: vec![],
            domain: None,
            connect_timeout: Duration::from_secs(30),
            tcp_timeout: Duration::from_secs(300),
            keepalive: None,
            max_connections: 1,
            buffer_size: 4096,
        }
    }

    #[tokio::test]
    async fn blocked_transport_with_pending_ingress_does_not_self_wake() {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        use std::task::{Wake, Waker};
        struct Counter(AtomicUsize);
        impl Wake for Counter {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
            fn wake_by_ref(self: &Arc<Self>) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }
        let (socket, _peer) = std::os::unix::net::UnixDatagram::pair().unwrap();
        socket.set_nonblocking(true).unwrap();
        let mut blocked = false;
        for _ in 0..65_536 {
            match socket.send(&[0; 1400]) {
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    blocked = true;
                    break;
                }
                // Darwin reports a full UNIX datagram peer queue as ENOBUFS,
                // rather than EAGAIN. This is only a test-setup condition;
                // production packet-send errors retain their existing handling.
                #[cfg(target_os = "macos")]
                Err(error) if error.raw_os_error() == Some(libc::ENOBUFS) => {
                    blocked = true;
                    break;
                }
                Err(error) => panic!("could not fill transport: {error}"),
            }
        }
        assert!(blocked, "transport did not saturate within the setup limit");
        let (network, mut driver) =
            new(UnixDatagram::from_std(socket).unwrap(), test_config()).unwrap();
        for _ in 0..PACKET_QUEUE {
            driver.device.tx.push_back(vec![0; 1400]);
        }
        driver.device.rx.push_back(vec![0; 20]);
        let counter = Arc::new(Counter(AtomicUsize::new(0)));
        let waker = Waker::from(counter.clone());
        let mut context = Context::from_waker(&waker);
        assert!(driver.poll(&mut context).is_pending());
        assert_eq!(
            counter.0.load(Ordering::Relaxed),
            0,
            "full TX + pending RX would busy-spin"
        );
        assert_eq!(driver.device.rx.len(), 1);
        drop(network);
    }

    #[tokio::test]
    async fn public_config_rejects_overflowing_deadlines() {
        for field in ["connect", "tcp"] {
            let mut config = test_config();
            if field == "connect" {
                config.connect_timeout = Duration::MAX;
            } else {
                config.tcp_timeout = Duration::MAX;
            }
            let (socket, _peer) = UnixDatagram::pair().unwrap();
            assert!(
                matches!(new(socket, config), Err(error) if error.kind() == io::ErrorKind::InvalidInput)
            );
        }
    }
}
