//! The VPN packet socket is the only path used for outbound TCP and DNS.
//!
//! One bounded actor owns smoltcp. Application streams use bounded in-memory
//! duplex pipes, so kernel TCP sockets are needed only for the local listeners.
use std::{
    collections::{BTreeSet, VecDeque},
    future::{Future, poll_fn},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
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
const SEND_RETRY_DELAY: Duration = Duration::from_millis(10);
const FIRST_EPHEMERAL: u16 = 49152;
const EPHEMERAL_COUNT: u32 = 16384;
const MAX_DATAGRAM: usize = 65_535;
/// smoltcp's TIME-WAIT duration. A reclaimed tuple stays reserved until the
/// socket would have left TIME-WAIT: this long after entry, and this long
/// after each later segment that restarts the timer.
const TIME_WAIT: Duration = Duration::from_secs(10);

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
    /// When smoltcp's TIME-WAIT timer expires. Set on entry and moved forward
    /// if an incoming segment restarts that timer.
    time_wait_until: Option<Instant>,
}

struct QuarantinedTuple {
    expires: Instant,
    port: u16,
    remote: SocketAddr,
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
    /// Reclaimed TIME-WAIT tuples. A local port stays blocked only for the
    /// remote it was connected to, and only until that socket's deadline.
    quarantined_ports: VecDeque<QuarantinedTuple>,
    epoch: Instant,
    timer: Pin<Box<Sleep>>,
    receive_buffer: Vec<u8>,
    send_retry_at: Option<Instant>,
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
        quarantined_ports: VecDeque::new(),
        epoch,
        timer: Box::pin(sleep_until(epoch)),
        // One extra byte detects a truncated datagram even at the maximum MTU.
        receive_buffer: vec![0; MAX_DATAGRAM + 1],
        send_retry_at: None,
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
    if !(crate::config::MIN_MTU..=MAX_DATAGRAM).contains(&config.mtu)
        || (config.ipv6.is_some() && config.mtu < crate::config::MIN_IPV6_MTU)
    {
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
        // A segment already queued for a TIME-WAIT socket restarts its timer
        // inside the poll below. Record that before a new connect can reclaim it.
        self.note_time_wait_segments(now);
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
        // Finish only after queued packets, such as final resets, have been sent.
        // A send error still ends the driver through flush_packets above.
        if self.commands_closed
            && self.flows.is_empty()
            && self.resolutions.is_empty()
            && self.device.tx.is_empty()
        {
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
        // ENOBUFS uses a timer because writable readiness may remain set. Other
        // blocked sends use readiness. Do not spin on an immediate egress deadline.
        let delay = match (delay.is_zero(), self.send_retry_at) {
            (true, Some(retry)) => retry.saturating_duration_since(now),
            (true, None) if self.device.tx.len() == PACKET_QUEUE => Duration::from_secs(1),
            _ => delay.max(Duration::from_millis(1)),
        };
        let mut deadline = now + delay;
        if let Some(retry) = self.send_retry_at {
            deadline = deadline.min(retry);
        }
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
        let tunnel = &self.tunnel;
        flush_packet_queue(
            &mut self.device.tx,
            &mut self.send_retry_at,
            Instant::now(),
            cx,
            |packet, cx| {
                match tunnel.poll_send_ready(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(())) => {}
                }
                Poll::Ready(tunnel.try_send(packet))
            },
        )
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
        // These checks do not need a free slot. Failing them must not abort a
        // TIME-WAIT socket whose peer is still reachable.
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
        let limit = || io::Error::new(io::ErrorKind::WouldBlock, "VPN connection limit reached");
        let at_limit = self.flows.len() + self.resolutions.len() >= self.config.max_connections;
        if at_limit && self.reclaimable_index().is_none() {
            let _ = reply.send(Err(limit()));
            return;
        }
        match target {
            Target::Ip(address) => {
                // Build the socket before reclaiming. A refused address or a
                // spent port then leaves the old TIME-WAIT peer in place.
                let (socket, local_addr) = match self.connect_socket(address) {
                    Ok(connected) => connected,
                    Err(error) => {
                        let _ = reply.send(Err(error));
                        return;
                    }
                };
                if at_limit && !self.reclaim_time_wait() {
                    self.used_ports.remove(&local_addr.port());
                    let _ = reply.send(Err(limit()));
                    return;
                }
                self.push_flow(socket, local_addr, VecDeque::new(), deadline, reply);
            }
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
                let queries = match self.start_dns_queries(&name) {
                    Ok(queries) => queries,
                    Err(error) => {
                        let _ = reply.send(Err(error));
                        return;
                    }
                };
                if at_limit && !self.reclaim_time_wait() {
                    self.cancel_dns_queries(&queries);
                    let _ = reply.send(Err(limit()));
                    return;
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

    fn start_dns_queries(&mut self, name: &str) -> io::Result<Vec<dns::QueryHandle>> {
        let mut queries = Vec::with_capacity(2);
        let query_types = [
            self.config.ipv4.map(|_| DnsQueryType::A),
            self.config.ipv6.map(|_| DnsQueryType::Aaaa),
        ];
        let socket = self.sockets.get_mut::<dns::Socket>(self.dns);
        for query_type in query_types.into_iter().flatten() {
            match socket.start_query(self.iface.context(), name, query_type) {
                Ok(query) => queries.push(query),
                Err(error) => {
                    for query in queries {
                        socket.cancel_query(query);
                    }
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        error.to_string(),
                    ));
                }
            }
        }
        Ok(queries)
    }

    fn cancel_dns_queries(&mut self, queries: &[dns::QueryHandle]) {
        let socket = self.sockets.get_mut::<dns::Socket>(self.dns);
        for query in queries {
            socket.cancel_query(*query);
        }
    }

    fn reclaimable_index(&self) -> Option<usize> {
        let sockets = &self.sockets;
        self.flows.iter().position(|flow| {
            let socket = sockets.get::<tcp::Socket>(flow.handle);
            flow.reply.is_none()
                && flow.remote_eof
                && socket.state() == tcp::State::TimeWait
                && !socket.can_recv()
        })
    }

    /// The earliest-opened TIME-WAIT flow has delivered its data. At the limit,
    /// release it so a connection that is ready to occupy the slot can proceed,
    /// as lwIP does. The socket set does not grow. The source port stays
    /// reserved for that remote tuple until the socket's own TIME-WAIT deadline,
    /// and another tuple may use the port immediately. If the peer lost our
    /// final ACK, its retransmitted FIN now gets a reset, which ends its
    /// LAST-ACK state just as the ACK would have.
    fn reclaim_time_wait(&mut self) -> bool {
        let Some(index) = self.reclaimable_index() else {
            return false;
        };
        let handle = self.flows[index].handle;
        let remote = SocketAddr::from(
            self.sockets
                .get::<tcp::Socket>(handle)
                .remote_endpoint()
                .expect("TIME-WAIT socket has a remote endpoint"),
        );
        let flow = self.flows.remove(index);
        let expires = flow
            .time_wait_until
            .expect("TIME-WAIT flow records its deadline");
        let port = flow.local_addr.port();
        self.sockets.remove(flow.handle);
        self.used_ports.remove(&port);
        self.quarantined_ports.push_back(QuarantinedTuple {
            expires,
            port,
            remote,
        });
        true
    }

    /// smoltcp restarts TIME-WAIT when a segment arrives for a socket already
    /// in that state. Extend our deadline to match before the socket can be
    /// reclaimed and the segment answered with a reset instead.
    fn note_time_wait_segments(&mut self, now: Instant) {
        let restart_at = now + TIME_WAIT;
        let queued: Vec<(SocketAddr, SocketAddr)> = self
            .device
            .rx
            .iter()
            .filter_map(|packet| tcp_endpoints(packet))
            .collect();
        if queued.is_empty() {
            return;
        }
        let sockets = &self.sockets;
        let matched: Vec<usize> = self
            .flows
            .iter()
            .enumerate()
            .filter(|(_, flow)| {
                let socket = sockets.get::<tcp::Socket>(flow.handle);
                if socket.state() != tcp::State::TimeWait {
                    return false;
                }
                let Some(remote) = socket.remote_endpoint().map(SocketAddr::from) else {
                    return false;
                };
                queued.iter().any(|&(source, destination)| {
                    source == remote && destination == flow.local_addr
                })
            })
            .map(|(index, _)| index)
            .collect();
        for index in matched {
            let flow = &mut self.flows[index];
            flow.time_wait_until = Some(
                flow.time_wait_until
                    .map_or(restart_at, |deadline| deadline.max(restart_at)),
            );
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

    fn allocate_port(&mut self, remote: SocketAddr) -> io::Result<u16> {
        let now = Instant::now();
        // Deadlines are not ordered: a later flow can enter TIME-WAIT first,
        // and a segment can restart one deadline without the others.
        self.quarantined_ports.retain(|entry| entry.expires > now);
        let blocked: BTreeSet<u16> = self
            .quarantined_ports
            .iter()
            .filter(|entry| entry.remote == remote)
            .map(|entry| entry.port)
            .collect();
        let mut random = [0; 2];
        getrandom::fill(&mut random).map_err(|error| io::Error::other(error.to_string()))?;
        let start = u16::from_ne_bytes(random) as u32 % EPHEMERAL_COUNT;
        for offset in 0..EPHEMERAL_COUNT {
            let port = FIRST_EPHEMERAL + ((start + offset) % EPHEMERAL_COUNT) as u16;
            if self.used_ports.contains(&port) || blocked.contains(&port) {
                continue;
            }
            self.used_ports.insert(port);
            return Ok(port);
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
        let port = self.allocate_port(remote)?;
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

    fn connect_socket(
        &mut self,
        remote: SocketAddr,
    ) -> io::Result<(tcp::Socket<'static>, SocketAddr)> {
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; self.config.buffer_size]),
            tcp::SocketBuffer::new(vec![0; self.config.buffer_size]),
        );
        let local_addr = self.open_tcp(&mut socket, remote)?;
        Ok((socket, local_addr))
    }

    fn push_flow(
        &mut self,
        socket: tcp::Socket<'static>,
        local_addr: SocketAddr,
        alternatives: VecDeque<SocketAddr>,
        deadline: Instant,
        reply: ConnectReply,
    ) {
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
            time_wait_until: None,
        });
    }

    fn start_tcp(&mut self, addresses: Vec<SocketAddr>, deadline: Instant, reply: ConnectReply) {
        let mut alternatives: VecDeque<_> = addresses.into();
        let Some(address) = alternatives.pop_front() else {
            return;
        };
        let (socket, local_addr) = match self.connect_socket(address) {
            Ok(connected) => connected,
            Err(error) => {
                let _ = reply.send(Err(error));
                return;
            }
        };
        self.push_flow(socket, local_addr, alternatives, deadline, reply);
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
            if self.sockets.get::<tcp::Socket>(flow.handle).state() == tcp::State::TimeWait
                && flow.time_wait_until.is_none()
            {
                // `now` is the same instant passed to smoltcp for this poll, which
                // is when the close timer was armed.
                flow.time_wait_until = Some(now + TIME_WAIT);
            }
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

// ENOBUFS can leave a UNIX datagram socket writable (notably on Darwin).
// Keep the datagram queued and retry on a timer instead of spinning on readiness.
fn flush_packet_queue(
    queue: &mut VecDeque<Vec<u8>>,
    retry_at: &mut Option<Instant>,
    now: Instant,
    cx: &mut Context<'_>,
    mut send: impl FnMut(&[u8], &mut Context<'_>) -> Poll<io::Result<usize>>,
) -> io::Result<()> {
    if retry_at.is_some_and(|deadline| now < deadline) {
        return Ok(());
    }
    *retry_at = None;
    for _ in 0..WORK_BUDGET {
        let Some(packet) = queue.front() else {
            return Ok(());
        };
        match send(packet, cx) {
            Poll::Pending => return Ok(()),
            Poll::Ready(Ok(size)) if size == packet.len() => {
                queue.pop_front();
            }
            Poll::Ready(Ok(_)) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "short VPN datagram write",
                ));
            }
            Poll::Ready(Err(error)) if error.raw_os_error() == Some(libc::ENOBUFS) => {
                *retry_at = Some(now + SEND_RETRY_DELAY);
                return Ok(());
            }
            Poll::Ready(Err(error))
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) => {}
            Poll::Ready(Err(error)) => return Err(error),
        }
    }
    if !queue.is_empty() {
        cx.waker().wake_by_ref();
    }
    Ok(())
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

/// Source and destination of a TCP segment carried directly in IPv4 or IPv6.
/// Extension headers and fragments are ignored; those segments are not used
/// to restart a TIME-WAIT deadline.
fn tcp_endpoints(packet: &[u8]) -> Option<(SocketAddr, SocketAddr)> {
    let (source, destination, segment) = match packet.first().copied().map(|byte| byte >> 4) {
        Some(4) if packet.len() >= 24 => {
            let header = usize::from(packet[0] & 0x0f) * 4;
            if header < 20 || packet.len() < header + 4 || packet[9] != 6 {
                return None;
            }
            let source = IpAddr::V4(Ipv4Addr::new(
                packet[12], packet[13], packet[14], packet[15],
            ));
            let destination = IpAddr::V4(Ipv4Addr::new(
                packet[16], packet[17], packet[18], packet[19],
            ));
            (source, destination, &packet[header..])
        }
        Some(6) if packet.len() >= 44 && packet[6] == 6 => {
            let source = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?));
            let destination =
                IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?));
            (source, destination, &packet[40..])
        }
        _ => return None,
    };
    let source_port = u16::from_be_bytes(segment.get(..2)?.try_into().ok()?);
    let destination_port = u16::from_be_bytes(segment.get(2..4)?.try_into().ok()?);
    Some((
        SocketAddr::new(source, source_port),
        SocketAddr::new(destination, destination_port),
    ))
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
    use tokio::io::AsyncWriteExt;

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

    #[tokio::test]
    async fn quarantined_port_is_not_reused_until_time_wait_expires() {
        let (vpn, _peer) = UnixDatagram::pair().unwrap();
        let (_network, mut driver) = new(vpn, test_config()).unwrap();
        let reclaimed = FIRST_EPHEMERAL + 7;
        let same: SocketAddr = "10.20.0.42:80".parse().unwrap();
        let other: SocketAddr = "10.20.0.43:80".parse().unwrap();
        driver.quarantined_ports.push_back(QuarantinedTuple {
            expires: Instant::now() + TIME_WAIT,
            port: reclaimed,
            remote: same,
        });
        let mut allocated = BTreeSet::new();
        for _ in 1..EPHEMERAL_COUNT {
            allocated.insert(driver.allocate_port(same).unwrap());
        }
        assert!(!allocated.contains(&reclaimed));
        assert_eq!(
            driver.allocate_port(same).unwrap_err().kind(),
            io::ErrorKind::AddrNotAvailable
        );
        assert_eq!(driver.allocate_port(other).unwrap(), reclaimed);
        driver.used_ports.remove(&reclaimed);
        driver.quarantined_ports[0].expires = Instant::now();
        assert_eq!(driver.allocate_port(same).unwrap(), reclaimed);
        assert!(driver.quarantined_ports.is_empty());
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
                // rather than EAGAIN. The production retry path is tested separately.
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
    async fn enobufs_preserves_packets_and_retries_without_readiness_spin() {
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
        let counter = Arc::new(Counter(AtomicUsize::new(0)));
        let waker = Waker::from(counter.clone());
        let mut cx = Context::from_waker(&waker);
        let now = Instant::now();
        let original = VecDeque::from([vec![1, 2, 3], vec![4, 5]]);
        let mut queue = original.clone();
        let mut retry_at = None;
        // A permanently writable transport must still be tried only once per
        // backoff interval when its send syscall reports ENOBUFS.
        for attempt in 0..3 {
            let now = now + SEND_RETRY_DELAY * attempt;
            let mut calls = 0;
            flush_packet_queue(&mut queue, &mut retry_at, now, &mut cx, |_, _| {
                calls += 1;
                Poll::Ready(Err(io::Error::from_raw_os_error(libc::ENOBUFS)))
            })
            .unwrap();
            assert_eq!(calls, 1);
            assert_eq!(retry_at, Some(now + SEND_RETRY_DELAY));
            assert_eq!(queue, original);
            flush_packet_queue(
                &mut queue,
                &mut retry_at,
                now + SEND_RETRY_DELAY / 2,
                &mut cx,
                |_, _| panic!("must not poll writable readiness before the retry deadline"),
            )
            .unwrap();
            assert_eq!(counter.0.load(Ordering::Relaxed), 0);
        }
        let mut sent = Vec::new();
        flush_packet_queue(
            &mut queue,
            &mut retry_at,
            now + SEND_RETRY_DELAY * 3,
            &mut cx,
            |packet, _| {
                sent.push(packet.to_vec());
                Poll::Ready(Ok(packet.len()))
            },
        )
        .unwrap();
        assert_eq!(sent, Vec::from(original));
        assert!(queue.is_empty());
        assert_eq!(retry_at, None);
        assert_eq!(counter.0.load(Ordering::Relaxed), 0);
    }

    struct WakeCounter(std::sync::atomic::AtomicUsize);
    impl std::task::Wake for WakeCounter {
        fn wake(self: std::sync::Arc<Self>) {
            self.wake_by_ref();
        }
        fn wake_by_ref(self: &std::sync::Arc<Self>) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    fn wake_counter() -> (std::sync::Arc<WakeCounter>, std::task::Waker) {
        let counter = std::sync::Arc::new(WakeCounter(Default::default()));
        (counter.clone(), std::task::Waker::from(counter))
    }

    fn take_wakes(counter: &WakeCounter) -> usize {
        counter.0.swap(0, std::sync::atomic::Ordering::Relaxed)
    }

    /// Poll until the driver stops requesting an immediate repoll.
    fn settle(driver: &mut Driver, cx: &mut Context<'_>, counter: &WakeCounter) {
        for _ in 0..16 {
            if take_wakes(counter) == 0 {
                return;
            }
            assert!(driver.poll(cx).is_pending());
        }
        panic!("driver keeps waking itself");
    }

    // The paused clock makes the backoff independent of scheduling delays.
    #[tokio::test(start_paused = true)]
    async fn send_backoff_keeps_timer_and_connect_cancellation_responsive() {
        let (socket, peer) = UnixDatagram::pair().unwrap();
        // A nonblocking std socket reads the queue directly, without readiness.
        let peer = peer.into_std().unwrap();
        let (_network, mut driver) = new(socket, test_config()).unwrap();
        let (reply, response) = oneshot::channel();
        driver.start(ConnectCommand {
            target: Target::Ip("10.20.0.3:443".parse().unwrap()),
            deadline: Instant::now() + Duration::from_secs(30),
            reply,
        });
        assert_eq!(driver.flows.len(), 1);
        drop(response);
        driver.send_retry_at = Some(Instant::now() + SEND_RETRY_DELAY);
        driver.device.tx.push_back(vec![0; 20]);
        let (counter, waker) = wake_counter();
        let mut cx = Context::from_waker(&waker);
        assert!(driver.poll(&mut cx).is_pending());
        assert!(
            driver.flows.is_empty(),
            "backoff must not defer cancellation"
        );
        settle(&mut driver, &mut cx, &counter);
        assert_eq!(driver.device.tx.front().unwrap(), &vec![0; 20]);
        assert!(peer.recv(&mut [0; 64]).is_err(), "sent before the deadline");
        tokio::time::advance(SEND_RETRY_DELAY / 2).await;
        assert_eq!(take_wakes(&counter), 0, "woke before the retry deadline");
        tokio::time::advance(SEND_RETRY_DELAY / 2).await;
        assert!(
            take_wakes(&counter) > 0,
            "retry deadline must wake the driver"
        );
        assert!(driver.poll(&mut cx).is_pending());
        let mut packet = [0; 64];
        assert_eq!(peer.recv(&mut packet).unwrap(), 20);
        assert_eq!(&packet[..20], &[0; 20]);
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_waits_for_packets_held_by_send_backoff() {
        let (socket, peer) = UnixDatagram::pair().unwrap();
        let peer = peer.into_std().unwrap();
        let (network, mut driver) = new(socket, test_config()).unwrap();
        drop(network);
        driver.send_retry_at = Some(Instant::now() + SEND_RETRY_DELAY);
        driver.device.tx.push_back(vec![0; 20]);
        let (counter, waker) = wake_counter();
        let mut cx = Context::from_waker(&waker);
        assert!(
            driver.poll(&mut cx).is_pending(),
            "driver finished with a queued packet"
        );
        settle(&mut driver, &mut cx, &counter);
        tokio::time::advance(SEND_RETRY_DELAY).await;
        assert!(take_wakes(&counter) > 0);
        assert!(matches!(driver.poll(&mut cx), Poll::Ready(Ok(()))));
        assert_eq!(peer.recv(&mut [0; 64]).unwrap(), 20);
    }

    #[test]
    fn packet_send_fatal_errors_and_short_writes_remain_errors() {
        let mut cx = Context::from_waker(std::task::Waker::noop());
        for result in [Err(io::Error::from_raw_os_error(libc::ECONNREFUSED)), Ok(1)] {
            let mut queue = VecDeque::from([vec![1, 2, 3]]);
            let mut retry_at = None;
            let mut result = Some(result);
            assert!(
                flush_packet_queue(
                    &mut queue,
                    &mut retry_at,
                    Instant::now(),
                    &mut cx,
                    |_, _| { Poll::Ready(result.take().unwrap()) }
                )
                .is_err()
            );
            assert_eq!(queue, VecDeque::from([vec![1, 2, 3]]));
            assert!(retry_at.is_none());
        }
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

    struct TimeWaitSession {
        _network: Network,
        driver: Driver,
        peer: std::os::unix::net::UnixDatagram,
        local: SocketAddr,
        remote: SocketAddr,
        server_fin_seq: u32,
        ack_of_fin: u32,
        _stream: DuplexStream,
    }

    impl TimeWaitSession {
        async fn establish() -> Self {
            let (socket, peer) = UnixDatagram::pair().unwrap();
            let peer = peer.into_std().unwrap();
            let mut config = test_config();
            config.max_connections = 1;
            let (network, mut driver) = new(socket, config).unwrap();
            let remote: SocketAddr = "10.20.0.42:7007".parse().unwrap();
            let (reply, mut response) = oneshot::channel();
            driver.start(ConnectCommand {
                target: Target::Ip(remote),
                deadline: Instant::now() + Duration::from_secs(30),
                reply,
            });
            drive(&mut driver);
            let packets = drain(&peer);
            let syn = packets
                .iter()
                .find(|packet| tcp_flags(packet) & 0x02 != 0)
                .expect("SYN");
            let (local, got_remote, segment) = ipv4_endpoints(syn);
            assert_eq!(got_remote, remote);
            let client_isn = u32_at(segment, 4);
            let server_isn = 0x5000u32;
            // Inbound datagrams are queued on the device. The test polls the
            // driver with its own waker, so tunnel readiness is not observed.
            driver.device.rx.push_back(ipv4_tcp(
                remote,
                local,
                server_isn,
                client_isn.wrapping_add(1),
                0x12,
            ));
            drive(&mut driver);
            let mut connected = response
                .try_recv()
                .expect("handshake produced no reply")
                .expect("handshake failed");
            assert_eq!(connected.local_addr, local);
            let _ = drain(&peer);
            connected.stream.shutdown().await.unwrap();
            let mut ack_of_fin = client_isn.wrapping_add(1);
            let mut saw_fin = false;
            for _ in 0..8 {
                drive(&mut driver);
                for packet in drain(&peer) {
                    let (_, _, segment) = ipv4_endpoints(&packet);
                    let seq = u32_at(segment, 4);
                    let data_offset = usize::from(segment[12] >> 4) * 4;
                    let mut advance = (segment.len() - data_offset) as u32;
                    if segment[13] & 0x02 != 0 {
                        advance = advance.wrapping_add(1);
                    }
                    if segment[13] & 0x01 != 0 {
                        advance = advance.wrapping_add(1);
                        saw_fin = true;
                    }
                    if advance > 0 {
                        ack_of_fin = seq.wrapping_add(advance);
                    }
                }
                if saw_fin {
                    break;
                }
            }
            assert!(saw_fin, "active close did not send a FIN");
            driver.device.rx.push_back(ipv4_tcp(
                remote,
                local,
                server_isn.wrapping_add(1),
                ack_of_fin,
                0x11,
            ));
            let mut session = Self {
                _network: network,
                driver,
                peer,
                local,
                remote,
                server_fin_seq: server_isn.wrapping_add(1),
                ack_of_fin,
                _stream: connected.stream,
            };
            for _ in 0..6 {
                session.drive();
                let _ = session.drain();
                if session.reclaimable() {
                    return session;
                }
            }
            panic!(
                "handshake did not reach reclaimable TIME-WAIT: {}",
                session.debug_state()
            );
        }

        fn drive(&mut self) {
            drive(&mut self.driver);
        }

        fn drain(&self) -> Vec<Vec<u8>> {
            drain(&self.peer)
        }

        fn reclaimable(&self) -> bool {
            let Some(flow) = self.driver.flows.first() else {
                return false;
            };
            let socket = self.driver.sockets.get::<tcp::Socket>(flow.handle);
            flow.reply.is_none()
                && flow.remote_eof
                && socket.state() == tcp::State::TimeWait
                && !socket.can_recv()
        }

        fn debug_state(&self) -> String {
            let Some(flow) = self.driver.flows.first() else {
                return "no flow".to_owned();
            };
            let socket = self.driver.sockets.get::<tcp::Socket>(flow.handle);
            format!(
                "state {:?} reply {} remote_eof {} can_recv {} flows {}",
                socket.state(),
                flow.reply.is_some(),
                flow.remote_eof,
                socket.can_recv(),
                self.driver.flows.len()
            )
        }
    }

    fn drive(driver: &mut Driver) {
        let (counter, waker) = wake_counter();
        let mut cx = Context::from_waker(&waker);
        assert!(driver.poll(&mut cx).is_pending(), "driver stopped");
        settle(driver, &mut cx, &counter);
    }

    fn drain(peer: &std::os::unix::net::UnixDatagram) -> Vec<Vec<u8>> {
        let mut packets = Vec::new();
        let mut buffer = [0; 65536];
        loop {
            match peer.recv(&mut buffer) {
                Ok(size) => packets.push(buffer[..size].to_vec()),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => panic!("peer recv: {error}"),
            }
        }
        packets
    }

    fn tcp_flags(packet: &[u8]) -> u8 {
        ipv4_endpoints(packet).2[13]
    }

    fn u32_at(bytes: &[u8], offset: usize) -> u32 {
        u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap())
    }

    fn ipv4_endpoints(packet: &[u8]) -> (SocketAddr, SocketAddr, &[u8]) {
        assert_eq!(packet[0] >> 4, 4);
        let source = IpAddr::V4(std::net::Ipv4Addr::from(
            <[u8; 4]>::try_from(&packet[12..16]).unwrap(),
        ));
        let destination = IpAddr::V4(std::net::Ipv4Addr::from(
            <[u8; 4]>::try_from(&packet[16..20]).unwrap(),
        ));
        let segment = &packet[20..];
        (
            SocketAddr::new(source, u16::from_be_bytes(segment[..2].try_into().unwrap())),
            SocketAddr::new(
                destination,
                u16::from_be_bytes(segment[2..4].try_into().unwrap()),
            ),
            segment,
        )
    }

    fn ipv4_checksum(bytes: &[u8]) -> u16 {
        let mut sum: u32 = bytes
            .chunks(2)
            .map(|word| u16::from_be_bytes([word[0], *word.get(1).unwrap_or(&0)]) as u32)
            .sum();
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    fn ipv4_tcp(source: SocketAddr, dest: SocketAddr, seq: u32, ack: u32, flags: u8) -> Vec<u8> {
        let mut tcp = vec![0; 20];
        tcp[..2].copy_from_slice(&source.port().to_be_bytes());
        tcp[2..4].copy_from_slice(&dest.port().to_be_bytes());
        tcp[4..8].copy_from_slice(&seq.to_be_bytes());
        tcp[8..12].copy_from_slice(&ack.to_be_bytes());
        tcp[12] = 0x50;
        tcp[13] = flags;
        tcp[14..16].copy_from_slice(&32_768u16.to_be_bytes());
        let IpAddr::V4(source_ip) = source.ip() else {
            unreachable!("test peer is IPv4");
        };
        let IpAddr::V4(dest_ip) = dest.ip() else {
            unreachable!("test peer is IPv4");
        };
        let mut pseudo = Vec::with_capacity(12 + tcp.len());
        pseudo.extend(source_ip.octets());
        pseudo.extend(dest_ip.octets());
        pseudo.extend([0, 6]);
        pseudo.extend((tcp.len() as u16).to_be_bytes());
        pseudo.extend(&tcp);
        let sum = ipv4_checksum(&pseudo);
        tcp[16..18].copy_from_slice(&sum.to_be_bytes());
        let mut packet = vec![0; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&((tcp.len() + 20) as u16).to_be_bytes());
        packet[6] = 0x40;
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&source_ip.octets());
        packet[16..20].copy_from_slice(&dest_ip.octets());
        let sum = ipv4_checksum(&packet);
        packet[10..12].copy_from_slice(&sum.to_be_bytes());
        packet.extend(tcp);
        packet
    }

    #[tokio::test(start_paused = true)]
    async fn rejected_connect_does_not_reset_time_wait_peer() {
        let mut session = TimeWaitSession::establish().await;
        let handle = session.driver.flows[0].handle;
        let rejections = [
            (
                Target::Ip("10.20.0.50:0".parse().unwrap()),
                Instant::now() + Duration::from_secs(5),
                io::ErrorKind::InvalidInput,
            ),
            (
                Target::Ip("10.20.0.50:80".parse().unwrap()),
                Instant::now(),
                io::ErrorKind::TimedOut,
            ),
            (
                Target::Domain(String::new(), 80),
                Instant::now() + Duration::from_secs(5),
                io::ErrorKind::InvalidInput,
            ),
            (
                Target::Domain("example.com".into(), 80),
                Instant::now() + Duration::from_secs(5),
                io::ErrorKind::NotFound,
            ),
            (
                Target::Ip("224.0.0.1:80".parse().unwrap()),
                Instant::now() + Duration::from_secs(5),
                io::ErrorKind::InvalidInput,
            ),
            (
                Target::Ip("[2001:db8::5]:443".parse().unwrap()),
                Instant::now() + Duration::from_secs(5),
                io::ErrorKind::Unsupported,
            ),
        ];
        for (target, deadline, kind) in rejections {
            let (reply, mut response) = oneshot::channel();
            session.driver.start(ConnectCommand {
                target,
                deadline,
                reply,
            });
            assert_eq!(response.try_recv().unwrap().unwrap_err().kind(), kind);
            assert_eq!(
                session.driver.flows.len(),
                1,
                "rejected connect removed the TIME-WAIT flow"
            );
            assert_eq!(session.driver.flows[0].handle, handle);
            assert!(session.reclaimable());
        }
        let keep = session.local.port();
        for offset in 0..EPHEMERAL_COUNT {
            session
                .driver
                .used_ports
                .insert(FIRST_EPHEMERAL + offset as u16);
        }
        let (reply, mut response) = oneshot::channel();
        session.driver.start(ConnectCommand {
            target: Target::Ip("10.20.0.50:80".parse().unwrap()),
            deadline: Instant::now() + Duration::from_secs(5),
            reply,
        });
        assert_eq!(
            response.try_recv().unwrap().unwrap_err().kind(),
            io::ErrorKind::AddrNotAvailable
        );
        assert_eq!(session.driver.flows.len(), 1);
        assert_eq!(session.driver.flows[0].handle, handle);
        session.driver.used_ports.retain(|port| *port == keep);

        let (reply, mut response) = oneshot::channel();
        session.driver.start(ConnectCommand {
            target: Target::Ip("10.20.0.50:80".parse().unwrap()),
            deadline: Instant::now() + Duration::from_secs(5),
            reply,
        });
        assert!(
            response.try_recv().is_err(),
            "a valid connect at the limit must reclaim TIME-WAIT and stay pending"
        );
        assert_eq!(session.driver.flows.len(), 1);
        assert_ne!(session.driver.flows[0].local_addr.port(), keep);
        assert_eq!(
            session
                .driver
                .sockets
                .get::<tcp::Socket>(session.driver.flows[0].handle)
                .state(),
            tcp::State::SynSent
        );
        assert!(
            session
                .driver
                .quarantined_ports
                .iter()
                .any(|entry| entry.port == keep && entry.remote == session.remote)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn reclaimed_port_keeps_the_original_time_wait_deadline() {
        let mut session = TimeWaitSession::establish().await;
        tokio::time::advance(Duration::from_secs(9)).await;
        assert!(session.driver.reclaim_time_wait());
        let expires = session.driver.quarantined_ports[0].expires;
        let remaining = expires.saturating_duration_since(Instant::now());
        assert_eq!(
            remaining,
            Duration::from_secs(1),
            "quarantine restarted TIME-WAIT ({remaining:?} left)"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn queued_time_wait_segment_restarts_the_quarantine_deadline() {
        let mut session = TimeWaitSession::establish().await;
        tokio::time::advance(Duration::from_secs(9)).await;
        session.driver.device.rx.push_back(ipv4_tcp(
            session.remote,
            session.local,
            session.server_fin_seq,
            session.ack_of_fin,
            0x11,
        ));
        session.drive();
        assert!(session.reclaimable());
        assert!(session.driver.reclaim_time_wait());
        let remaining = session.driver.quarantined_ports[0]
            .expires
            .saturating_duration_since(Instant::now());
        assert_eq!(remaining, TIME_WAIT);
    }

    #[tokio::test(start_paused = true)]
    async fn reclaimed_port_is_reusable_for_a_distinct_tuple() {
        let mut session = TimeWaitSession::establish().await;
        let port = session.local.port();
        for offset in 0..EPHEMERAL_COUNT {
            session
                .driver
                .used_ports
                .insert(FIRST_EPHEMERAL + offset as u16);
        }
        assert!(session.driver.reclaim_time_wait());
        assert_eq!(
            session
                .driver
                .allocate_port(session.remote)
                .unwrap_err()
                .kind(),
            io::ErrorKind::AddrNotAvailable,
            "the reclaimed tuple must stay reserved"
        );
        let other: SocketAddr = "10.9.9.9:443".parse().unwrap();
        assert_eq!(
            session.driver.allocate_port(other).ok(),
            Some(port),
            "a distinct destination must be able to reuse reclaimed port {port}"
        );
    }
}
