//! Host sockets are listeners only. Every outbound connection uses `Network`.
use crate::{
    config::{ListenerKind, ListenerSpec},
    socks,
    stack::Network,
};
use std::{io, sync::Arc, time::Duration};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    task::JoinSet,
    time::{Instant, sleep_until, timeout},
};

/// Pause accepting while the process or kernel is out of descriptors or memory.
/// The pending connection stays in the listen backlog; existing clients continue.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

#[derive(Debug, PartialEq, Eq)]
enum AcceptFailure {
    /// Belongs to one incoming connection; accept the next one immediately.
    Connection,
    /// Resource exhaustion; retry after [`ACCEPT_BACKOFF`].
    Resources,
    /// The listener itself is unusable.
    Listener,
}

fn classify_accept_error(error: &io::Error) -> AcceptFailure {
    if matches!(
        error.kind(),
        io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::Interrupted
            | io::ErrorKind::WouldBlock
    ) {
        return AcceptFailure::Connection;
    }
    match error.raw_os_error() {
        Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM) => {
            AcceptFailure::Resources
        }
        // accept(2) reports pending network errors of the new connection; Linux
        // documents treating these like EAGAIN.
        Some(
            libc::EPROTO
            | libc::ENOPROTOOPT
            | libc::ENETDOWN
            | libc::ENETUNREACH
            | libc::EHOSTDOWN
            | libc::EHOSTUNREACH
            | libc::EOPNOTSUPP
            | libc::ETIMEDOUT,
        ) => AcceptFailure::Connection,
        // Linux also reports EPERM when firewall rules reject one connection.
        #[cfg(target_os = "linux")]
        Some(libc::ENONET | libc::EPERM) => AcceptFailure::Connection,
        _ => AcceptFailure::Listener,
    }
}

pub struct BoundListener {
    pub listener: TcpListener,
    pub kind: ListenerKind,
}

/// Bind the complete configuration before exposing readiness. A failure drops
/// every previously bound socket, so startup cannot silently omit a forward.
pub async fn bind_all(specs: &[ListenerSpec]) -> io::Result<Vec<BoundListener>> {
    let mut listeners = Vec::with_capacity(specs.len());
    for spec in specs {
        let listener = TcpListener::bind(spec.bind)
            .await
            .map_err(|e| io::Error::new(e.kind(), format!("cannot bind {}: {e}", spec.bind)))?;
        listeners.push(BoundListener {
            listener,
            kind: spec.kind.clone(),
        });
    }
    Ok(listeners)
}

/// Owns the tasks for one listener. Dropping this future aborts its client tasks.
pub async fn serve(
    bound: BoundListener,
    network: Network,
    permits: Arc<Semaphore>,
    handshake_timeout: Duration,
    connect_timeout: Duration,
) -> io::Result<()> {
    let mut clients = JoinSet::new();
    let mut resume_at: Option<Instant> = None;
    let mut exhausted = false;
    loop {
        tokio::select! {
            accepted = bound.listener.accept(), if resume_at.is_none() => {
                let (stream, peer) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) => match classify_accept_error(&error) {
                        AcceptFailure::Connection => {
                            tracing::debug!(%error, "incoming connection failed before accept");
                            continue;
                        }
                        AcceptFailure::Resources => {
                            if !exhausted {
                                tracing::warn!(%error, "cannot accept; pausing listener while existing connections continue");
                            }
                            exhausted = true;
                            resume_at = Some(Instant::now() + ACCEPT_BACKOFF);
                            continue;
                        }
                        AcceptFailure::Listener => return Err(error),
                    },
                };
                exhausted = false;
                let Ok(permit) = permits.clone().try_acquire_owned() else {
                    tracing::debug!(%peer, "connection limit reached");
                    drop(stream);
                    continue;
                };
                let network = network.clone();
                let kind = bound.kind.clone();
                clients.spawn(async move {
                    let _permit = permit;
                    if let Err(error) = handle_client(stream, kind, network, handshake_timeout, connect_timeout).await {
                        tracing::debug!(%peer, %error, "client connection ended");
                    }
                });
            }
            // The future is built even when disabled; it is polled only while paused.
            () = sleep_until(resume_at.unwrap_or_else(Instant::now)), if resume_at.is_some() => resume_at = None,
            completed = clients.join_next(), if !clients.is_empty() => {
                if let Some(Err(error)) = completed {
                    return Err(io::Error::other(format!("client task failed: {error}")));
                }
            }
        }
    }
}

async fn handle_client(
    mut stream: TcpStream,
    kind: ListenerKind,
    network: Network,
    handshake_timeout: Duration,
    connect_timeout: Duration,
) -> io::Result<()> {
    stream.set_nodelay(true)?;
    let is_socks = matches!(kind, ListenerKind::Socks);
    let target = match kind {
        ListenerKind::Socks => timeout(handshake_timeout, socks::handshake(&mut stream))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SOCKS handshake timed out"))??,
        ListenerKind::Forward(target) => target,
    };
    let result = timeout(connect_timeout, network.connect(target))
        .await
        .unwrap_or_else(|_| {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "VPN connection timed out",
            ))
        });
    let mut connected = match result {
        Ok(connected) => connected,
        Err(error) => {
            if is_socks {
                let _ = timeout(handshake_timeout, socks::reply(&mut stream, Err(&error))).await;
            }
            return Err(error);
        }
    };
    if is_socks {
        timeout(
            handshake_timeout,
            socks::reply(&mut stream, Ok(connected.local_addr)),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SOCKS reply timed out"))??;
    }
    // copy_bidirectional forwards EOF independently in each direction. It keeps
    // reading the response after a client shuts down its request-writing half.
    tokio::io::copy_bidirectional(&mut stream, &mut connected.stream).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn binding_failure_does_not_return_partial_service() {
        let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let specs = [
            ListenerSpec {
                bind: "127.0.0.1:0".parse().unwrap(),
                kind: ListenerKind::Socks,
            },
            ListenerSpec {
                bind: occupied.local_addr().unwrap(),
                kind: ListenerKind::Socks,
            },
        ];
        assert!(bind_all(&specs).await.is_err());
    }

    #[test]
    fn accept_errors_stop_only_a_broken_listener() {
        let os = io::Error::from_raw_os_error;
        for error in [
            io::Error::from(io::ErrorKind::ConnectionAborted),
            os(libc::ECONNABORTED),
            os(libc::ECONNRESET),
            os(libc::EINTR),
            os(libc::EPROTO),
            os(libc::ENETUNREACH),
            os(libc::EHOSTUNREACH),
            os(libc::ETIMEDOUT),
        ] {
            assert_eq!(
                classify_accept_error(&error),
                AcceptFailure::Connection,
                "{error}"
            );
        }
        #[cfg(target_os = "linux")]
        assert_eq!(
            classify_accept_error(&os(libc::EPERM)),
            AcceptFailure::Connection
        );
        for code in [libc::EMFILE, libc::ENFILE, libc::ENOBUFS, libc::ENOMEM] {
            assert_eq!(classify_accept_error(&os(code)), AcceptFailure::Resources);
        }
        for code in [libc::EBADF, libc::EINVAL, libc::ENOTSOCK, libc::EFAULT] {
            assert_eq!(classify_accept_error(&os(code)), AcceptFailure::Listener);
        }
    }
}
